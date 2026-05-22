"""Source fetcher tests. All HTTP and registry calls are mocked."""
from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from nyuwaymcpscanner.sources import resolve, UnsupportedSource
from nyuwaymcpscanner.sources import github as gh
from nyuwaymcpscanner.sources import npm as npm_src
from nyuwaymcpscanner.sources import pypi as pypi_src
from nyuwaymcpscanner.sources._archive import (
    safe_extract_tar, safe_extract_zip, UnsafeArchive,
    MAX_ENTRY_BYTES,
)


# ---------- helpers to build test archives ----------

def make_tar(entries: dict[str, bytes], path: Path, malicious_names: list[str] | None = None) -> Path:
    """Build a tar.gz with the given entries. Optionally include unsafe names."""
    with tarfile.open(path, "w:gz") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, fileobj=io.BytesIO(data))
        for bad_name in (malicious_names or []):
            info = tarfile.TarInfo(name=bad_name)
            info.size = 0
            tar.addfile(info, fileobj=io.BytesIO(b""))
    return path


def make_zip(entries: dict[str, bytes], path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


# ---------- safe extract ----------

def test_safe_extract_tar_extracts_normal_archive(tmp_path):
    archive = make_tar({"pkg/index.js": b"console.log(1)\n"}, tmp_path / "ok.tar.gz")
    dest = tmp_path / "out"
    safe_extract_tar(archive, dest)
    assert (dest / "pkg" / "index.js").read_text() == "console.log(1)\n"


def test_safe_extract_tar_rejects_path_traversal(tmp_path):
    archive = make_tar(
        {"normal.txt": b"ok"},
        tmp_path / "bad.tar.gz",
        malicious_names=["../escape.txt"],
    )
    with pytest.raises(UnsafeArchive):
        safe_extract_tar(archive, tmp_path / "out")


def test_safe_extract_tar_rejects_absolute_path(tmp_path):
    archive = make_tar(
        {"normal.txt": b"ok"},
        tmp_path / "abs.tar.gz",
        malicious_names=["/etc/passwd"],
    )
    with pytest.raises(UnsafeArchive):
        safe_extract_tar(archive, tmp_path / "out")


def test_safe_extract_tar_rejects_oversize_entry(tmp_path):
    archive_path = tmp_path / "huge.tar.gz"
    huge_payload = b"X" * (MAX_ENTRY_BYTES + 100)
    make_tar({"huge.bin": huge_payload}, archive_path)
    with pytest.raises(UnsafeArchive):
        safe_extract_tar(archive_path, tmp_path / "out")


def test_safe_extract_zip_extracts_normal_archive(tmp_path):
    archive = make_zip({"pkg/index.py": b"x = 1\n"}, tmp_path / "ok.zip")
    dest = tmp_path / "out"
    safe_extract_zip(archive, dest)
    assert (dest / "pkg" / "index.py").read_text() == "x = 1\n"


def test_safe_extract_zip_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("../escape.txt", b"bad")
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(archive_path, tmp_path / "out")


def test_safe_extract_zip_rejects_absolute_path(tmp_path):
    archive_path = tmp_path / "abs.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("/etc/passwd", b"bad")
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(archive_path, tmp_path / "out")


# ---------- dispatch / resolver ----------

def test_resolve_unknown_prefix_raises():
    with pytest.raises(UnsupportedSource):
        with resolve("docker:foo/bar"):
            pass


def test_resolve_local_path_round_trips(tmp_path):
    target = tmp_path / "local"
    target.mkdir()
    with resolve(str(target)) as p:
        assert Path(p).resolve() == target.resolve()


def test_resolve_local_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        with resolve(str(tmp_path / "nope")):
            pass


def test_resolve_windows_path_not_mistaken_for_source(tmp_path):
    # On non-Windows this still parses cleanly because the path doesn't exist
    # but is not treated as an unsupported source prefix.
    with pytest.raises(FileNotFoundError):
        with resolve("C:\\nope\\definitely-not-a-real-path"):
            pass


# ---------- github fetcher ----------

class _FakeStreamingResponse:
    """Minimal stub of a requests streaming Response."""
    def __init__(self, content: bytes, status: int = 200):
        self._content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=8192):
        yield self._content

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_github_parses_owner_repo_ref():
    owner, repo, ref = gh._parse_spec("github:nyuway/scanner@main")
    assert owner == "nyuway"
    assert repo == "scanner"
    assert ref == "main"


def test_github_defaults_ref_to_head():
    _, _, ref = gh._parse_spec("github:nyuway/scanner")
    assert ref == "HEAD"


def test_github_rejects_malformed_spec():
    with pytest.raises(gh.GitHubFetchError):
        gh._parse_spec("github:not-a-valid-spec")


def test_github_fetch_downloads_and_extracts(monkeypatch, tmp_path):
    archive = tmp_path / "src.tar.gz"
    make_tar({"nyuway-scanner-deadbeef/index.js": b"// hello\n"}, archive)
    content = archive.read_bytes()

    monkeypatch.setattr(gh.requests, "get",
                        lambda *a, **kw: _FakeStreamingResponse(content))

    with gh.fetch_github("github:nyuway/scanner@main") as path:
        assert Path(path).is_dir()
        assert (Path(path) / "index.js").read_text() == "// hello\n"


def test_github_download_failure_raises(monkeypatch):
    import requests as real_requests
    def boom(*a, **kw):
        raise real_requests.ConnectionError("no network")
    monkeypatch.setattr(gh.requests, "get", boom)
    with pytest.raises(gh.GitHubFetchError):
        with gh.fetch_github("github:nyuway/scanner"):
            pass


# ---------- npm fetcher ----------

class _FakeJSONResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_npm_parses_scoped_name():
    name, version = npm_src._parse_spec("npm:@scope/pkg@1.2.3")
    assert name == "@scope/pkg"
    assert version == "1.2.3"


def test_npm_parses_unscoped_name():
    name, version = npm_src._parse_spec("npm:lodash")
    assert name == "lodash"
    assert version is None


def test_npm_rejects_invalid_name():
    with pytest.raises(npm_src.NpmFetchError):
        npm_src._parse_spec("npm:bad name/with spaces")


def test_npm_fetch_end_to_end(monkeypatch, tmp_path):
    archive = tmp_path / "pkg.tgz"
    make_tar({"package/index.js": b"module.exports = 1;\n",
              "package/package.json": b'{"name":"fakepkg"}'}, archive)
    archive_bytes = archive.read_bytes()

    registry_payload = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/fakepkg/-/fakepkg-1.0.0.tgz"}}
        },
    }

    def fake_get(url, *a, **kw):
        if "registry.npmjs.org/fakepkg" == url.rstrip("/") or url.endswith("fakepkg"):
            return _FakeJSONResponse(registry_payload)
        return _FakeStreamingResponse(archive_bytes)

    monkeypatch.setattr(npm_src.requests, "get", fake_get)

    with npm_src.fetch_npm("npm:fakepkg") as path:
        assert (Path(path) / "package.json").is_file()
        assert (Path(path) / "index.js").read_text() == "module.exports = 1;\n"


def test_npm_unknown_version_raises(monkeypatch):
    registry_payload = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}}
    monkeypatch.setattr(npm_src.requests, "get",
                        lambda *a, **kw: _FakeJSONResponse(registry_payload))
    with pytest.raises(npm_src.NpmFetchError):
        with npm_src.fetch_npm("npm:fakepkg@9.9.9"):
            pass


# ---------- pypi fetcher ----------

def test_pypi_parses_name_and_version():
    name, version = pypi_src._parse_spec("pypi:requests@2.31.0")
    assert name == "requests"
    assert version == "2.31.0"


def test_pypi_rejects_invalid_name():
    with pytest.raises(pypi_src.PyPIFetchError):
        pypi_src._parse_spec("pypi:bad name")


def test_pypi_fetch_sdist_end_to_end(monkeypatch, tmp_path):
    archive = tmp_path / "fakepkg-1.0.0.tar.gz"
    make_tar({"fakepkg-1.0.0/setup.py": b"# setup\n"}, archive)
    archive_bytes = archive.read_bytes()

    pypi_payload = {
        "urls": [
            {"packagetype": "sdist",
             "filename": "fakepkg-1.0.0.tar.gz",
             "url": "https://files.pythonhosted.org/fakepkg-1.0.0.tar.gz"}
        ]
    }

    def fake_get(url, *a, **kw):
        if "pypi.org" in url:
            return _FakeJSONResponse(pypi_payload)
        return _FakeStreamingResponse(archive_bytes)

    monkeypatch.setattr(pypi_src.requests, "get", fake_get)

    with pypi_src.fetch_pypi("pypi:fakepkg") as path:
        assert (Path(path) / "setup.py").read_text() == "# setup\n"


def test_pypi_falls_back_to_wheel(monkeypatch, tmp_path):
    archive_path = tmp_path / "fakepkg-1.0-py3-none-any.whl"
    make_zip({"fakepkg/__init__.py": b"# init\n"}, archive_path)
    archive_bytes = archive_path.read_bytes()

    pypi_payload = {
        "urls": [
            {"packagetype": "bdist_wheel",
             "filename": "fakepkg-1.0-py3-none-any.whl",
             "url": "https://files.pythonhosted.org/fakepkg-1.0-py3-none-any.whl"}
        ]
    }

    def fake_get(url, *a, **kw):
        if "pypi.org" in url:
            return _FakeJSONResponse(pypi_payload)
        return _FakeStreamingResponse(archive_bytes)

    monkeypatch.setattr(pypi_src.requests, "get", fake_get)

    with pypi_src.fetch_pypi("pypi:fakepkg") as path:
        # Wheels don't always have a single top-level dir; just confirm extraction.
        assert any(Path(path).rglob("__init__.py"))


def test_pypi_no_distributions_raises(monkeypatch):
    monkeypatch.setattr(pypi_src.requests, "get",
                        lambda *a, **kw: _FakeJSONResponse({"urls": []}))
    with pytest.raises(pypi_src.PyPIFetchError):
        with pypi_src.fetch_pypi("pypi:fakepkg"):
            pass
