"""Safety guard tests: file size caps, skip-dirs, binary file handling."""
import pytest
from nyuwaymcpscanner.scanners.secrets import scan_secrets, MAX_FILE_BYTES as SECRETS_MAX
from nyuwaymcpscanner.scanners.yara_engine import run_yara, MAX_FILE_BYTES as YARA_MAX


def test_secrets_skips_oversized_files(tmp_path):
    """A file larger than MAX_FILE_BYTES with a secret in it must not produce findings."""
    project = tmp_path / "huge_project"
    project.mkdir()
    huge_file = project / "huge.py"
    # Pad with whitespace to exceed cap, then put the secret on the last line.
    padding = b" " * (SECRETS_MAX + 100)
    huge_file.write_bytes(padding + b'\nAKIAIOSFODNN7EXAMPLE\n')
    findings = scan_secrets(str(project))
    assert findings == [], "Oversized file should be skipped, but findings were produced"


def test_yara_skips_oversized_files(tmp_path):
    project = tmp_path / "huge_yar_project"
    project.mkdir()
    huge = project / "huge.py"
    padding = b" " * (YARA_MAX + 100)
    huge.write_bytes(padding + b'\nos.system("rm -rf /")\n')
    findings = run_yara(str(project))
    assert findings == [], "Oversized file should be skipped by YARA"


def test_secrets_skips_git_dir(tmp_path):
    """Content under .git/ must be ignored even if it contains secrets."""
    project = tmp_path / "with_git"
    project.mkdir()
    git_dir = project / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text('AKIAIOSFODNN7EXAMPLE\n')
    findings = scan_secrets(str(project))
    assert findings == [], "Content under .git should be skipped"


def test_secrets_skips_node_modules(tmp_path):
    project = tmp_path / "with_node_modules"
    project.mkdir()
    nm = project / "node_modules" / "some-pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text('const TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";\n')
    findings = scan_secrets(str(project))
    assert findings == [], "Content under node_modules should be skipped"


def test_secrets_skips_binary_extensions(tmp_path):
    """A .png file containing what looks like a secret must be skipped."""
    project = tmp_path / "with_binary"
    project.mkdir()
    (project / "logo.png").write_bytes(b'AKIAIOSFODNN7EXAMPLE\x00\xff\x00')
    findings = scan_secrets(str(project))
    assert findings == []


def test_secrets_handles_unreadable_bytes(tmp_path):
    """Non-UTF8 bytes must not crash the scanner (errors='ignore')."""
    project = tmp_path / "binary_text"
    project.mkdir()
    (project / "weird.py").write_bytes(b'\xff\xfe\x00\x01valid_python = 1\n')
    # Should not raise
    findings = scan_secrets(str(project))
    assert isinstance(findings, list)


def test_yara_skips_binary_extensions(tmp_path):
    project = tmp_path / "yar_binary"
    project.mkdir()
    (project / "bin.exe").write_bytes(b'os.system("rm -rf /")\n')
    findings = run_yara(str(project))
    assert findings == []


def test_secrets_finding_evidence_truncated(tmp_path):
    """Evidence must be capped at 200 chars to avoid leaking entire long lines."""
    project = tmp_path / "long_line"
    project.mkdir()
    long_prefix = "x" * 500
    (project / "f.py").write_text(f'TOKEN = "{long_prefix} ghp_{"A"*36}"\n')
    findings = scan_secrets(str(project))
    assert findings
    for f in findings:
        assert len(f["evidence"]) <= 200
