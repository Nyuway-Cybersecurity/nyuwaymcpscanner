"""CLI entry point tests."""

import pytest
from click.testing import CliRunner
from nyuwaymcpscanner.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


def test_deep_scan_without_token_exits_nonzero(runner):
    result = runner.invoke(cli, ["scan", "./some-server", "--deep"])
    assert result.exit_code == 1


def test_deep_scan_without_token_shows_waitlist_url(runner):
    result = runner.invoke(cli, ["scan", "./some-server", "--deep"])
    assert "forms.gle/bH8nToK9Zh7ey5F46" in result.output


def test_help_displays(runner):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0


def test_scan_help_displays(runner):
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--static-only" in result.output
    assert "--deep" in result.output


def test_scan_help_lists_all_documented_flags(runner):
    result = runner.invoke(cli, ["scan", "--help"])
    for flag in [
        "--static-only",
        "--offline",
        "--deep",
        "--token",
        "--fail-on",
        "--output",
        "--batch",
    ]:
        assert flag in result.output, f"Flag {flag} missing from scan --help"


def test_root_help_lists_subcommands(runner):
    result = runner.invoke(cli, ["--help"])
    assert "scan" in result.output
    assert "setup" in result.output


def test_end_to_end_clean_server_passes(runner, clean_server_path):
    result = runner.invoke(cli, ["scan", str(clean_server_path), "--offline"])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_end_to_end_secret_server_flags_high(runner, server_with_secret):
    result = runner.invoke(
        cli, ["scan", str(server_with_secret), "--offline", "--fail-on", "high"]
    )
    assert result.exit_code == 1, (
        f"Expected non-zero exit on --fail-on high. Output:\n{result.output}"
    )


def test_end_to_end_json_output_is_valid(runner, server_with_secret):
    import json

    result = runner.invoke(
        cli, ["scan", str(server_with_secret), "--offline", "--output", "json"]
    )
    parsed = json.loads(result.output)
    assert parsed["tool"] == "nyuwaymcpscanner"
    assert "risk_score" in parsed
    assert "verdict" in parsed
    assert isinstance(parsed["findings"], list)


def test_end_to_end_sarif_output_is_valid(runner, server_with_secret):
    import json

    result = runner.invoke(
        cli,
        [
            "scan",
            str(server_with_secret),
            "--offline",
            "--output",
            "sarif",
            "--static-only",
        ],
    )
    assert result.exit_code == 0, f"Output: {result.output}"
    parsed = json.loads(result.output)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "nyuwaymcpscanner"
    # The secret server has findings, so results must be non-empty.
    assert len(parsed["runs"][0]["results"]) > 0


def test_missing_target_exits_with_error(runner):
    result = runner.invoke(cli, ["scan", "/definitely/does/not/exist", "--offline"])
    assert result.exit_code == 2


def test_static_only_runs_and_passes_clean(runner, clean_server_path):
    result = runner.invoke(
        cli, ["scan", str(clean_server_path), "--offline", "--static-only"]
    )
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_setup_command_succeeds_when_run_setup_returns_ok(runner, monkeypatch):
    from nyuwaymcpscanner.cli import main as cli_main

    def fake_setup(model):
        return {
            "ollama_installed": True,
            "ollama_running": True,
            "model": model,
            "model_present": True,
        }

    monkeypatch.setattr(cli_main, "run_setup", fake_setup)
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code == 0
    assert "complete" in result.output.lower()


def test_setup_command_reports_setup_error(runner, monkeypatch):
    from nyuwaymcpscanner.cli import main as cli_main
    from nyuwaymcpscanner.setup.local_llm import SetupError

    def fake_setup(model):
        raise SetupError("Ollama not installed.")

    monkeypatch.setattr(cli_main, "run_setup", fake_setup)
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code == 1
    assert "ollama not installed" in result.output.lower()


def test_batch_scans_each_listed_path(
    runner, tmp_path, clean_server_path, server_with_secret
):
    listing = tmp_path / "servers.txt"
    listing.write_text(
        f"{clean_server_path}\n# a comment line\n\n{server_with_secret}\n"
    )
    result = runner.invoke(cli, ["scan", str(listing), "--offline", "--batch"])
    assert result.exit_code == 0
    # Each target should produce its own scan section. We check for the basename
    # since Rich may soft-wrap long absolute paths in the rendered output.
    assert clean_server_path.name in result.output
    assert server_with_secret.name in result.output
    # Two separate scans should produce two "Baseline Scan" headers.
    assert result.output.count("Baseline Scan") == 2


def test_batch_with_missing_listing_file_errors(runner):
    result = runner.invoke(cli, ["scan", "/nope/servers.txt", "--offline", "--batch"])
    assert result.exit_code == 2


def test_batch_with_empty_listing_errors(runner, tmp_path):
    listing = tmp_path / "empty.txt"
    listing.write_text("# only comments\n\n")
    result = runner.invoke(cli, ["scan", str(listing), "--offline", "--batch"])
    assert result.exit_code == 2


def test_local_llm_skipped_when_no_manifest(runner, clean_server_path, monkeypatch):
    """No manifest in the tree → LLM layer must not even attempt a call."""
    from nyuwaymcpscanner.cli import main as cli_main

    called = {"n": 0}

    def fail_if_called(*a, **kw):
        called["n"] += 1
        raise AssertionError("LLM should not be invoked when no manifest exists")

    monkeypatch.setattr(cli_main, "run_local_llm_analysis", fail_if_called)

    result = runner.invoke(cli, ["scan", str(clean_server_path), "--offline"])
    assert result.exit_code == 0
    assert called["n"] == 0


def test_local_llm_invoked_when_manifest_present(runner, tmp_path, monkeypatch):
    from nyuwaymcpscanner.cli import main as cli_main

    project = tmp_path / "with_manifest"
    project.mkdir()
    (project / "mcp.json").write_text(
        '{"tools": [{"name": "fetch", "description": "fetch data"}]}'
    )

    called = {"n": 0}

    def fake_llm(manifest, model=None):
        called["n"] += 1
        return [
            {
                "type": "tool_poisoning",
                "severity": "critical",
                "weight": 35,
                "tool_name": "fetch",
                "evidence": "x",
                "rationale": "x",
                "confidence": 0.9,
                "source": "local_llm",
            }
        ]

    monkeypatch.setattr(cli_main, "run_local_llm_analysis", fake_llm)

    result = runner.invoke(cli, ["scan", str(project), "--offline"])
    assert result.exit_code == 0
    assert called["n"] == 1
    assert "tool_poisoning" in result.output


def test_static_only_skips_llm_even_with_manifest(runner, tmp_path, monkeypatch):
    from nyuwaymcpscanner.cli import main as cli_main

    project = tmp_path / "with_manifest"
    project.mkdir()
    (project / "mcp.json").write_text(
        '{"tools": [{"name": "fetch", "description": "x"}]}'
    )

    def fail_if_called(*a, **kw):
        raise AssertionError("LLM must not be called under --static-only")

    monkeypatch.setattr(cli_main, "run_local_llm_analysis", fail_if_called)

    result = runner.invoke(cli, ["scan", str(project), "--offline", "--static-only"])
    assert result.exit_code == 0


def test_local_llm_graceful_degradation_when_ollama_unavailable(
    runner, tmp_path, monkeypatch
):
    """When Ollama is down, the scan must still succeed (with a warning)."""
    from nyuwaymcpscanner.cli import main as cli_main
    from nyuwaymcpscanner.scanners.llm_safety import OllamaUnavailable

    project = tmp_path / "with_manifest"
    project.mkdir()
    (project / "mcp.json").write_text(
        '{"tools": [{"name": "fetch", "description": "x"}]}'
    )

    def raise_unavailable(*a, **kw):
        raise OllamaUnavailable("not running")

    monkeypatch.setattr(cli_main, "run_local_llm_analysis", raise_unavailable)

    result = runner.invoke(cli, ["scan", str(project), "--offline"])
    assert result.exit_code == 0
    # Warning should be on stderr (mixed into output by CliRunner by default).
    assert "skipped" in result.output.lower() or "not running" in result.output.lower()


def test_local_llm_skipped_on_malformed_manifest(runner, tmp_path, monkeypatch):
    from nyuwaymcpscanner.cli import main as cli_main

    project = tmp_path / "bad_manifest"
    project.mkdir()
    (project / "mcp.json").write_text("{not valid json")

    called = {"n": 0}

    def fail_if_called(*a, **kw):
        called["n"] += 1
        raise AssertionError("LLM must not be called when manifest is malformed")

    monkeypatch.setattr(cli_main, "run_local_llm_analysis", fail_if_called)

    result = runner.invoke(cli, ["scan", str(project), "--offline"])
    assert result.exit_code == 0
    assert called["n"] == 0
    assert "could not parse manifest" in result.output.lower()


def test_config_flag_scans_each_declared_server(
    runner, tmp_path, clean_server_path, monkeypatch
):
    import json as _json

    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(
        _json.dumps(
            {
                "mcpServers": {
                    "local": {
                        "command": "python",
                        "args": [str(clean_server_path / "nothing.py")],
                    },
                    "gh": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                    },
                }
            }
        )
    )

    # Mock the npm fetcher so we don't hit the network for the npm entry.
    from contextlib import contextmanager
    import nyuwaymcpscanner.sources as sources

    @contextmanager
    def fake_npm(spec):
        yield clean_server_path

    monkeypatch.setattr(sources, "fetch_npm", fake_npm)

    # The python path doesn't exist; that should be surfaced as exit 2 from the
    # underlying scanner FileNotFoundError. We instead point it at clean_server_path
    # by adjusting the config to use an existing path.
    cfg.write_text(
        _json.dumps(
            {
                "mcpServers": {
                    "local": {"command": "python", "args": [str(clean_server_path)]},
                    "gh": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                    },
                }
            }
        )
    )

    result = runner.invoke(
        cli, ["scan", str(cfg), "--config", "--offline", "--static-only"]
    )
    assert result.exit_code == 0, f"Output: {result.output}"
    # Both servers should appear as scan targets.
    assert "npm:@modelcontextprotocol/server-github" in result.output
    assert (
        str(clean_server_path) in result.output
        or clean_server_path.name in result.output
    )


def test_config_flag_skips_remote_endpoints(runner, tmp_path, clean_server_path):
    import json as _json

    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        _json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "https://mcp.example.com/sse", "type": "sse"},
                    "local": {"command": "python", "args": [str(clean_server_path)]},
                }
            }
        )
    )
    result = runner.invoke(
        cli, ["scan", str(cfg), "--config", "--offline", "--static-only"]
    )
    assert result.exit_code == 0
    # Warning about the remote one should be on stderr (mixed into output by CliRunner).
    assert "remote" in result.output.lower() or "skipping" in result.output.lower()


def test_config_flag_with_no_scannable_servers_exits(runner, tmp_path):
    import json as _json

    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        _json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "https://x.io/sse", "type": "sse"},
                }
            }
        )
    )
    result = runner.invoke(
        cli, ["scan", str(cfg), "--config", "--offline", "--static-only"]
    )
    assert result.exit_code == 2


def test_config_flag_with_malformed_config_exits(runner, tmp_path):
    cfg = tmp_path / "bad.json"
    cfg.write_text("{not json")
    result = runner.invoke(
        cli, ["scan", str(cfg), "--config", "--offline", "--static-only"]
    )
    assert result.exit_code == 2


def test_config_and_batch_are_mutually_exclusive(runner, tmp_path):
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}")
    result = runner.invoke(cli, ["scan", str(cfg), "--config", "--batch"])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output.lower()


def test_unknown_source_prefix_errors(runner):
    result = runner.invoke(
        cli, ["scan", "docker:foo/bar", "--offline", "--static-only"]
    )
    assert result.exit_code == 2
    assert (
        "docker" in result.output.lower() or "unknown source" in result.output.lower()
    )


def test_github_source_dispatched_through_cli(runner, monkeypatch, tmp_path):
    """End-to-end: scan with github: prefix uses the github fetcher."""
    from contextlib import contextmanager
    import nyuwaymcpscanner.sources as sources

    fake_repo = tmp_path / "fake_repo"
    fake_repo.mkdir()
    (fake_repo / "index.js").write_text("// nothing scary here\n")

    called = {"n": 0}

    @contextmanager
    def fake_github(spec):
        called["n"] += 1
        assert spec == "github:nyuway/scanner"
        yield fake_repo

    monkeypatch.setattr(sources, "fetch_github", fake_github)

    result = runner.invoke(
        cli, ["scan", "github:nyuway/scanner", "--offline", "--static-only"]
    )
    assert result.exit_code == 0, f"Output: {result.output}"
    assert called["n"] == 1
    # The displayed target should be the original spec, not the temp path.
    assert "github:nyuway/scanner" in result.output


def test_batch_fail_on_aggregates_across_targets(
    runner, tmp_path, clean_server_path, server_with_secret
):
    listing = tmp_path / "servers.txt"
    listing.write_text(f"{clean_server_path}\n{server_with_secret}\n")
    result = runner.invoke(
        cli, ["scan", str(listing), "--offline", "--batch", "--fail-on", "high"]
    )
    assert result.exit_code == 1


# ---------- single-file scan tests ----------


def test_single_file_clean_passes(runner, tmp_path):
    """Scanning a clean individual file returns PASS."""
    f = tmp_path / "server.py"
    f.write_text('print("hello")\n')
    result = runner.invoke(cli, ["scan", str(f), "--offline", "--static-only"])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_single_file_with_secret_detected(runner, tmp_path):
    """Scanning a single file containing a secret surfaces the finding."""
    f = tmp_path / "config.py"
    f.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    result = runner.invoke(cli, ["scan", str(f), "--offline", "--static-only"])
    assert result.exit_code == 0
    assert "hardcoded_secret" in result.output


def test_single_file_does_not_include_sibling_findings(runner, tmp_path):
    """Findings from sibling files must NOT appear when scanning a single file."""
    import json as _json

    # clean file to scan
    target = tmp_path / "clean.py"
    target.write_text('print("hello")\n')
    # sibling with a secret - must be ignored
    (tmp_path / "other.py").write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    result = runner.invoke(
        cli, ["scan", str(target), "--offline", "--static-only", "--output", "json"]
    )
    assert result.exit_code == 0
    report = _json.loads(result.output)
    assert report["verdict"] == "PASS", (
        f"Sibling file findings leaked into single-file scan: {report['findings']}"
    )


def test_single_file_json_output_is_valid(runner, tmp_path):
    """Single-file scan produces valid JSON report."""
    import json as _json

    f = tmp_path / "tool.py"
    f.write_text('import os\ndef run(cmd):\n    os.system("echo " + cmd)\n')
    result = runner.invoke(
        cli, ["scan", str(f), "--offline", "--static-only", "--output", "json"]
    )
    assert result.exit_code == 0
    report = _json.loads(result.output)
    assert report["target"] == str(f)
    assert isinstance(report["findings"], list)


def test_single_file_missing_exits_with_error(runner, tmp_path):
    """Scanning a non-existent file exits with code 2."""
    result = runner.invoke(cli, ["scan", str(tmp_path / "nope.py"), "--offline"])
    assert result.exit_code == 2
