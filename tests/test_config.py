"""Tests for MCP host config parsing."""

import json
import pytest

from nyuwaymcpscanner.sources.config import (
    parse_config,
    ConfigParseError,
    resolvable_specs,
)


def _write(tmp_path, payload):
    f = tmp_path / "mcp_config.json"
    f.write_text(json.dumps(payload))
    return str(f)


def test_parses_npx_runner(tmp_path):
    cfg = _write(
        tmp_path,
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                }
            }
        },
    )
    entries = parse_config(cfg)
    assert len(entries) == 1
    assert entries[0].name == "github"
    assert entries[0].spec == "npm:@modelcontextprotocol/server-github"


def test_parses_uvx_runner(tmp_path):
    cfg = _write(
        tmp_path,
        {"mcpServers": {"weather": {"command": "uvx", "args": ["weather-mcp"]}}},
    )
    entries = parse_config(cfg)
    assert entries[0].spec == "pypi:weather-mcp"


def test_python_script_resolved_to_local_path(tmp_path):
    cfg = _write(
        tmp_path,
        {
            "mcpServers": {
                "custom": {"command": "python", "args": ["/opt/mcp/server.py"]}
            }
        },
    )
    entries = parse_config(cfg)
    assert entries[0].spec == "/opt/mcp/server.py"


def test_node_script_resolved(tmp_path):
    cfg = _write(
        tmp_path,
        {"mcpServers": {"custom": {"command": "node", "args": ["./local-server.js"]}}},
    )
    entries = parse_config(cfg)
    assert entries[0].spec == "./local-server.js"


def test_direct_executable_path(tmp_path):
    cfg = _write(
        tmp_path,
        {"mcpServers": {"bin": {"command": "/opt/mcp/bin/server", "args": []}}},
    )
    entries = parse_config(cfg)
    assert entries[0].spec == "/opt/mcp/bin/server"


def test_remote_endpoint_deferred(tmp_path):
    cfg = _write(
        tmp_path,
        {
            "mcpServers": {
                "remote": {"url": "https://mcp.example.com/sse", "type": "sse"}
            }
        },
    )
    entries = parse_config(cfg)
    assert entries[0].spec is None
    assert "remote" in entries[0].notes.lower() or "v1.1" in entries[0].notes


def test_servers_key_alias_for_vscode(tmp_path):
    """VS Code MCP uses 'servers' instead of 'mcpServers'."""
    cfg = _write(
        tmp_path,
        {
            "servers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                }
            }
        },
    )
    entries = parse_config(cfg)
    assert entries[0].spec == "npm:@modelcontextprotocol/server-github"


def test_missing_command_returns_unresolved(tmp_path):
    cfg = _write(tmp_path, {"mcpServers": {"broken": {"args": ["x"]}}})
    entries = parse_config(cfg)
    assert entries[0].spec is None
    assert "missing command" in entries[0].notes


def test_non_dict_entry_skipped_gracefully(tmp_path):
    cfg = _write(tmp_path, {"mcpServers": {"weird": "not an object"}})
    entries = parse_config(cfg)
    assert entries[0].spec is None


def test_npx_with_only_flags(tmp_path):
    cfg = _write(
        tmp_path, {"mcpServers": {"f": {"command": "npx", "args": ["-y", "--quiet"]}}}
    )
    entries = parse_config(cfg)
    assert entries[0].spec is None


def test_multiple_servers_all_parsed(tmp_path):
    cfg = _write(
        tmp_path,
        {
            "mcpServers": {
                "gh": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                },
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                },
                "py": {"command": "uvx", "args": ["weather-mcp"]},
                "remote": {"url": "https://x.io/sse", "type": "sse"},
            }
        },
    )
    entries = parse_config(cfg)
    specs = resolvable_specs(entries)
    assert "npm:@modelcontextprotocol/server-github" in specs
    assert "pypi:weather-mcp" in specs
    # The filesystem one has a path arg too; the resolver picks the first non-flag
    # arg, which is the package name (path comes after).
    assert any("server-filesystem" in s for s in specs)
    # Remote one isn't resolvable.
    assert len(specs) == 3


def test_malformed_json_raises(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not json")
    with pytest.raises(ConfigParseError):
        parse_config(str(f))


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigParseError):
        parse_config(str(tmp_path / "nope.json"))


def test_mcpServers_not_object_raises(tmp_path):
    cfg = _write(tmp_path, {"mcpServers": ["this", "is", "wrong"]})
    with pytest.raises(ConfigParseError):
        parse_config(cfg)


def test_empty_config_is_valid_but_yields_nothing(tmp_path):
    cfg = _write(tmp_path, {})
    entries = parse_config(cfg)
    assert entries == []
