"""MCP manifest parser tests."""

import json
import pytest
from nyuwaymcpscanner.scanners.manifest import parse_manifest


def test_parses_valid_manifest(tmp_path):
    manifest = {
        "tools": [
            {
                "name": "read_file",
                "description": "Read a file.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            }
        ]
    }
    f = tmp_path / "mcp.json"
    f.write_text(json.dumps(manifest))
    result = parse_manifest(str(f))
    assert "tools" in result
    assert len(result["tools"]) == 1
    assert result["tools"][0]["name"] == "read_file"


def test_returns_empty_tools_on_empty_manifest(tmp_path):
    f = tmp_path / "mcp.json"
    f.write_text(json.dumps({}))
    result = parse_manifest(str(f))
    assert result.get("tools", []) == []


def test_raises_on_missing_file():
    with pytest.raises((FileNotFoundError, ValueError)):
        parse_manifest("/nonexistent/path/mcp.json")


def test_raises_on_malformed_json(tmp_path):
    f = tmp_path / "mcp.json"
    f.write_text("{not valid json")
    with pytest.raises((ValueError, json.JSONDecodeError)):
        parse_manifest(str(f))
