"""MCP config and tool schema parser."""

import json
from pathlib import Path


def parse_manifest(path: str) -> dict:
    """Parse an MCP manifest JSON file.

    Returns a dict with at minimum a 'tools' key (possibly empty list).
    Raises FileNotFoundError if the path does not exist.
    Raises json.JSONDecodeError on malformed JSON.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Manifest not found: {path}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Manifest root must be an object, got {type(data).__name__}")

    data.setdefault("tools", [])
    return data
