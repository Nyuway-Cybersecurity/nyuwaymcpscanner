"""MCP host config parsing.

Reads ``claude_desktop_config.json``, Cursor, VS Code, and Windsurf-style MCP
configs and converts each declared server into a target spec the scanner can
resolve (``local path``, ``npm:pkg``, or ``pypi:pkg``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

NPM_RUNNERS = {"npx", "bunx", "pnpm", "yarn"}
PY_RUNNERS = {"uvx", "pipx"}


def _expand_path(arg: str) -> str:
    """Expand a leading ~ but otherwise preserve the spec string verbatim.

    We deliberately avoid ``Path(...).expanduser()`` here because, on Windows,
    constructing a Path from a forward-slash string and converting back to str
    rewrites separators (``/opt/x`` → ``\\opt\\x``). That would break specs
    that downstream code compares as strings.
    """
    if arg.startswith("~"):
        from os.path import expanduser

        return expanduser(arg)
    return arg


class ConfigParseError(Exception):
    """Could not parse the MCP host config."""


class ConfigEntry:
    """One server entry resolved from a host config."""

    __slots__ = ("name", "spec", "notes")

    def __init__(self, name: str, spec: str | None, notes: str = ""):
        self.name = name
        self.spec = spec
        self.notes = notes

    def __repr__(self) -> str:
        return (
            f"ConfigEntry(name={self.name!r}, spec={self.spec!r}, notes={self.notes!r})"
        )


def _is_path_like(arg: str) -> bool:
    if not arg:
        return False
    if arg.startswith(("/", "./", "../", "~")):
        return True
    if len(arg) >= 3 and arg[1] == ":" and arg[0].isalpha():
        return True  # Windows drive letter
    return False


def _strip_npm_flags(args: list[str]) -> list[str]:
    """Drop common npx/bunx flags so we can find the package name."""
    skip_next = False
    cleaned: list[str] = []
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in {"-y", "--yes", "-q", "--quiet", "--silent"}:
            continue
        if a.startswith("-"):
            # Most npx flags do not take a value; conservative: just drop the flag.
            continue
        cleaned.append(a)
    return cleaned


def _resolve_command(name: str, command: str, args: list[str]) -> ConfigEntry:
    """Resolve a single MCP server entry to a scan target spec."""
    cmd = (command or "").lower().strip()
    if not cmd:
        return ConfigEntry(name, None, "missing command")

    base = Path(cmd).name.lower()

    # Npm-family runner: pick the first non-flag arg that isn't a path.
    if base in NPM_RUNNERS or cmd in NPM_RUNNERS:
        candidates = _strip_npm_flags(args)
        for arg in candidates:
            if _is_path_like(arg):
                return ConfigEntry(
                    name,
                    _expand_path(arg),
                    notes="resolved to local path from npm runner",
                )
            return ConfigEntry(name, f"npm:{arg}", notes=f"resolved via {base}")
        return ConfigEntry(name, None, f"no package name found in {base} args")

    # uvx/pipx: same logic but PyPI.
    if base in PY_RUNNERS or cmd in PY_RUNNERS:
        candidates = _strip_npm_flags(args)
        for arg in candidates:
            if _is_path_like(arg):
                return ConfigEntry(
                    name,
                    _expand_path(arg),
                    notes="resolved to local path from py runner",
                )
            return ConfigEntry(name, f"pypi:{arg}", notes=f"resolved via {base}")
        return ConfigEntry(name, None, f"no package name found in {base} args")

    # Direct interpreter: python/node/deno running a script.
    if base in {"python", "python3", "node", "deno", "bun"} or cmd in {
        "python",
        "python3",
        "node",
    }:
        for arg in args:
            if _is_path_like(arg) or arg.endswith((".py", ".js", ".mjs", ".ts")):
                return ConfigEntry(
                    name, _expand_path(arg), notes=f"resolved to script path via {base}"
                )
        return ConfigEntry(name, None, f"no script path found in {base} args")

    # Command itself is a path to an executable/script.
    if _is_path_like(cmd):
        return ConfigEntry(
            name, _expand_path(command), notes="command is a direct path"
        )

    return ConfigEntry(name, None, f"unrecognized command pattern: {cmd}")


def parse_config(path: str) -> list[ConfigEntry]:
    """Parse an MCP host config file into a list of ``ConfigEntry``."""
    p = Path(path)
    if not p.is_file():
        raise ConfigParseError(f"Config not found: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ConfigParseError(f"Malformed config {path}: {e}") from e

    # The standard key is "mcpServers" (Claude Desktop, Cursor, Windsurf).
    # VS Code MCP extension uses "servers"; accept both.
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        raise ConfigParseError(
            f"Config {path}: 'mcpServers' must be an object, got {type(servers).__name__}"
        )

    entries: list[ConfigEntry] = []
    for name, body in servers.items():
        if not isinstance(body, dict):
            entries.append(ConfigEntry(str(name), None, "entry is not an object"))
            continue
        # Remote SSE/HTTP entries declare a "url" or "type":"sse" - defer to v1.1.
        if body.get("url") or body.get("type") in {"sse", "http"}:
            entries.append(
                ConfigEntry(
                    str(name),
                    None,
                    "remote endpoint; remote scanning is deferred to v1.1",
                )
            )
            continue
        command = body.get("command", "")
        args = body.get("args") or []
        if not isinstance(args, list):
            args = []
        entries.append(
            _resolve_command(str(name), str(command), [str(a) for a in args])
        )
    return entries


def resolvable_specs(entries: Iterable[ConfigEntry]) -> list[str]:
    """Return only the scannable specs from a list of entries."""
    return [e.spec for e in entries if e.spec]
