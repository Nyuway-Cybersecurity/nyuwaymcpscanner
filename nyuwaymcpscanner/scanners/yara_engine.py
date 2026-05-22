"""YARA rule execution against MCP server source."""

import yara
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
DEFAULT_RULES_FILE = RULES_DIR / "mcp_threats.yar"

# Same skip behaviour as the secrets scanner — keeps results clean of noise.
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".pyc",
    ".so",
    ".dll",
    ".exe",
    ".yar",
    ".yara",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_BYTES = 2 * 1024 * 1024

_compiled_rules: yara.Rules | None = None


def _load_rules() -> yara.Rules:
    global _compiled_rules
    if _compiled_rules is None:
        if not DEFAULT_RULES_FILE.is_file():
            raise FileNotFoundError(f"YARA rules file missing: {DEFAULT_RULES_FILE}")
        _compiled_rules = yara.compile(filepath=str(DEFAULT_RULES_FILE))
    return _compiled_rules


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        yield path


def run_yara(path: str) -> list[dict]:
    """Scan a path with the bundled YARA rules and return structured findings."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    rules = _load_rules()
    findings: list[dict] = []

    files = [root] if root.is_file() else list(_iter_files(root))

    for file_path in files:
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            matches = rules.match(str(file_path))
        except (OSError, yara.Error):
            continue

        for match in matches:
            meta = match.meta or {}
            findings.append(
                {
                    "type": "yara_match",
                    "rule": match.rule,
                    "category": meta.get("category", "uncategorized"),
                    "severity": meta.get("severity", "medium"),
                    "weight": int(meta.get("weight", 15)),
                    "file": str(file_path),
                    "description": meta.get("description", ""),
                }
            )

    return findings
