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

# Directory name segments that indicate test/example/documentation/CI context.
_TEST_OR_DOC_PARTS = {
    "tests", "test", "__tests__",
    "examples", "example",
    "docs", "doc",
    ".github",
}


def _is_test_or_doc_file(path: Path) -> bool:
    """Return True for test fixtures, example code, documentation, and CI files."""
    lower_parts = {p.lower() for p in path.parts}
    if lower_parts & _TEST_OR_DOC_PARTS:
        return True
    name = path.name.lower()
    # pytest-style: test_foo.py; Jest-style: foo.test.ts / foo.spec.js
    if name.startswith("test_") or name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js")):
        return True
    if path.suffix.lower() in {".md", ".sh"}:
        return True
    return False


def _is_cli_file(path: Path) -> bool:
    """Return True for CLI entry-point files where process spawning is expected."""
    lower_parts = [p.lower() for p in path.parts]
    if "cli" in lower_parts:
        return True
    return path.stem.lower() in {"cli", "main", "__main__"}


# Rules that should be suppressed for test/example/doc files (too noisy).
_SUPPRESS_IN_TEST_OR_DOC = {"Private_IP_Or_Internal_Endpoint"}

# Rules that should be suppressed in CLI entry-point files.
_SUPPRESS_IN_CLI = {"Suspicious_Shell_Execution_In_Tool"}

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

        is_test_doc = _is_test_or_doc_file(file_path)
        is_cli = _is_cli_file(file_path)

        for match in matches:
            if is_test_doc and match.rule in _SUPPRESS_IN_TEST_OR_DOC:
                continue
            if is_cli and match.rule in _SUPPRESS_IN_CLI:
                continue
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
