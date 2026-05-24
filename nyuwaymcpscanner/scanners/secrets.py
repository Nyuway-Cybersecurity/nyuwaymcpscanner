"""Credential and secret detection.

Pattern catalogue is intentionally small for v0.1. The full 95+ pattern target
is tracked in the project roadmap and will be expanded incrementally with
fixture-backed tests.
"""

import re
from pathlib import Path

# Each entry: (label, compiled pattern, severity)
PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    (
        "aws_secret_access_key",
        re.compile(
            r"\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
            re.IGNORECASE,
        ),
        "high",
    ),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "high"),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "high"),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "high"),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    (
        "generic_jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
        "medium",
    ),
]

# Placeholder substrings that appear in documentation examples and READMEs.
# A matched value containing any of these is treated as a non-secret.
_PLACEHOLDER_FRAGMENTS = {
    "your-",
    "-your-",
    "your_",
    "_your_",
    "xxxxxxx",
    "replace-me",
    "insert-here",
}

# The canonical jwt.io demonstration token that appears in countless test suites.
_KNOWN_SAFE_JWTS = {
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
    # Compact variant without the assertion= prefix
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
}

# Directory segments that indicate test or example context.
_TEST_OR_DOC_PARTS = {
    "tests",
    "test",
    "__tests__",
    "examples",
    "example",
    "docs",
    "doc",
}


def _is_test_or_doc_file(path: Path) -> bool:
    lower_parts = {p.lower() for p in path.parts}
    if lower_parts & _TEST_OR_DOC_PARTS:
        return True
    name = path.name.lower()
    if name.startswith("test_") or name.endswith(
        (".test.ts", ".test.js", ".spec.ts", ".spec.js")
    ):
        return True
    if path.suffix.lower() == ".md":
        return True
    return False


def _is_placeholder(matched_value: str) -> bool:
    lower = matched_value.lower()
    return any(frag in lower for frag in _PLACEHOLDER_FRAGMENTS)


def _is_known_safe_jwt(matched_value: str) -> bool:
    return matched_value.strip() in _KNOWN_SAFE_JWTS


# Skip binaries and lock-style files where matches would be noise.
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
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

# Cap individual file reads to avoid pathological inputs.
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        yield path


def scan_secrets(path: str) -> list[dict]:
    """Walk a directory and return all secret findings."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    findings: list[dict] = []

    if root.is_file():
        files = [root]
    else:
        files = list(_iter_files(root))

    for file_path in files:
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        is_test_doc = _is_test_or_doc_file(file_path)

        for line_num, line in enumerate(text.splitlines(), start=1):
            for label, pattern, severity in PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                matched_value = m.group(0)

                # Drop obvious documentation placeholders.
                if _is_placeholder(matched_value):
                    continue

                # Drop the canonical jwt.io demo token used in test suites.
                if label == "generic_jwt" and _is_known_safe_jwt(matched_value):
                    continue

                # JWTs in test/example/doc files are almost always fixtures.
                if label == "generic_jwt" and is_test_doc:
                    continue

                findings.append(
                    {
                        "type": "hardcoded_secret",
                        "label": label,
                        "severity": severity,
                        "weight": 25,
                        "file": str(file_path),
                        "line": line_num,
                        "evidence": line.strip()[:200],
                    }
                )

    return findings
