"""VirusTotal hash-lookup scanner for binary files.

Computes SHA256 of each binary in the scan tree and checks it against the
VirusTotal public API. No file content is uploaded - only the hash is sent.

Requires a VirusTotal API key (free tier: 4 req/min, 500 req/day):
  - Set VIRUSTOTAL_API_KEY environment variable, or
  - Pass --vt-key on the CLI.

The scanner is silently skipped when no key is available or --offline is set.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import requests

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
REQUEST_TIMEOUT = 15

# Binary file extensions worth checking against VT.
BINARY_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib",
    ".whl", ".egg",
    ".tar", ".gz", ".tgz", ".zip", ".bz2", ".xz",
    ".pdf",
    ".bin", ".dat",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

# Free tier: 4 requests/minute. Add a small delay between calls to stay safe.
_REQUEST_DELAY_SECONDS = 15


class VTKeyMissing(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _query_vt(sha256: str, api_key: str) -> dict | None:
    """Return VT file report dict or None on miss/error."""
    url = VT_API_URL.format(hash=sha256)
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return None  # VT has never seen this file - not flagged
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError):
        return None


def _iter_binaries(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            yield path


def _detection_ratio(report: dict) -> tuple[int, int]:
    stats = (
        report.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    return malicious, total


def count_binaries(path: str) -> int:
    """Return the number of binary files that would be checked by VT."""
    root = Path(path)
    if not root.exists():
        return 0
    if root.is_file():
        return 1 if root.suffix.lower() in BINARY_SUFFIXES else 0
    return sum(1 for _ in _iter_binaries(root))


def scan_virustotal(path: str, api_key: str) -> list[dict]:
    """Hash-check binary files in path against VirusTotal.

    Returns findings for any file with at least one malicious detection.
    Sleeps between requests to respect the free-tier rate limit.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if not api_key:
        raise VTKeyMissing("No VirusTotal API key provided")

    files = [root] if (root.is_file() and root.suffix.lower() in BINARY_SUFFIXES) \
            else list(_iter_binaries(root))

    findings: list[dict] = []
    for i, file_path in enumerate(files):
        if i > 0:
            time.sleep(_REQUEST_DELAY_SECONDS)

        sha = _sha256(file_path)
        report = _query_vt(sha, api_key)
        if report is None:
            continue

        malicious, total = _detection_ratio(report)
        if malicious == 0:
            continue

        severity = "critical" if malicious >= 5 else "high" if malicious >= 2 else "medium"
        weight = 35 if malicious >= 5 else 25 if malicious >= 2 else 15

        findings.append({
            "type": "malware_detected",
            "severity": severity,
            "weight": weight,
            "file": str(file_path),
            "sha256": sha,
            "detections": f"{malicious}/{total}",
            "description": f"VirusTotal: {malicious} of {total} engines flagged this file",
            "source": "virustotal",
        })

    return findings


def resolve_api_key(cli_key: str | None) -> str | None:
    """Return the API key from CLI flag or VIRUSTOTAL_API_KEY env var."""
    return cli_key or os.environ.get("VIRUSTOTAL_API_KEY") or None
