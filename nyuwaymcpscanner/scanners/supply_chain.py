"""Supply chain analysis: dependency CVE lookup and typosquatting checks.

CVE data is fetched from the OSV.dev public API. Typosquatting is detected by
Levenshtein distance against a known-popular package list.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import requests

OSV_API_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 10  # seconds

# A small seed of well-known package names. Real deployments will expand this.
POPULAR_PYPI = {
    "requests",
    "numpy",
    "pandas",
    "django",
    "flask",
    "fastapi",
    "pydantic",
    "click",
    "rich",
    "httpx",
    "aiohttp",
    "sqlalchemy",
    "pytest",
}
POPULAR_NPM = {
    "express",
    "react",
    "lodash",
    "axios",
    "moment",
    "vue",
    "next",
    "typescript",
    "webpack",
    "babel",
    "eslint",
    "jest",
}

CVE_SEVERITY_MAP = {
    "CRITICAL": ("critical", 25),
    "HIGH": ("high", 20),
    "MODERATE": ("medium", 15),
    "MEDIUM": ("medium", 15),
    "LOW": ("low", 5),
}


def _parse_requirements_txt(path: Path) -> list[tuple[str, str | None]]:
    """Return list of (name, version_or_None) from a requirements.txt-style file."""
    pkgs: list[tuple[str, str | None]] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(
            r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.\-]+)?", line
        )
        if not match:
            continue
        name = match.group(1).lower()
        version = match.group(3) if match.group(2) == "==" else None
        pkgs.append((name, version))
    return pkgs


def _parse_package_json(path: Path) -> list[tuple[str, str | None]]:
    pkgs: list[tuple[str, str | None]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return pkgs
    for key in ("dependencies", "devDependencies"):
        deps = data.get(key) or {}
        if isinstance(deps, dict):
            for name, version in deps.items():
                clean_version = re.sub(r"^[\^~>=<]+\s*", "", str(version)) or None
                pkgs.append((name.lower(), clean_version))
    return pkgs


def _enumerate_dependencies(root: Path) -> list[tuple[str, str | None, str]]:
    """Return (name, version, ecosystem) tuples found in a project tree."""
    found: list[tuple[str, str | None, str]] = []
    if root.is_file():
        candidates = [root]
    else:
        candidates = list(root.rglob("requirements*.txt")) + list(
            root.rglob("package.json")
        )

    for c in candidates:
        if any(part in {".git", "node_modules", ".venv", "venv"} for part in c.parts):
            continue
        if c.name.startswith("requirements") and c.suffix == ".txt":
            for name, version in _parse_requirements_txt(c):
                found.append((name, version, "PyPI"))
        elif c.name == "package.json":
            for name, version in _parse_package_json(c):
                found.append((name, version, "npm"))
    return found


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _check_typosquatting(name: str, ecosystem: str) -> str | None:
    popular = POPULAR_PYPI if ecosystem == "PyPI" else POPULAR_NPM
    if name in popular:
        return None
    for target in popular:
        if _levenshtein(name, target) == 1:
            return target
    return None


def _query_osv(name: str, version: str | None, ecosystem: str) -> list[dict]:
    """Query OSV.dev for vulnerabilities. Returns empty list on any error."""
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []
    return data.get("vulns", []) or []


def _vuln_to_finding(
    vuln: dict, pkg_name: str, version: str | None, ecosystem: str
) -> dict:
    sev_label = "medium"
    weight = 15
    for sev in vuln.get("database_specific", {}).get("severity", []) or []:
        mapped = CVE_SEVERITY_MAP.get(str(sev).upper())
        if mapped:
            sev_label, weight = mapped
            break
    for sev in vuln.get("severity", []) or []:
        score = str(sev.get("score", "")).upper()
        for key, mapped in CVE_SEVERITY_MAP.items():
            if key in score:
                sev_label, weight = mapped
                break
    return {
        "type": "dependency_cve",
        "severity": sev_label,
        "weight": weight,
        "package": pkg_name,
        "version": version,
        "ecosystem": ecosystem,
        "cve_id": vuln.get("id", "UNKNOWN"),
        "description": (vuln.get("summary") or "")[:300],
    }


def scan_supply_chain(path: str, offline: bool = False) -> list[dict]:
    """Walk a project for dependency manifests and return CVE + typosquat findings.

    When ``offline=True`` the scanner skips all network calls (OSV.dev lookup)
    and only reports typosquatting risks. Required for fully air-gapped scans.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    findings: list[dict] = []
    dependencies = _enumerate_dependencies(root)

    for name, version, ecosystem in dependencies:
        if not offline:
            for vuln in _query_osv(name, version, ecosystem):
                findings.append(_vuln_to_finding(vuln, name, version, ecosystem))

        squat_target = _check_typosquatting(name, ecosystem)
        if squat_target:
            findings.append(
                {
                    "type": "typosquatting_risk",
                    "severity": "medium",
                    "weight": 15,
                    "package": name,
                    "ecosystem": ecosystem,
                    "description": f"Package name '{name}' is one edit from popular '{squat_target}'",
                }
            )

    return findings
