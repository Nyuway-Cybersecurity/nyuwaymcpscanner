"""SARIF 2.1.0 output.

SARIF (Static Analysis Results Interchange Format) is the standard
machine-readable format consumed by GitHub Code Scanning, Azure DevOps,
GitLab, and most enterprise SAST dashboards.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "nyuwaymcpscanner"
TOOL_VERSION = "0.1.0"
INFORMATION_URI = "https://nyuway.ai/mcp-scanner"

# Map our internal severities to SARIF levels.
SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _rule_id_for(finding: dict) -> str:
    """Stable rule identifier per finding type."""
    base = finding.get("type", "finding")
    sub = finding.get("label") or finding.get("rule")
    return f"{base}/{sub}" if sub else base


def _location_for(finding: dict) -> dict | None:
    """Build a SARIF physicalLocation block when the finding has file context."""
    file_path = finding.get("file")
    if not file_path:
        return None
    # SARIF expects forward slashes and URIs relative to the repo root when possible.
    uri = str(file_path).replace("\\", "/")
    region: dict = {}
    if finding.get("line") is not None:
        try:
            region["startLine"] = int(finding["line"])
        except (TypeError, ValueError):
            pass
    physical: dict = {"artifactLocation": {"uri": uri}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def _collect_rules(findings: list[dict]) -> list[dict]:
    """Build the reportingDescriptor entries (one per unique rule id)."""
    rules: dict[str, dict] = {}
    for f in findings:
        rid = _rule_id_for(f)
        if rid in rules:
            continue
        rules[rid] = {
            "id": rid,
            "name": rid.replace("/", "_"),
            "shortDescription": {
                "text": f.get("description") or rid,
            },
            "fullDescription": {
                "text": f.get("rationale") or f.get("description") or rid,
            },
            "defaultConfiguration": {
                "level": SEVERITY_TO_LEVEL.get(f.get("severity", "low"), "note"),
            },
            "properties": {
                "category": f.get("category") or f.get("type") or "uncategorized",
                "severity": f.get("severity", "low"),
            },
        }
    return list(rules.values())


def _result_for(finding: dict) -> dict:
    rid = _rule_id_for(finding)
    message_text = (
        finding.get("rationale")
        or finding.get("description")
        or finding.get("evidence")
        or rid
    )
    result: dict = {
        "ruleId": rid,
        "level": SEVERITY_TO_LEVEL.get(finding.get("severity", "low"), "note"),
        "message": {"text": str(message_text)[:1000]},
    }
    loc = _location_for(finding)
    if loc:
        result["locations"] = [loc]

    # Carry tool-specific detail in properties so consumers can deep-dive without
    # polluting the SARIF message field.
    extra: dict = {}
    for key in (
        "severity",
        "weight",
        "confidence",
        "evidence",
        "tool_name",
        "package",
        "version",
        "ecosystem",
        "cve_id",
        "category",
        "source",
    ):
        if key in finding and finding[key] is not None:
            extra[key] = finding[key]
    if extra:
        result["properties"] = extra
    return result


def build_sarif(target: str, score: int, verdict: str, findings: list[dict]) -> dict:
    """Build a SARIF 2.1.0 log object."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": INFORMATION_URI,
                        "rules": _collect_rules(findings),
                    }
                },
                "results": [_result_for(f) for f in findings],
                "properties": {
                    "target": target,
                    "risk_score": score,
                    "verdict": verdict,
                    "finding_count": len(findings),
                },
            }
        ],
    }


def render_sarif(target: str, score: int, verdict: str, findings: list[dict]) -> str:
    return json.dumps(build_sarif(target, score, verdict, findings), indent=2)
