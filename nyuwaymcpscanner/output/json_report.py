"""JSON report writer."""

import json
from datetime import datetime, timezone


def build_report(target: str, score: int, verdict: str, findings: list[dict]) -> dict:
    return {
        "tool": "nyuwaymcpscanner",
        "version": "0.1.0",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "risk_score": score,
        "verdict": verdict,
        "finding_count": len(findings),
        "findings": findings,
    }


def render_json(target: str, score: int, verdict: str, findings: list[dict]) -> str:
    return json.dumps(build_report(target, score, verdict, findings), indent=2)
