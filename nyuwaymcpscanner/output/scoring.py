"""0-100 risk score engine.

Score reflects the most serious findings, not just the count. A single critical
finding scores higher than many low findings. Verdict is the higher of:
  - the band the numeric score falls into, and
  - the floor implied by the most severe finding present.
"""

SEVERITY_FLOOR = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
}

VERDICTS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "PASS"),
]


def _verdict_for(score: int) -> str:
    for threshold, label in VERDICTS:
        if score >= threshold:
            return label
    return "PASS"


def calculate_score(findings: list[dict]) -> tuple[int, str]:
    """Return (score 0-100, verdict string) from a list of findings.

    Each finding must have a 'severity' (critical/high/medium/low) and 'weight'.
    """
    if not findings:
        return 0, "PASS"

    weight_sum = sum(int(f.get("weight", 0)) for f in findings)
    severity_floor = max(
        (SEVERITY_FLOOR.get(f.get("severity", "").lower(), 0) for f in findings),
        default=0,
    )
    score = max(0, min(100, max(weight_sum, severity_floor)))
    return score, _verdict_for(score)
