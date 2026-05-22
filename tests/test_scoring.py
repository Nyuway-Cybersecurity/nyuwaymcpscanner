"""Risk scoring engine tests."""
import pytest
from nyuwaymcpscanner.output.scoring import calculate_score, VERDICTS


def test_no_findings_returns_pass():
    score, verdict = calculate_score([])
    assert score <= 19
    assert verdict == "PASS"


def test_single_critical_finding_scores_high():
    findings = [{"severity": "critical", "weight": 35, "type": "tool_poisoning"}]
    score, verdict = calculate_score(findings)
    assert score >= 60


def test_verdict_thresholds():
    cases = [
        ([{"severity": "critical", "weight": 35}, {"severity": "critical", "weight": 35}], "CRITICAL"),
        ([{"severity": "high", "weight": 25}, {"severity": "high", "weight": 25}], "HIGH"),
        ([{"severity": "medium", "weight": 15}], "MEDIUM"),
        ([{"severity": "low", "weight": 5}], "LOW"),
        ([], "PASS"),
    ]
    for findings, expected_verdict in cases:
        _, verdict = calculate_score(findings)
        assert verdict == expected_verdict, f"Expected {expected_verdict}, got {verdict} for {findings}"


def test_score_capped_at_100():
    findings = [{"severity": "critical", "weight": 35}] * 10
    score, _ = calculate_score(findings)
    assert score <= 100


def test_score_not_negative():
    score, _ = calculate_score([])
    assert score >= 0
