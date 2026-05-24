"""Direct tests for terminal and JSON output renderers."""

import json
import pytest

from nyuwaymcpscanner.output.terminal import render_summary
from nyuwaymcpscanner.output.json_report import build_report, render_json
from nyuwaymcpscanner.output.sarif_report import build_sarif, render_sarif


@pytest.fixture
def sample_findings():
    return [
        {
            "type": "hardcoded_secret",
            "label": "github_pat",
            "severity": "high",
            "weight": 25,
            "file": "/tmp/foo/config.py",
            "line": 10,
            "evidence": 'TOKEN = "ghp_xxx"',
        },
        {
            "type": "yara_match",
            "rule": "Tool_Description_Forward_Instruction",
            "category": "tool_poisoning",
            "severity": "critical",
            "weight": 35,
            "file": "/tmp/foo/tool.py",
            "description": "Tool description contains forwarding",
        },
    ]


def test_terminal_render_includes_target_and_score(capsys, sample_findings):
    render_summary("/tmp/foo", 78, "HIGH", sample_findings)
    out = capsys.readouterr().out
    assert "/tmp/foo" in out
    assert "78" in out
    assert "HIGH" in out
    assert "Powered by nyuwaymcpscanner" in out


def test_terminal_render_pass_path_with_no_findings(capsys):
    render_summary("/tmp/clean", 0, "PASS", [])
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "No findings" in out


def test_terminal_render_shows_each_finding(capsys, sample_findings):
    render_summary("/tmp/foo", 78, "HIGH", sample_findings)
    out = capsys.readouterr().out
    assert "hardcoded_secret" in out
    assert "yara_match" in out


def test_build_report_shape(sample_findings):
    report = build_report("/tmp/foo", 78, "HIGH", sample_findings)
    assert report["tool"] == "nyuwaymcpscanner"
    assert report["target"] == "/tmp/foo"
    assert report["risk_score"] == 78
    assert report["verdict"] == "HIGH"
    assert report["finding_count"] == 2
    assert report["findings"] == sample_findings
    assert "scanned_at" in report
    assert "version" in report


def test_render_json_is_parseable(sample_findings):
    output = render_json("/tmp/foo", 78, "HIGH", sample_findings)
    parsed = json.loads(output)
    assert parsed["risk_score"] == 78
    assert len(parsed["findings"]) == 2


def test_render_json_empty_findings():
    output = render_json("/tmp/clean", 0, "PASS", [])
    parsed = json.loads(output)
    assert parsed["finding_count"] == 0
    assert parsed["findings"] == []


# ---------- SARIF ----------


def test_sarif_top_level_shape(sample_findings):
    log = build_sarif("/tmp/foo", 78, "HIGH", sample_findings)
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    assert isinstance(log["runs"], list) and len(log["runs"]) == 1


def test_sarif_driver_metadata(sample_findings):
    log = build_sarif("/tmp/foo", 78, "HIGH", sample_findings)
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "nyuwaymcpscanner"
    assert "version" in driver
    assert "informationUri" in driver


def test_sarif_results_match_findings_count(sample_findings):
    log = build_sarif("/tmp/foo", 78, "HIGH", sample_findings)
    assert len(log["runs"][0]["results"]) == len(sample_findings)


def test_sarif_severity_mapping(sample_findings):
    log = build_sarif("/tmp/foo", 78, "HIGH", sample_findings)
    levels = [r["level"] for r in log["runs"][0]["results"]]
    # sample_findings has one "high" and one "critical" - both map to "error".
    assert all(level in ("error", "warning", "note", "none") for level in levels)
    assert "error" in levels


def test_sarif_rule_ids_are_unique(sample_findings):
    log = build_sarif("/tmp/foo", 78, "HIGH", sample_findings)
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), "Rule IDs must be unique"


def test_sarif_carries_evidence_in_properties(sample_findings):
    log = build_sarif("/tmp/foo", 78, "HIGH", sample_findings)
    secret_result = next(
        r
        for r in log["runs"][0]["results"]
        if r["ruleId"].startswith("hardcoded_secret")
    )
    assert "properties" in secret_result
    assert secret_result["properties"].get("evidence") is not None


def test_sarif_empty_findings_still_valid():
    log = build_sarif("/tmp/clean", 0, "PASS", [])
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_handles_findings_without_file_location():
    findings = [
        {
            "type": "shadow_tool",
            "severity": "medium",
            "weight": 15,
            "tool_name": "github__create_issue",
            "rationale": "Mimics a trusted tool name",
            "confidence": 0.85,
            "source": "local_llm",
        }
    ]
    log = build_sarif("/tmp/foo", 40, "MEDIUM", findings)
    result = log["runs"][0]["results"][0]
    # No physical location, but the result must still be well-formed.
    assert "locations" not in result
    assert result["level"] == "warning"


def test_render_sarif_is_parseable(sample_findings):
    out = render_sarif("/tmp/foo", 78, "HIGH", sample_findings)
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"


def test_sarif_message_text_capped(sample_findings):
    huge = "Z" * 5000
    findings = [
        {
            "type": "tool_poisoning",
            "severity": "critical",
            "weight": 35,
            "rationale": huge,
        }
    ]
    log = build_sarif("/tmp/foo", 90, "CRITICAL", findings)
    msg = log["runs"][0]["results"][0]["message"]["text"]
    assert len(msg) <= 1000
