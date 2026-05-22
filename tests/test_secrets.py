"""Secret detection scanner tests."""
import pytest
from nyuwaymcpscanner.scanners.secrets import scan_secrets


def test_detects_aws_access_key(server_with_secret):
    findings = scan_secrets(str(server_with_secret))
    types = [f["type"] for f in findings]
    assert "hardcoded_secret" in types


def test_clean_server_no_secret_findings(clean_server_path):
    findings = scan_secrets(str(clean_server_path))
    assert findings == []


def test_finding_includes_file_and_line(server_with_secret):
    findings = scan_secrets(str(server_with_secret))
    assert findings, "Expected at least one finding"
    for f in findings:
        assert "file" in f
        assert "line" in f
        assert "evidence" in f


# One test per credential pattern. Tokens below are synthetic — they match
# the pattern shape but are not valid against any real provider.

def test_aws_secret_key_requires_exactly_40_chars(tmp_path):
    """The AWS secret regex requires a 40-char body. 39 should not match, 40 should."""
    project = tmp_path / "boundary"
    project.mkdir()
    short_key = "A" * 39
    exact_key = "A" * 40
    too_long_key = "A" * 41

    (project / "short.py").write_text(f'aws_secret_access_key = "{short_key}"\n')
    (project / "exact.py").write_text(f'aws_secret_access_key = "{exact_key}"\n')
    (project / "long.py").write_text(f'aws_secret_access_key = "{too_long_key}"\n')

    findings = scan_secrets(str(project))
    by_file = {f["file"].split("\\")[-1].split("/")[-1]: f for f in findings if f["label"] == "aws_secret_access_key"}

    assert "exact.py" in by_file, "Expected 40-char key to match"
    assert "short.py" not in by_file, "39-char key should not match"
    # 41 chars: the regex's capture group is exactly 40, so on a 41-char body
    # inside quotes it should not match because the closing quote is required.
    assert "long.py" not in by_file, "41-char body inside quotes should not match exact-40 capture"


@pytest.mark.parametrize("label,sample", [
    ("github_pat",          'TOKEN = "ghp_' + "A" * 36 + '"'),
    ("github_oauth",        'TOKEN = "gho_' + "B" * 36 + '"'),
    ("openai_api_key",      'KEY = "sk-' + "C" * 32 + '"'),
    ("anthropic_api_key",   'KEY = "sk-ant-' + "D" * 30 + '"'),
    ("slack_token",         'TOKEN = "xoxb-1234567890-abcdefghijk"'),
    ("generic_jwt",         'JWT = "eyJabcdefghij.eyJklmnopqrst.uvwxyzABCDEF"'),
    ("aws_secret_access_key", 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'),
])
def test_each_secret_pattern_detected(tmp_path, label, sample):
    project = tmp_path / f"sample_{label}"
    project.mkdir()
    (project / "config.py").write_text(sample + "\n")
    findings = scan_secrets(str(project))
    labels = {f["label"] for f in findings}
    assert label in labels, (
        f"Pattern '{label}' did not match its own sample. "
        f"Got labels: {labels}"
    )
