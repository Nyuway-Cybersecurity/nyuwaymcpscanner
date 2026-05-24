"""YARA engine tests."""

import pytest
from nyuwaymcpscanner.scanners.yara_engine import run_yara


def test_clean_server_no_yara_findings(clean_server_path):
    findings = run_yara(str(clean_server_path))
    assert isinstance(findings, list)
    assert findings == []


def test_detects_tool_poisoning_pattern(server_with_yara_trigger):
    findings = run_yara(str(server_with_yara_trigger))
    assert findings, "Expected YARA to flag the forwarding instruction"
    rules_fired = {f["rule"] for f in findings}
    assert "Tool_Description_Forward_Instruction" in rules_fired


def test_finding_structure_when_matched(server_with_yara_trigger):
    findings = run_yara(str(server_with_yara_trigger))
    assert findings
    for f in findings:
        assert "rule" in f
        assert "file" in f
        assert "severity" in f
        assert "weight" in f
        assert "category" in f


@pytest.mark.parametrize(
    "rule_name,content",
    [
        (
            "Hardcoded_External_Logging_Endpoint",
            'WEBHOOK = "https://something.webhook.site/abc123"\n',
        ),
        (
            "Suspicious_Shell_Execution_In_Tool",
            'import os\nos.system("rm -rf /tmp/x")\n',
        ),
        (
            "Plaintext_Password_Assignment",
            'password = "hunter2pass"\n',
        ),
        (
            "Private_IP_Or_Internal_Endpoint",
            'API = "http://10.0.0.5/internal"\n',
        ),
    ],
)
def test_each_yara_rule_fires(tmp_path, rule_name, content):
    project = tmp_path / f"rule_{rule_name}"
    project.mkdir()
    (project / "tool.py").write_text(content)
    findings = run_yara(str(project))
    rules_fired = {f["rule"] for f in findings}
    assert rule_name in rules_fired, (
        f"Expected rule '{rule_name}' to fire on its own sample. Got: {rules_fired}"
    )


@pytest.mark.parametrize(
    "filename,content",
    [
        # Go
        ("tool.go", 'cmd := exec.Command("sh", "-c", userInput)\n'),
        ("tool.go", 'cmd := exec.CommandContext(ctx, "bash", arg)\n'),
        # Java
        ("Tool.java", "Process p = Runtime.getRuntime().exec(cmd);\n"),
        ("Tool.java", "ProcessBuilder pb = new ProcessBuilder(args);\n"),
        # Rust
        ("tool.rs", 'let output = Command::new("sh").arg("-c").arg(cmd).output();\n'),
        # Ruby
        ("tool.rb", 'system("rm -rf /tmp/x")\n'),
        ("tool.rb", "result = `ls #{user_dir}`\n"),
        ("tool.rb", "IO.popen(cmd) { |io| io.read }\n"),
        # C#
        ("Tool.cs", 'Process.Start("cmd.exe", args);\n'),
        ("Tool.cs", "var proc = new Process();\n"),
        # PHP
        ("tool.php", "$out = shell_exec($cmd);\n"),
        ("tool.php", "passthru($user_input);\n"),
        ("tool.php", "$handle = proc_open($cmd, $desc, $pipes);\n"),
        # Kotlin
        ("Tool.kt", 'val pb = ProcessBuilder(listOf("sh", "-c", cmd))\n'),
    ],
)
def test_shell_exec_rule_fires_for_multilang(tmp_path, filename, content):
    project = tmp_path / "proj"
    project.mkdir()
    (project / filename).write_text(content)
    findings = run_yara(str(project))
    rules_fired = {f["rule"] for f in findings}
    assert "Suspicious_Shell_Execution_In_Tool" in rules_fired, (
        f"Expected Suspicious_Shell_Execution_In_Tool for {filename!r}. Got: {rules_fired}"
    )


def test_yara_rules_file_itself_does_not_self_trigger(tmp_path):
    """Regression: scanning a tree containing the bundled .yar file must not
    flag the rule definitions themselves."""
    from nyuwaymcpscanner.scanners.yara_engine import DEFAULT_RULES_FILE

    project = tmp_path / "with_yar"
    project.mkdir()
    # Copy the actual bundled rules file into the scanned tree.
    (project / "mcp_threats.yar").write_text(
        DEFAULT_RULES_FILE.read_text(encoding="utf-8")
    )
    findings = run_yara(str(project))
    files_flagged = {f["file"] for f in findings}
    yar_hits = [f for f in files_flagged if f.endswith(".yar")]
    assert not yar_hits, f".yar files should be skipped, but got hits: {yar_hits}"
