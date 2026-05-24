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
        # Go - original
        ("tool.go", 'cmd := exec.Command("sh", "-c", userInput)\n'),
        ("tool.go", 'cmd := exec.CommandContext(ctx, "bash", arg)\n'),
        # Go - new
        ("tool.go", "syscall.Exec(path, args, env)\n"),
        ("tool.go", "syscall.ForkExec(path, args, nil)\n"),
        # Java - original
        ("Tool.java", "Process p = Runtime.getRuntime().exec(cmd);\n"),
        ("Tool.java", "ProcessBuilder pb = new ProcessBuilder(args);\n"),
        # Java - new
        ("Tool.java", "ScriptEngineManager mgr = new ScriptEngineManager();\n"),
        # Kotlin - original
        ("Tool.kt", 'val pb = ProcessBuilder(listOf("sh", "-c", cmd))\n'),
        # Kotlin - new
        ("Tool.kt", "Runtime.getRuntime().exec(cmd)\n"),
        # Rust - original
        ("tool.rs", 'let output = Command::new("sh").arg("-c").arg(cmd).output();\n'),
        # Rust - new
        ("tool.rs", "use std::process::Command;\n"),
        ("tool.rs", "nix::unistd::execv(&path, &args);\n"),
        # Ruby - original
        ("tool.rb", 'system("rm -rf /tmp/x")\n'),
        ("tool.rb", "result = `ls #{user_dir}`\n"),
        ("tool.rb", "IO.popen(cmd) { |io| io.read }\n"),
        # Ruby - new
        ("tool.rb", "result = %x{ls #{dir}}\n"),
        ("tool.rb", "Open3.popen3(cmd) { |i, o, e| o.read }\n"),
        ("tool.rb", "Open3.capture3(cmd)\n"),
        ("tool.rb", "PTY.spawn(cmd) { |r, w, pid| r.read }\n"),
        ("tool.rb", "pid = spawn(cmd)\n"),
        # C# - original
        ("Tool.cs", 'Process.Start("cmd.exe", args);\n'),
        ("Tool.cs", "var proc = new Process();\n"),
        # C# - new
        ("Tool.cs", "var psi = new ProcessStartInfo(cmd);\n"),
        ("Tool.cs", "var asm = Assembly.Load(bytes);\n"),
        ("Tool.cs", "var provider = new CSharpCodeProvider();\n"),
        # PHP - original
        ("tool.php", "$out = shell_exec($cmd);\n"),
        ("tool.php", "passthru($user_input);\n"),
        ("tool.php", "$handle = proc_open($cmd, $desc, $pipes);\n"),
        # PHP - new
        ("tool.php", "system($cmd);\n"),
        ("tool.php", "exec($cmd, $output);\n"),
        ("tool.php", "eval($code);\n"),
        ("tool.php", "$out = `$cmd`;\n"),
        ("tool.php", "$fn = create_function('', $code);\n"),
        ("tool.php", "assert('eval($x)');\n"),
        ("tool.php", "preg_replace('/pattern/e', $code, $str);\n"),
        # Python - new
        ("tool.py", "os.popen(cmd).read()\n"),
        ("tool.py", "os.execv('/bin/sh', ['/bin/sh', '-c', cmd])\n"),
        ("tool.py", "subprocess.getoutput(cmd)\n"),
        ("tool.py", "subprocess.getstatusoutput(cmd)\n"),
        ("tool.py", "pty.spawn(cmd)\n"),
        # JS - new
        ("tool.js", "child_process.spawn('sh', ['-c', cmd])\n"),
        ("tool.js", "child_process.spawnSync('sh', args)\n"),
        ("tool.js", "child_process.execSync(cmd)\n"),
        ("tool.js", "child_process.execFile('/bin/sh', args)\n"),
        ("tool.js", "const fn = new Function('return ' + code)();\n"),
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
