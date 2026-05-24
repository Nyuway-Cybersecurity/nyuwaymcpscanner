/*
 * nyuwaymcpscanner — MCP threat YARA rules
 *
 * Each rule sets metadata:
 *   severity: critical | high | medium | low
 *   weight:   integer used by the scoring engine
 *   category: short tag for grouping in reports
 *
 * Rules target patterns that static analysis can catch without an LLM. The
 * LLM-assisted scanners (Baseline local LLM, Deep Scan) catch the semantic
 * variants these signature rules miss.
 */

rule Tool_Description_Forward_Instruction
{
    meta:
        severity = "critical"
        weight = 35
        category = "tool_poisoning"
        description = "Tool description contains forwarding or exfiltration instructions"

    strings:
        $a = "forward the user" nocase
        $b = "forward this to" nocase
        $c = "send the user's message" nocase
        $d = "send the message to https" nocase
        $e = "copy the user's input" nocase

    condition:
        any of them
}

rule Hardcoded_External_Logging_Endpoint
{
    meta:
        severity = "high"
        weight = 25
        category = "exfiltration"
        description = "Hardcoded external logging or collection endpoint"

    strings:
        $a = "log.external" nocase
        $b = "unknown-logger" nocase
        $c = ".webhook.site"
        $d = "/collect" nocase
        $e = "requestbin.com"
        $f = "pipedream.net"

    condition:
        any of them
}

rule Suspicious_Shell_Execution_In_Tool
{
    meta:
        severity = "high"
        weight = 25
        category = "code_execution"
        description = "Shell or process execution in MCP server source (Python, JS, Go, Java, Rust, Ruby, C#, PHP, Kotlin)"

    strings:
        // Python
        $py_os_system        = "os.system("
        $py_os_popen         = "os.popen("
        $py_os_execv         = /\bos\.exec[vle]/
        $py_subproc_shell    = /subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True/
        $py_subproc_getout   = "subprocess.getoutput("
        $py_subproc_getstat  = "subprocess.getstatusoutput("
        $py_pty_spawn        = "pty.spawn("

        // JavaScript / TypeScript
        $js_child_process    = "child_process.exec"
        $js_cp_spawn         = "child_process.spawn("
        $js_cp_spawn_sync    = "child_process.spawnSync("
        $js_cp_exec_sync     = "child_process.execSync("
        $js_cp_exec_file     = "child_process.execFile("
        $js_new_function     = /new\s+Function\s*\(/
        $js_eval             = /\beval\s*\(/

        // Go
        $go_exec_cmd         = "exec.Command("
        $go_exec_ctx         = "exec.CommandContext("
        $go_syscall_exec     = "syscall.Exec("
        $go_syscall_forkexec = "syscall.ForkExec("

        // Java
        $java_runtime_exec   = "Runtime.getRuntime().exec("
        $java_runtime_exec2  = "Runtime.exec("
        $java_proc_builder   = "new ProcessBuilder("
        $java_script_engine  = "ScriptEngineManager("

        // Kotlin
        $kt_proc_builder     = "ProcessBuilder("
        $kt_runtime_exec     = "Runtime.getRuntime().exec("

        // Rust
        $rust_command_new    = "Command::new("
        $rust_std_command    = "std::process::Command"
        $rust_nix_execv      = "nix::unistd::execv"

        // Ruby
        $rb_system           = /\bsystem\s*\(/
        $rb_backtick         = /`[^`]{3,}`/
        $rb_pct_x            = /%x\{[^}]{2,}\}/
        $rb_popen            = "IO.popen("
        $rb_open3_popen      = "Open3.popen3("
        $rb_open3_cap        = "Open3.capture3("
        $rb_pty_spawn        = "PTY.spawn("
        $rb_spawn            = /\bspawn\s*\(/
        $rb_exec             = /\bexec\s*\(/

        // C#
        $cs_proc_start       = "Process.Start("
        $cs_new_process      = "new Process("
        $cs_proc_start_info  = "new ProcessStartInfo("
        $cs_assembly_load    = "Assembly.Load("
        $cs_csharp_provider  = "CSharpCodeProvider"

        // PHP
        $php_shell_exec      = "shell_exec("
        $php_passthru        = "passthru("
        $php_popen           = /\bpopen\s*\(/
        $php_proc_open       = "proc_open("
        $php_system          = /\bsystem\s*\(/
        $php_exec            = /\bexec\s*\(/
        $php_eval            = /\beval\s*\(/
        $php_backtick        = /`[^`]{3,}`/
        $php_create_func     = "create_function("
        $php_assert          = /\bassert\s*\(\s*['"]/
        $php_preg_replace_e  = /preg_replace\s*\(\s*['"][^'"]*\/e/

    condition:
        any of them
}

rule Plaintext_Password_Assignment
{
    meta:
        severity = "high"
        weight = 25
        category = "credential_exposure"
        description = "Likely plaintext password assigned to a variable"

    strings:
        $a = /\b(password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]/ nocase

    condition:
        $a
}

rule Private_IP_Or_Internal_Endpoint
{
    meta:
        severity = "low"
        weight = 5
        category = "info_disclosure"
        description = "Internal endpoint or private IP in source"

    strings:
        $a = /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $b = /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}/
        $c = /https?:\/\/172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}/
        $d = "localhost:" nocase

    condition:
        any of them
}
