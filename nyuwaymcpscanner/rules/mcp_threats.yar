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
        description = "Shell or process execution in MCP server source"

    strings:
        $py_os_system = "os.system("
        $py_subproc_shell = /subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True/
        $js_child_process = "child_process.exec"
        $js_eval = /\beval\s*\(/

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
