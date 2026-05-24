# nyuwaymcpscanner

[![CI](https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/nyuwaymcpscanner)](https://pypi.org/project/nyuwaymcpscanner/)
[![Python](https://img.shields.io/pypi/pyversions/nyuwaymcpscanner)](https://pypi.org/project/nyuwaymcpscanner/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Enterprise-grade security scanner for Model Context Protocol (MCP) servers.**

Catches hardcoded secrets, tool-poisoning instructions, supply-chain attacks, shell-execution backdoors, and data-exfiltration endpoints before they reach production - entirely offline, with no data leaving your machine.

```
pip install nyuwaymcpscanner
nyuwaymcpscanner scan ./my-mcp-server
```

---

## Why nyuwaymcpscanner?

MCP servers run with broad access to files, shells, and network sockets on behalf of AI agents. A compromised or malicious MCP server can:

- Exfiltrate secrets and conversation history to attacker-controlled webhooks
- Inject hidden instructions into tool descriptions to hijack agent behaviour ("tool poisoning")
- Execute arbitrary shell commands through unsanitized tool inputs
- Pull in typosquatted dependencies that install malware at install time

nyuwaymcpscanner gives you a repeatable, CI-friendly audit layer that catches these threats statically - no runtime required.

---

## Quick start

```bash
# Install
pip install nyuwaymcpscanner

# Scan a local server directory
nyuwaymcpscanner scan ./my-mcp-server

# Scan a single file directly
nyuwaymcpscanner scan ./mcp.json
nyuwaymcpscanner scan ./config.py

# Scan a package from npm or PyPI
nyuwaymcpscanner scan npm:@modelcontextprotocol/server-github
nyuwaymcpscanner scan pypi:weather-mcp

# Scan a GitHub repository
nyuwaymcpscanner scan github:owner/repo

# Scan a claude_desktop_config.json (all declared servers at once)
nyuwaymcpscanner scan ~/Library/Application\ Support/Claude/claude_desktop_config.json --config

# CI: fail the build when HIGH or above findings are found
nyuwaymcpscanner scan ./server --offline --static-only --fail-on high
```

---

## Sample output

```
 Baseline Scan - ./my-mcp-server
+--------------+-------------------------------------------------------------------+
| Risk Score   | 85 / 100                                                          |
| Verdict      | HIGH                                                              |
| Files scanned| 12                                                                |
+--------------+-------------------------------------------------------------------+

Findings
+----+--------------------+----------+---------------------------------------------+
| #  | Type               | Severity | Evidence                                    |
+----+--------------------+----------+---------------------------------------------+
| 1  | hardcoded_secret   | HIGH     | AWS_ACCESS_KEY_ID = "AKIA..."  config.py:1  |
| 2  | yara_match         | HIGH     | os.system call in tool logic   tool.py:4    |
+----+--------------------+----------+---------------------------------------------+
```

---

## Scan modes

### Baseline scan (default, fully offline)

The Baseline scan runs entirely on your machine. It makes **zero external network calls** - no telemetry, no cloud APIs, no data leaves your environment.

Three static layers run in sequence:

| Layer | What it catches |
|---|---|
| **Secrets** | Hardcoded AWS/GCP/Azure keys, OpenAI/Anthropic tokens, private keys, JWT secrets, generic passwords |
| **YARA rules** | Tool-poisoning instructions, external logging endpoints, shell execution, plaintext passwords, internal IP leakage |
| **Supply chain** | Typosquatted dependency names (edit-distance 1 from popular packages); CVE lookup via OSV.dev (skipped in `--offline` mode) |
| **VirusTotal** | SHA256 hash lookup for binary files against 70+ AV engines - no file upload, hash only (skipped when `VIRUSTOTAL_API_KEY` is not set) |

A fifth **local LLM** layer runs semantic analysis of MCP tool manifests using a locally-hosted Ollama model (skipped with `--static-only`).

```bash
# Static only - no Ollama required, suitable for CI without GPU
nyuwaymcpscanner scan ./server --static-only --offline

# With LLM analysis - requires Ollama running locally
nyuwaymcpscanner scan ./server --offline
```

### Running with LLM analysis

One-time setup to install Ollama and pull the model (~5GB):

```bash
nyuwaymcpscanner setup
```

Then scan without `--static-only`:

```bash
# Full Baseline: static + local LLM, fully air-gapped
nyuwaymcpscanner scan ./my-mcp-server --offline

# Single manifest file with LLM analysis
nyuwaymcpscanner scan ./mcp.json --offline
```

The LLM layer only activates when an `mcp.json` manifest is present. If Ollama is not running, the scan falls back to static-only with a warning - it never fails hard.

**Requirements:** ~8GB RAM, Ollama installed via `nyuwaymcpscanner setup`.

### VirusTotal malware detection

nyuwaymcpscanner can hash-check binary files (wheels, archives, executables, DLLs) against VirusTotal's 70+ AV engines. Only the SHA256 hash is sent - no file content ever leaves your machine.

**Setup (free, takes 2 minutes):**

1. Create a free account at [virustotal.com](https://www.virustotal.com)
2. Go to your profile and copy your API key
3. Set it once in your environment:

```bash
export VIRUSTOTAL_API_KEY=your_key_here
```

Then scan normally - VirusTotal runs automatically on any binary files found:

```bash
nyuwaymcpscanner scan npm:some-package
nyuwaymcpscanner scan github:owner/repo
nyuwaymcpscanner scan ./my-mcp-server
```

If binaries are found but no key is set, the scanner prints a reminder:

```
Note: 3 binary files not checked for malware - set VIRUSTOTAL_API_KEY for hash-based detection (free at virustotal.com).
```

You can also pass the key inline for one-off scans:

```bash
nyuwaymcpscanner scan ./server --vt-key YOUR_KEY
```

VirusTotal is skipped automatically when `--offline` is set. Free tier allows 500 lookups per day.

---

### Scanning a single file

When the target is a single file, findings are scoped to that file only - sibling files in the same directory are ignored:

```bash
# Scan a single mcp.json
nyuwaymcpscanner scan ./mcp.json --offline --static-only

# Scan a single source file
nyuwaymcpscanner scan ./server.py --offline --static-only

# Scan a requirements file (CVE lookup runs against its dependencies)
nyuwaymcpscanner scan ./requirements.txt --static-only
```

| Target type | Recommended command |
|---|---|
| Single `mcp.json` or `.py` | `scan ./file --offline --static-only` |
| Full server directory | `scan ./my-server --offline` |
| `requirements.txt` / `package.json` | `scan ./requirements.txt --static-only` |
| Claude Desktop config | `scan ./claude_desktop_config.json --config --offline --static-only` |

### Deep Scan (invite only)

Deep Scan is a Nyuway-hosted analysis tier that performs frontier-model semantic analysis, cross-tool exfiltration detection, and behavioral mismatch analysis. It is currently available by invite.

```bash
nyuwaymcpscanner scan ./server --deep --token YOUR_TOKEN
```

Join the waitlist: **https://forms.gle/bH8nToK9Zh7ey5F46**

---

## CLI reference

```
nyuwaymcpscanner scan TARGET [OPTIONS]

TARGET
  ./path/to/server     Local directory
  ./path/to/file.py    Single file (findings scoped to that file only)
  ./mcp.json           Single manifest file
  github:owner/repo    GitHub repository (optionally @ref)
  npm:package@version  npm package
  pypi:package@version PyPI package
  /path/to/config.json MCP host config file (requires --config)
  /path/to/list.txt    Newline-delimited list of targets (requires --batch)

Options
  --offline        Disable all outbound network calls (OSV.dev CVE lookup skipped)
  --static-only    Skip local LLM layer; run secrets + YARA + supply chain only
  --output FORMAT  Output format: summary (default), json, sarif
  --fail-on LEVEL  Exit non-zero when verdict >= LEVEL (low/medium/high/critical)
  --config         Treat TARGET as an MCP host config file; scan all declared servers
  --batch          Treat TARGET as a newline-delimited list of server paths
  --deep           Run Deep Scan (invite only; requires --token)
  --token TOKEN    Deep Scan invite token
  --model MODEL    Ollama model for local LLM layer (default: llama3)
  --vt-key KEY     VirusTotal API key for binary malware detection (or set VIRUSTOTAL_API_KEY)

nyuwaymcpscanner setup
  Download and verify the local Ollama model for LLM-assisted scanning.
```

---

## Output formats

### Summary (default)
Rich terminal table with colour-coded severity, suitable for interactive use.

### JSON (`--output json`)
Machine-readable report. Stable schema for scripting and dashboards.

```json
{
  "tool": "nyuwaymcpscanner",
  "version": "0.1.0",
  "target": "./server",
  "scanned_at": "2025-01-15T10:30:00Z",
  "risk_score": 85,
  "verdict": "HIGH",
  "findings": [
    {
      "type": "hardcoded_secret",
      "severity": "high",
      "weight": 30,
      "file": "config.py",
      "line": 1,
      "pattern": "AWS Access Key ID",
      "evidence": "AWS_ACCESS_KEY_ID = \"AKIA...\"",
      "source": "secrets_scanner"
    }
  ]
}
```

### SARIF (`--output sarif`)
SARIF 2.1.0 format for GitHub Advanced Security, VS Code Problems panel, and any SARIF-aware CI tool.

```yaml
# .github/workflows/mcp-scan.yml
- name: Scan MCP server
  run: |
    pip install nyuwaymcpscanner
    nyuwaymcpscanner scan ./server --offline --static-only --output sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Scanning MCP host configs

Point nyuwaymcpscanner at your MCP host config to audit every server declared in it:

```bash
# Claude Desktop (macOS)
nyuwaymcpscanner scan \
  ~/Library/Application\ Support/Claude/claude_desktop_config.json \
  --config --offline

# Cursor / Windsurf / VS Code
nyuwaymcpscanner scan ~/.cursor/mcp.json --config --offline
```

Remote SSE/HTTP endpoints are reported as skipped (deep remote scanning is roadmapped for v1.1).

---

## Local LLM setup

The LLM layer uses [Ollama](https://ollama.ai) running locally. Run setup once:

```bash
# Install Ollama from https://ollama.ai, then:
nyuwaymcpscanner setup
```

This pulls the default model (`llama3`) and verifies connectivity. The LLM layer only runs when an `mcp.json` manifest is present in the scanned tree; it is silently skipped otherwise.

---

## Verdicts and scoring

| Verdict  | Score range | Meaning |
|---|---|---|
| PASS     | 0           | No findings |
| LOW      | 1-24        | Informational; review but not urgent |
| MEDIUM   | 25-49       | Should be fixed before production |
| HIGH     | 50-79       | Block deployment |
| CRITICAL | 80-100      | Immediate action required |

Each finding carries a `weight` (5-35). The final score is `max(weight_sum, severity_floor)` capped at 100.

---

## What nyuwaymcpscanner catches

| Finding type | Severity | Description |
|---|---|---|
| `hardcoded_secret` | HIGH | AWS/GCP/Azure credentials, API keys, private keys, JWT secrets |
| `yara_match` | CRITICAL-LOW | Tool-poisoning instructions, exfil endpoints, shell exec, passwords, internal IPs |
| `typosquatting_risk` | MEDIUM | Dependency name 1 edit-distance from a popular package |
| `dependency_cve` | HIGH | Known CVE in a pinned dependency (requires network; skipped with --offline) |
| `tool_poisoning` | CRITICAL | LLM-detected hidden instruction in tool description |
| `malware_detected` | CRITICAL-MEDIUM | Binary file flagged by VirusTotal AV engines (requires `VIRUSTOTAL_API_KEY`) |

---

## How nyuwaymcpscanner compares

| Capability | nyuwaymcpscanner | Other MCP scanners |
|---|:---:|:---:|
| Hardcoded secret detection (8 types) | yes | partial |
| Shell execution patterns across 10 languages | yes (50 patterns) | Python/JS only |
| Supply chain CVE lookup (OSV.dev) | yes | partial |
| Typosquatting detection | yes | - |
| VirusTotal binary malware (hash only, no upload) | yes | partial |
| Tool poisoning / exfiltration instructions | yes | yes |
| Local LLM semantic analysis (fully offline) | yes | cloud only |
| Fully air-gapped / offline mode | yes | no |
| SARIF 2.1.0 output | yes | - |
| JSON output | yes | partial |
| Batch and host config file scanning | yes | - |
| Single-file scoped scanning | yes | - |
| Test/doc-aware false positive tuning | yes | - |
| Open, auditable detection rules (YARA) | yes | no |
| CI/CD fail-on severity gate | yes | - |
| Runtime proxy / tool pinning | roadmap | yes |
| Cloud behavioral analysis | roadmap (Deep Scan) | yes |

Runtime proxy and behavioral analysis are complementary to static scanning - they operate at a different point in the deployment lifecycle. nyuwaymcpscanner is the pre-deploy static layer; runtime tools sit alongside it, not in place of it.

---

## Requirements

- Python 3.11+
- [Ollama](https://ollama.ai) (optional; only needed for LLM layer)

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

## Links

- Website: https://nyuway.ai
- Deep Scan waitlist: https://forms.gle/bH8nToK9Zh7ey5F46
- Issues: https://github.com/Nyuway-Cybersecurity/nyuwaymcpscanner/issues
