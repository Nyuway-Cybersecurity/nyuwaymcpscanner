# Changelog

All notable changes to nyuwaymcpscanner are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.2.0] - 2026-05-24

### Added
- VirusTotal binary malware detection: SHA256 hash-only lookup against 70+ AV engines; no file content uploaded. Enabled via `VIRUSTOTAL_API_KEY` env var or `--vt-key` flag. Skipped automatically with `--offline`.
- Hint message when binaries are found but no VT key is set, with instructions to enable detection.
- Single-file scan support: `nyuwaymcpscanner scan ./mcp.json` or any individual source file; findings are scoped to that file only, sibling files are excluded.
- Multi-language shell execution detection: extended `Suspicious_Shell_Execution_In_Tool` YARA rule to cover 10 languages with 50 patterns - Python, JavaScript/TypeScript, Go, Java, Kotlin, Rust, Ruby, C#, and PHP.
- New Python patterns: `os.popen`, `os.execv*`, `pty.spawn`, `subprocess.getoutput`, `subprocess.getstatusoutput`.
- New JS/TS patterns: `child_process.spawn`, `spawnSync`, `execSync`, `execFile`, `new Function(`.
- New Go patterns: `syscall.Exec`, `syscall.ForkExec`.
- New Java patterns: `ScriptEngineManager` (Nashorn/JS engine eval equivalent).
- New Rust patterns: `std::process::Command`, `nix::unistd::execv`.
- New Ruby patterns: `Open3.popen3`, `Open3.capture3`, `PTY.spawn`, `%x{...}`, `spawn(`.
- New C# patterns: `new ProcessStartInfo`, `Assembly.Load`, `CSharpCodeProvider`.
- New PHP patterns: `system`, `exec`, `eval`, backtick execution, `create_function`, `assert('...`, `preg_replace /e`.
- Competitive capability comparison table in README.
- False positive tuning: test/doc/CI-aware rule suppression; placeholder token filtering; known-safe JWT allowlist.

### Fixed
- Single-file scans no longer trigger supply chain CVE lookup against unrelated sibling `requirements.txt` files.

---

## [0.1.0] - 2025-01-15

### Added
- Baseline scan: secrets detection (8 credential patterns, 2 MiB file cap)
- Baseline scan: YARA engine with 5 MCP-specific threat rules
  - Tool-poisoning / forward-instruction detection (CRITICAL)
  - External logging endpoint detection (HIGH)
  - Shell execution in tool logic (HIGH)
  - Plaintext password assignment (HIGH)
  - Private IP / internal endpoint reference (LOW)
- Baseline scan: supply chain analysis - typosquatting detection and OSV.dev CVE lookup
- Baseline scan: local LLM layer via Ollama for semantic manifest analysis
- Source fetchers: local path, `github:owner/repo`, `npm:package`, `pypi:package`
- MCP host config parsing: Claude Desktop, Cursor, VS Code, Windsurf
- Output formats: summary (Rich terminal), JSON, SARIF 2.1.0
- CLI flags: `--offline`, `--static-only`, `--fail-on`, `--output`, `--batch`, `--config`
- `setup` command to install and verify local Ollama model
- Deep Scan stub: `--deep` without invite token hard-errors with waitlist URL
- Safe archive extraction with path traversal and zip bomb protection
- GitHub Actions CI: 9-matrix test run (Python 3.11/3.12/3.13 x Ubuntu/Windows/macOS)
- GitHub Actions release pipeline with OIDC trusted publishing to PyPI
