# Changelog

All notable changes to nyuwaymcpscanner are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Single-file scan support: `nyuwaymcpscanner scan ./mcp.json` or any individual source file; findings are scoped to that file only, sibling files are excluded

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
