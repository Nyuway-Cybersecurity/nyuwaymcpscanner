# Fixture MCP Servers

The fixture catalog is defined as a Python data structure in
`tests/test_integration_fixtures.py` and materialized into a session-scoped
temp directory by `tests/conftest.py`. There is no per-fixture subdirectory
in source control; the catalog itself is the source of truth.

The integration tests run each fixture through the full scan pipeline in
`--static-only --offline` mode and assert the expected findings. This tests
the static layer end-to-end without requiring Ollama or network access.

To inspect a fixture's expected behaviour:

1. Open `tests/test_integration_fixtures.py`.
2. Find the entry in `FIXTURE_CATALOG`.
3. Each entry has `files` (path → content), `expected_min_verdict`, and
   `expected_finding_types` for the assertions.

## Index

| Fixture | Class | Expected verdict | Notes |
|---|---|---|---|
| `clean_minimal/` | known-good | PASS | Minimal valid server, no findings |
| `clean_well_formed/` | known-good | PASS | Realistic clean Python MCP server |
| `secret_aws/` | known-bad | HIGH+ | Hardcoded AWS credentials |
| `secret_openai/` | known-bad | HIGH+ | Hardcoded OpenAI key |
| `tool_poisoning/` | known-bad | CRITICAL | YARA rule for forwarding instruction in tool description |
| `exfiltration_endpoint/` | known-bad | HIGH+ | Webhook to log.external in code |
| `shell_exec/` | known-bad | HIGH+ | os.system call in tool logic |
| `plaintext_password/` | known-bad | HIGH+ | password = "..." pattern |
| `typosquat_dep/` | known-bad | MEDIUM+ | requirements.txt with one-edit-from-popular name |
| `mixed_findings/` | known-bad | CRITICAL | Multiple finding types stacked |
| `private_endpoint/` | known-info | LOW+ | Internal IP reference (low severity) |
| `large_skip/` | edge | PASS | Oversized file plus binary noise; both must be skipped |

If you add a fixture: drop a `FIXTURE.md`, then add a corresponding entry
to `EXPECTED_FINDINGS` in `tests/test_integration_fixtures.py`.
