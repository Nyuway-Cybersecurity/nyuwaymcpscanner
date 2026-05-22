# nyuwaymcpscanner — Developer Guidelines

## Mandatory Development Flow

Every piece of code or feature — no exceptions — must follow this sequence before being considered done:

### Step 1: Write
Implement the feature or fix.

### Step 2: Self-Review (Security + Functional)
Before moving on, review the code just written for:

**Security**
- No hardcoded secrets, keys, or credentials
- No command injection (especially in source fetchers handling user-supplied paths/URLs)
- No path traversal vulnerabilities when reading local files
- No unsafe deserialization of untrusted MCP server content
- Outbound network calls only from Deep Scan paths, never from Baseline
- Dependencies added must be checked against OSV.dev for known CVEs

**Functional**
- Does the code do exactly what the spec says, no more, no less
- Edge cases handled: empty tool list, malformed manifest, missing fields, unsupported file types
- Error messages are clear and actionable, not raw stack traces
- No silent failures — every scanner module must surface errors explicitly

### Step 3: Fix Issues
Fix everything identified in Step 2 before proceeding. Do not defer review findings.

### Step 4: Run Local Tests
```bash
python -m pytest tests/ -v
```
All tests must pass. If a test fails:
- Understand why before changing the test
- Fix the code, not the test, unless the test itself is wrong
- Add a new test if the bug wasn't covered

### Step 5: Fix Test Issues
Fix any failures from Step 4. Re-run until clean.

---

## Project Context

See `nyuwaymcpscanner_project.md` for full product spec, architecture, and roadmap.

**Scan modes:**
- **Baseline** (public, offline): static analysis + local Ollama LLM. No API key. No account. Air-gapped.
- **Deep Scan** (private beta, invite-only): Nyuway-hosted frontier model. `--deep --token <invite-token>`. Hard-errors with waitlist link if no valid token.

**Key invariant:** Baseline must make zero external network calls. Any outbound call in a Baseline code path is a bug.
