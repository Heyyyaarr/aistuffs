# Improvement Plan: Multi-Agent Threat Hunt System

Based on a thorough review of the codebase documented in [`AGENTS.md`](./AGENTS.md) and cross-referenced against the [TrustedSec Log4j Detection and Response Playbook](https://trustedsec.com/blog/log4j-playbook).

---

## 1. Critical Security Issues

### 1.1 Hardcoded Credentials in Source

**Files:** `multi_agent.py:16`, `docker-compose.yml:9`

```python
"SPLUNK_PASS": os.environ.get("SPLUNK_PASS", "Cybercapstone123!"),
```

The default password is committed to the repository in both `multi_agent.py` and `docker-compose.yml`. While environment variable overrides exist, the fallback value is a live credential.

**Fix:** Remove the hardcoded default. Fail fast if `SPLUNK_PASS` is unset:

```python
"SPLUNK_PASS": os.environ.get("SPLUNK_PASS") or sys.exit("SPLUNK_PASS required"),
```

### 1.2 SSL Verification Disabled Globally

**File:** `multi_agent.py:10`, `multi_agent.py:62`/`76`

```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
...
verify=False,
```

All Splunk API calls skip certificate verification with no option to enable it.

**Fix:** Add a `SPLUNK_VERIFY_SSL` config key (default `True`). Allow users to set it to `False` for self-signed certs, but never default to insecure.

### 1.3 Splunk Password in docker-compose.yml

**File:** `docker-compose.yml:9`

The Splunk service password is exposed in the compose file. This is fine for local testing but should be called out for production use + documented alternative (`.env` file).

**Fix:** Add a note in AGENTS.md about using `.env` files for production. Optionally support `SPLUNK_PASSWORD_FILE` for Docker secrets.

---

## 2. Architecture & Design Improvements

### 2.1 Pipeline Should Be Configurable, Not Hardcoded

**File:** `multi_agent.py:297-299`

```python
splunk_results = run_agent_1_splunk()
pcap_results = run_agent_2_pcap()
final_report = run_agent_3_synthesis(splunk_results, pcap_results)
```

The pipeline is hardcoded as: Splunk → PCAP → Synthesis. There's no way to:
- Skip an agent
- Reorder agents
- Run agents in parallel
- Add new agents without modifying `main()`

**Fix:** Implement an agent registry pattern. Each agent registers itself with a name, dependencies, and a run function. `main()` reads a `PIPELINE` config to determine execution order.

### 2.2 No Agent-Level Error Isolation

If Agent 1 (Splunk) crashes, the entire pipeline fails. There's no graceful degradation — a Splunk connection failure means no PCAP analysis either, even though they're independent.

**Fix:** Wrap each agent call in a try/except with a fallback result string (e.g., `"AGENT_ERROR: Splunk unavailable — skipping SIEM analysis."`). Log the error but continue the pipeline.

### 2.3 Splunk and PCAP Agents Should Run in Parallel

**File:** `multi_agent.py:297-298`

The Splunk and PCAP agents have no data dependency on each other (both feed into Agent 3 independently), yet they run sequentially.

**Fix:** Use `concurrent.futures.ThreadPoolExecutor` to run Agents 1 and 2 in parallel. This halves wall-clock runtime.

### 2.4 Missing Agent Abstraction / Plugin Architecture

**Documented in:** `AGENTS.md:217-239` (Adding a New Agent)

The documented pattern for adding agents requires manual wiring in `main()` — editing the orchestration file for every new agent.

**Fix:** Create an `AgentBase` abstract class or protocol that each agent implements. Auto-discover agents from the `agents/` directory. Move orchestration logic out of `multi_agent.py` into a config-driven pipeline runner.

---

## 3. Functional Gaps (vs. TrustedSec Playbook)

The [TrustedSec Log4j Playbook](https://trustedsec.com/blog/log4j-playbook) covers four phases. The current tool only addresses **one**:

| Playbook Phase | Covered? | What's Missing |
|---|---|---|
| **Vulnerable Software Detection** (Section 2) | ✅ | Syft SBOM + Grype CVE scanning via Agent 4. Scans for Log4j and all other known CVEs on the target. |
| **Prevention & Mitigation** (Section 3) | ❌ | No KB/model for recommending specific mitigations (JNDI removal, `formatMsgNoLookups`, network isolation). |
| **Exploitation Detection** (Section 4) | ⚠️ Partial | Log analysis ✅ (Agent 1). Network analysis ✅ (Agent 2). **Endpoint analysis** ❌ — no EDR/process/ file-system telemetry. Obfuscation handling ❌ — playbook specifically warns about `${lower:}`, `${upper:}`, `${::-}` obfuscation; the SPL fallback and PCAP parser don't handle these. |
| **Post-Exploitation** (Section 4.2-4.3) | ⚠️ Partial | Network callback detection is basic. No DNS query analysis. No curl/wget process detection. No cryptominer indicators. |

### 3.1 Specific Functional Gaps

**a) No JNDI Obfuscation Handling**

The TrustedSec playbook (Section 4.1) provides specific regex patterns to detect obfuscated JNDI strings (e.g., `${${lower:j}ndi}`). The tool's PCAP parser at `multi_agent.py:148` checks for literal `"jndi"`, `${`, and `"ldap"`, which misses:

- `${${lower:j}ndi:${lower:l}dap://...}`
- `${${upper:j}ndi:ldap://...}`
- `${${::-j}${::-n}di:ldap://...}`

**Fix:** Add a normalization step that recursively resolves nested `${lower:...}`, `${upper:...}`, and `${::-...}` patterns before checking for JNDI indicators. Consider integrating with Neo23x0's log4shell-detector.

**b) No IOC Feed Integration**

The playbook (Section 4.3) references known scanning IPs and callback URLs:
- `https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217`
- `https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8`
- `https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/blob/master/log4j_ip.intel`

The tool has no mechanism to enrich findings against known threat intelligence feeds.

**Fix:** Add an optional enrichment step that cross-references extracted IPs/domains against downloadable IOC lists.

**c) No Endpoint Analysis**

The playbook (Section 4.2) recommends checking for:
- Suspicious execution of `curl`, `wget`, `powershell`
- Unexpected process creation
- CPU/memory spikes (cryptominers)
- EDR alerts

The tool has no endpoint visibility. This is a known scope limitation, but it should be documented.

**Fix:** Document as a known gap in AGENTS.md. Consider adding an agent for endpoint log analysis (Sysmon, osquery, EDR API).

**f) No Vulnerability Scanning (Now Implemented)**

**Status:** ✅ Implemented as Agent 4

**Files:** `agents/agent4_vuln_scan.md`, `multi_agent.py`

Agent 4 uses Syft (SBOM generation) and Grype (vulnerability scanning) to identify known CVEs in the target system. It runs in parallel with Agents 1 and 2, and its findings are passed to Agent 3 for inclusion in the final report.

Key capabilities:
- Discovers all installed packages via Syft
- Scans for known vulnerabilities via Grype
- Severity breakdown (Critical, High, Medium, Low, Negligible)
- Log4j-specific CVE detection (CVE-2021-44228, CVE-2021-45046, etc.)
- Top 10 critical/high vulnerabilities reported with fix versions

Configure with `SCAN_TARGET` environment variable (directory path or container image name).

**d) DNS Analysis (Now Implemented)**

**Status:** ✅ Implemented

The PCAP tool now extracts DNS queries via TShark JSON output (`dns.qry.name`, `dns.flags.response`). External DNS queries are surfaced in the PCAP analysis results under a "DNS Queries" section. Configurable display filter and max packet limits prevent resource exhaustion on large captures.

**e) Report Template Has Placeholder Values**

**File:** `output/incident_report_20260724_231226.md:93-96`

```markdown
Prepared by:
[Your Name]
Lead Incident Response Agent
TrustedSec

Date: [Current Date]
```

The LLM output still contains template placeholders because the Agent 3 prompt doesn't provide the investigator name or current date.

**Fix:** Add these to the Agent 3 user content template or pass them as variables.

---

## 4. Code Quality & Robustness

### 4.1 Fragile TShark Field Parsing

**File:** `multi_agent.py:131-145`

```python
parts = line.split("\t")
if len(parts) < 5:
    continue

frame_num, frame_time = parts[0], parts[1]
src = parts[2] if parts[2] else "N/A"
```

The parser assumes tab-separated fields with specific positional indices. TShark's field output can vary:
- Missing fields produce empty strings, shifting alignment
- Fields with embedded tabs break the split
- No field quoting/escaping

**Fix:** Use `-E separator=|` or `-E header=y` with `-E quote=d` for more robust parsing. Alternatively, output JSON with `-T json` and parse with `json.loads()`.

### 4.2 Potential IndexError in Time Sorting

**File:** `multi_agent.py:85-86`

```python
timestamps = sorted([item.get("_time") for item in data if item.get("_time")])
time_summary = f"TIME RANGE ... Earliest = {timestamps[0]} ..."
```

If all items lack `_time`, `timestamps` is an empty list and `timestamps[0]` raises `IndexError`.

**Fix:** Guard with `if timestamps:` before accessing.

### 4.3 Limited Result Truncation

**File:** `multi_agent.py:88`

```python
raw_logs = [item.get("_raw", str(item)) for item in data[:25]]
```

Hardcoded limit of 25 log entries. For large incident response investigations, this could miss critical evidence.

**Fix:** Make this configurable (`MAX_LOG_EVENTS`). Use a smarter approach: prioritize logs with JNDI/LDAP matches first, then fill remaining slots with surrounding context.

### 4.4 No Retry Logic for Network Calls

Both the Splunk API call (`multi_agent.py:58`) and the Ollama API call (`multi_agent.py:218`) have no retry logic. Transient network failures cause pipeline crashes.

**Fix:** Wrap external HTTP calls with `tenacity` or a simple exponential-backoff retry decorator (3 retries, 2s base delay).

### 4.5 PCAP Analysis Has No Pagination / Streaming

**File:** `multi_agent.py:102-116`

TShark loads all fields for all packets into memory at once. For large PCAP files, this can OOM the container or hit the 30-second timeout.

**Fix:** Add `-Y` (display filter) early to reduce packet count. Use TShark's `-l` (line-buffered) mode with iterative reading. Add a packet limit (`PCAP_MAX_PACKETS`).

### 4.6 Fallback SPL Query Is Hardcoded

**File:** `multi_agent.py:70`

```python
fallback_spl = 'search index=* "jndi" OR "${" OR "ldap" OR "rmi" ...'
```

This logic is in Python rather than in the agent prompt where the LLM could craft a smarter fallback. The hardcoded fallback bypasses the LLM entirely.

**Fix:** Move fallback strategy to the agent prompt. Let the LLM decide on a second tool call when the first returns 0 results. Or at minimum, move the fallback query to a config variable.

### 4.7 No Logging Framework

**File:** `multi_agent.py` — uses `print()` throughout

No structured logging, log levels, or output to files. Debugging pipeline issues requires reading stdout.

**Fix:** Replace `print()` with the `logging` module. Log to both stdout and a rotating file in `output/`. Include timestamps and log levels.

---

## 5. Testing & Validation

### 5.1 No Tests

There are zero tests in the repository — no unit tests, integration tests, or end-to-end tests.

**Required test coverage:**
- **Unit:** `tool_query_splunk()` response parsing, `tool_analyze_pcap()` output parsing, `load_section()` regex extraction
- **Integration:** Splunk API mock with known-good/known-bad responses, TShark mock with sample PCAP data
- **E2E:** Full pipeline with mock agents, verifying output structure

**Fix:** Add `tests/` directory with `pytest`-based tests. Add `pytest` and `responses` (for HTTP mocking) to `requirements.txt`. Add CI config (GitHub Actions) to run tests on push.

### 5.2 No PCAP Test Fixtures

**File:** `pcap/.gitkeep` — directory is empty

There are no sample PCAP files for testing. Anyone wanting to test the PCAP analysis must find their own captures.

**Fix:** Create a small synthetic PCAP file with known JNDI exploit payloads using `scapy`. Check it into `tests/fixtures/`. Generate known-good output to compare against.

---

## 6. Observability & Operations

### 6.1 No Structured Report Output Format

**File:** `multi_agent.py:301-311`

The final report is saved as Markdown. There's no machine-readable output (JSON) for downstream tooling or dashboards.

**Fix:** In addition to the Markdown report, output a JSON version with structured fields: `timeline`, `indicators` (IPs, domains, hashes), `severity`, `affected_hosts`. This enables integration with SOAR platforms.

### 6.2 No Pipeline Telemetry

There's no tracking of:
- Per-agent duration
- Token usage per LLM call
- Number of Splunk results returned
- PCAP packets processed vs. flagged
- Error rates

**Fix:** Add a `PipelineTelemetry` dataclass that accumulates metrics. Print summary at end of run. Optionally emit to a JSON metrics file.

### 6.3 LLM Response Unstructured / Unreliable

**File:** `multi_agent.py:218-234`, `254-258`, `277-283`

The LLM responses are consumed as free text. There's no validation that:
- Agent 1 actually called the Splunk tool
- Agent 3 produced a report matching the required structure
- The output contains required sections (Timeline, Analysis, Recommendations)

**Fix:** For Agent 3, use structured output (constrained JSON schema) via Ollama's JSON mode. Validate the report structure before saving. For Agent 1, verify that tool_calls were made and provide a default response if not.

---

## 7. Documentation & Developer Experience

### 7.1 Missing `pyproject.toml` or `setup.py`

**File:** `requirements.txt` (only 3 dependencies)

No package configuration. Can't install as a package (`pip install -e .`). No versioning, entry points, or dependency pinning.

**Fix:** Add `pyproject.toml` with `[project]` metadata, `[tool.setuptools]` config, and a `console_scripts` entry point. Pin dependency versions.

### 7.2 No Pre-commit Hooks

No linting, formatting, or type-checking configured. AGENTS.md documents commit message conventions but provides no automation to enforce them.

**Fix:** Add `.pre-commit-config.yaml` with `ruff`, `mypy`, `trailing-whitespace`, and `check-yaml`. Add a commit-msg hook to enforce conventional commit format.

### 7.3 AGENTS.md Gaps

**File:** `AGENTS.md`

**Strengths:** Excellent documentation — architecture diagram, file descriptions, pipeline flow, troubleshooting table.

**Missing:**
- No "Known Limitations" section (no endpoint analysis, no IOC feeds, no obfuscation detection)
- No development setup guide (virtual environment, Ollama setup, sample data)
- No "How to Test" section
- No reference to the TrustedSec playbook as the basis for Agent 3

### 7.4 No CHANGELOG

No changelog or release notes. Hard to track what changed between versions.

---

## 8. DevOps & Deployment

### 8.1 Docker Compose Lacks Health Check for hunt Service

**File:** `docker-compose.yml:18-30`

The `hunt` service depends on `splunk` being healthy, but there's no health check defined for `hunt` itself. It exits immediately after running the pipeline, so `docker logs` must be used proactively to see results.

**Fix:** Consider adding a `healthcheck` to keep the container alive briefly for log inspection, or use a `restart: "no"` policy with clear exit message.

### 8.2 Docker Build Has No .dockerignore

**File:** `Dockerfile` (no `.dockerignore` present)

The entire project directory is sent as build context. The `output/` and `.git/` directories are included unnecessarily.

**Fix:** Add `.dockerignore` excluding `output/`, `.git/`, `*.md`, `__pycache__/`.

### 8.3 No CI/CD Pipeline

No GitHub Actions workflow for:
- Running tests on PR
- Linting/type-checking
- Building and publishing Docker image
- Validating incident report output format

---

## 9. Prioritized Roadmap

| Priority | Area | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| **P0** | Remove hardcoded credentials (1.1) | 30 min | Security — prevents credential leak | ✅ |
| **P0** | Enable SSL verification by default (1.2) | 15 min | Security — prevents MITM | ✅ |
| **P0** | Fix empty timestamps IndexError (4.2) | 5 min | Prevents runtime crash | ✅ |
| **P1** | Add retry logic for network calls (4.4) | 1 hr | Reliability in production | ✅ |
| **P1** | Add JNDI obfuscation handling (3.1a) | 2 hr | Core detection gap | ✅ |
| **P1** | Add test suite (5.1) | 4 hr | Enables safe refactoring | ✅ |
| **P1** | Replace `print()` with logging (4.7) | 1 hr | Observability | ✅ |
| **P2** | Parallelize Splunk + PCAP agents (2.3) | 1 hr | Performance (2x speedup) | ✅ |
| **P2** | Robust TShark parsing (4.1) | 2 hr | Prevents false negatives | ✅ |
| **P2** | Add IOC feed enrichment (3.1b) | 3 hr | Threat intel context | ✅ |
| **P2** | Add JSON report output (6.1) | 2 hr | Machine readability | ✅ |
| **P2** | Add vulnerability scanning agent (3.1c) | 4 hr | CVE detection | ✅ |
| **P2** | DNS analysis in PCAP tool (3.1d) | 2 hr | Broader detection | ✅ |
| **P3** | Agent plugin architecture (2.4) | 6 hr | Extensibility | ❌ |
| **P3** | Endpoint analysis agent (Sysmon/EDR) | 8 hr | Complete coverage | ❌ |
| **P3** | CI/CD pipeline (8.3) | 3 hr | Developer workflow | ❌ |
| **P3** | Pre-commit hooks (7.2) | 1 hr | Code quality automation | ✅ |
| **P3** | .dockerignore (8.2) | 15 min | Build context hygiene | ✅ |

---

## 10. TrustedSec Playbook Alignment Summary

| Playbook Requirement | Status | Notes |
|---|---|---|---|
| Search logs for `jndi:ldap`, `jndi:rmi`, `jndi:dns` | ✅ | Agent 1 — basic coverage |
| Handle obfuscated patterns (`${lower:}`, `${::-}`) | ✅ | `normalize_jndi_payload()` in `multi_agent.py` |
| Search compressed logs | ✅ | SPL `index=*` covers this in Splunk |
| Endpoint analysis (process, file, EDR) | ❌ | Future agent needed |
| Network callback detection | ✅ | Agent 2 — HTTP + DNS + LDAP callback ports |
| DNS query analysis | ✅ | TShark JSON extraction with `dns.qry.name` |
| IOC feed cross-referencing | ✅ | `enrich_iocs()` with gist + Zeek feeds |
| Known scanning IP lists | ✅ | IOC feed enrichment covers this |
| Vulnerability scanning integration | ✅ | Agent 4 — Syft SBOM + Grype CVE scan |
| Mitigation recommendations | ✅ | Agent 3 LLM with playbook-grounded prompts |

---

*Prepared from review of `AGENTS.md`, `multi_agent.py`, `Dockerfile`, `docker-compose.yml`, `agents/*.md`, and `output/*.md`. Aligned with [TrustedSec Log4j Detection and Response Playbook](https://trustedsec.com/blog/log4j-playbook) (Dec 13, 2021).*