# Task Tracker: Multi-Agent Threat Hunt Improvements

Reference: [`improvements.md`](./improvements.md) — full improvement plan with rationale for each item.

---

## P0 — Critical (Security + Runtime Crashes)

- [x] **1.1** Remove hardcoded credentials from `multi_agent.py` and `docker-compose.yml`
      `multi_agent.py:16` `docker-compose.yml:9`
- [x] **1.2** Enable SSL verification by default; add `SPLUNK_VERIFY_SSL` config key
      `multi_agent.py:10` `multi_agent.py:62` `multi_agent.py:76`
- [x] **4.2** Guard empty timestamps list before accessing `timestamps[0]`
      `multi_agent.py:85-86`

---

## P1 — High Priority (Reliability + Core Detection)

- [x] **4.4** Add retry logic (exponential backoff) for Splunk and Ollama HTTP calls
      `multi_agent.py:58` `multi_agent.py:218`
- [x] **3.1a** Add JNDI obfuscation handling — normalize ${lower:}, ${upper:}, ${::-} patterns
      `multi_agent.py:148`
- [x] **5.1** Add test suite with pytest (unit + integration + mock Splunk/TShark)
      `tests/`
- [x] **4.7** Replace print() with logging module (stdout + rotating file)
      `multi_agent.py` (entire file)

---

## P2 — Medium Priority (Performance + Threat Intel + Output)

- [x] **2.3** Parallelize Splunk (Agent 1) and PCAP (Agent 2) with ThreadPoolExecutor
      `multi_agent.py:297-298`
- [x] **4.1** Robust TShark parsing — use JSON output mode instead of tab split
      `multi_agent.py:102-145`
- [x] **3.1b** Add IOC feed enrichment — cross-reference IPs against known threat intel lists
      `multi_agent.py` (new function)
- [x] **6.1** Add structured JSON report output alongside Markdown
      `multi_agent.py:301-311`
- [x] **4.5** Add PCAP packet limit and TShark display filter for large captures
      `multi_agent.py:102-116`
- [x] **4.3** Make MAX_LOG_EVENTS configurable; prioritize JNDI/LDAP matches
      `multi_agent.py:88`
- [x] **2.2** Add agent-level error isolation — wrap each agent in try/except
      `multi_agent.py:291-316`
- [x] **3.1e** Pass investigator name and current date to Agent 3 prompt
      `agents/agent3_synthesis.md`
- [x] **1.3** Document .env usage for production Splunk credentials
      `AGENTS.md`

---

## P3 — Future (Architecture + New Agents + DevOps)

- [x] **2.4** Create AgentBase abstract class with auto-discovery from agents/ directory
      `multi_agent.py` (refactor)
- [ ] **3.1c** Add Agent 4: Endpoint analysis (Sysmon, osquery, EDR API)
      `agents/agent4_endpoint.md`
- [x] **3.1d** Add DNS query extraction to TShark fields; flag suspicious lookups
      `multi_agent.py:102-116`
- [x] **8.3** Add CI/CD — GitHub Actions for tests, lint, Docker build
      `.github/workflows/`
- [x] **7.2** Add pre-commit hooks (ruff, mypy, conventional commits)
      `.pre-commit-config.yaml`
- [x] **8.2** Add .dockerignore (exclude output/, .git/, *.md, __pycache__)
      `.dockerignore`
- [x] **6.2** Add PipelineTelemetry dataclass — per-agent duration, token usage, error rates
      `multi_agent.py` (new class)
- [x] **6.3** Validate Agent 3 output structure before saving; use JSON mode
      `multi_agent.py:262-284`
- [x] **4.6** Move fallback SPL query from hardcoded Python into agent prompt
      `multi_agent.py:70`
- [x] **7.1** Add pyproject.toml with console_scripts entry point, pinned deps
      `pyproject.toml`
- [x] **5.2** Create synthetic PCAP test fixture with known JNDI payloads
      `tests/fixtures/`

---

*Checklist maps to sections in [`improvements.md`](./improvements.md). Mark `[x]` as items are completed.*
