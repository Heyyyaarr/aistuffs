# Multi-Agent Threat Hunt System

## Architecture

Three-agent pipeline for Log4j/JNDI threat hunting, orchestrated by `multi_agent.py`:

```
Agent 1 (Splunk SIEM) ──┐
                         ├── Agent 3 (IR Synthesis) ── Final Report
Agent 2 (PCAP Analyst) ──┘
```

| Agent | Role | Tool | Runtime Dependency |
|-------|------|------|--------------------|
| 1 | SIEM & Log Collector | `query_splunk` — SPL queries against Splunk via REST API | Splunk container (port 8089) |
| 2 | Network & PCAP Analyst | `tool_analyze_pcap` — TShark dissection of PCAP files | TShark on PATH, PCAP files on disk |
| 3 | Lead IR Reporter | Synthesizes findings into structured report | No external tools (pure LLM) |

All agents communicate through Ollama (`qwen2.5:14b`) for LLM reasoning.

---

## Project Map

```
.
├── AGENTS.md                    # This file — project docs, git standards, references
├── .gitignore                   # Ignores output/ and other build artifacts
├── codetools/                    # Agent workflow references & task tracking
│   ├── improvements.md           #   Improvement plan with rationale for each finding
│   ├── task.md                   #   Task tracker mapping to improvements.md
│   └── git_workflow.md           #   Git workflow reference (branch, commit, PR)
├── multi_agent.py               # Pipeline orchestrator + tool implementations
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Container build for hunt service
├── docker-compose.yml           # Splunk + hunt services
├── agents/                      # AI prompt files loaded at runtime
│   ├── agent1_siem.md           #   Agent 1 system prompt, tool desc, user message
│   ├── agent2_pcap.md           #   Agent 2 analysis prompt template
│   └── agent3_synthesis.md      #   Agent 3 system prompt + user content template
├── output/                      # Generated incident reports (gitignored)
│   └── incident_report_*.md     #   Timestamped report output files
└── pcap/                        # PCAP files mounted into containers
    └── *.pcap                   #   Network capture files to analyze
```

---

## File Descriptions

### `multi_agent.py`
- **Config**: All settings in the `CONFIG` dict (top of file), overridable via environment variables
- **Tools**: `tool_query_splunk()` (Splunk REST API) and `tool_analyze_pcap()` (TShark wrapper)
- **Agents**: Three functions (`run_agent_1_splunk`, `run_agent_2_pcap`, `run_agent_3_synthesis`) that load prompts from markdown files and call Ollama
- **Orchestration**: `main()` runs the pipeline sequentially (Splunk → PCAP → Synthesis), prints results, and writes to `output/`

### `agents/agent1_siem.md`
| Section | Content |
|---------|---------|
| `system_prompt` | SIEM Analyst role definition — instructs the LLM to call `query_splunk` for Log4j/JNDI/LDAP indicators |
| `tool_query_splunk` | Description of the Splunk tool exposed to the LLM for function-calling |
| `user_message` | Initial user prompt sent to the LLM to trigger the Splunk query |

### `agents/agent2_pcap.md`
| Section | Content |
|---------|---------|
| `analysis_prompt` | Prompt template using `{{PCAP_DATA}}` placeholder — filled with tool output at runtime |

### `agents/agent3_synthesis.md`
| Section | Content |
|---------|---------|
| `system_prompt` | Lead IR Reporter role — TrustedSec Log4j Playbook instructions for report structure |
| `user_content_template` | Template using `{{SPLUNK_FINDINGS}}` and `{{PCAP_FINDINGS}}` placeholders |

### `Dockerfile`
- Base: `python:3.11-slim` for arm64 compatibility (Apple Silicon)
- Installs `tshark` for PCAP analysis
- Copies `multi_agent.py` and `agents/` directory
- Sets `PYTHONUNBUFFERED=1` for real-time log output

### `docker-compose.yml`
Two services:
- **splunk**: `splunk/splunk:latest` with persistent named volumes (`splunk-var`, `splunk-etc`), accepts SPLGT license, exposes ports 8000 (UI) and 8089 (API)
- **hunt**: Built from `Dockerfile`, runs the pipeline, depends on Splunk health, mounts `./pcap` and `./output`

### `output/`
Contains timestamped incident reports (`incident_report_YYYYMMDD_HHMMSS.md`). Each run appends a new file. This directory is gitignored.

### `codetools/improvements.md`
Comprehensive codebase review cross-referenced against the [TrustedSec Log4j Playbook](https://trustedsec.com/blog/log4j-playbook). Covers security, architecture, functional gaps, code quality, testing, observability, documentation, and DevOps improvements with a prioritized roadmap.

### `codetools/task.md`
Checklist tracking all improvement items from `improvements.md`. Organized by priority (P0-P3) with file:line locations for each change. Mark items `[x]` as completed.

---

## Pipeline Flow

1. **Agent 1 (Splunk SIEM)**
   - Loads `agent1_siem.md` sections (`system_prompt`, `user_message`, `tool_query_splunk`)
   - Calls Ollama with function-calling enabled
   - LLM decides to call `query_splunk()` with an SPL query
   - Tool executes the query against Splunk REST API (all indexes, all time)
   - If 0 results, automatically runs a fallback wildcard search for JNDI/LDAP/RMI
   - Returns raw log events back to the LLM for interpretation

2. **Agent 2 (PCAP Analyst)**
   - Loads `agent2_pcap.md` (`analysis_prompt`)
   - Runs `tool_analyze_pcap()` on each configured PCAP file via TShark
   - Extracts: frame numbers, timestamps, IPs, protocols, HTTP methods/URIs, User-Agents, TCP payloads
   - Flags frames containing JNDI strings (`jndi`, `${`, `ldap`) or outbound LDAP connections (ports 389, 636, 1099, 1389)
   - Injects PCAP data into `{{PCAP_DATA}}` placeholder and sends to LLM

3. **Agent 3 (IR Synthesis)**
   - Loads `agent3_synthesis.md` (`system_prompt`, `user_content_template`)
   - Injects Splunk findings into `{{SPLUNK_FINDINGS}}` and PCAP findings into `{{PCAP_FINDINGS}}`
   - LLM produces a structured Playbook Incident Report with:
     - Timeline (earliest to latest)
     - IP categorization (internal RFC1918 vs external attacker infrastructure)
     - Analysis and recommendations
     - TrustedSec Log4j Playbook format

4. **Output**
   - Report printed to stdout
   - Report saved to `output/incident_report_TIMESTAMP.md`

---

## Running

### Locally

```bash
pip install -r requirements.txt
python multi_agent.py
```

Requires:
- [Ollama](https://ollama.ai) running locally with `qwen2.5:14b` pulled
- TShark on `PATH` (install via `brew install wireshark` or `apt install tshark`)
- Accessible Splunk instance (or set `SPLUNK_HOST` to skip)

### Docker

```bash
docker compose build hunt
docker compose up -d hunt
docker logs -f multi-agent-hunt
```

Or run both Splunk and the hunt together:

```bash
docker compose up -d
```

The `hunt` service auto-waits for Splunk to be healthy before starting.

---

## Configuration

All settings are in the `CONFIG` dict in `multi_agent.py`. Each key can be overridden by setting the corresponding environment variable:

| Config Key | Env Variable | Default | Description |
|------------|-------------|---------|-------------|
| `SPLUNK_HOST` | `SPLUNK_HOST` | `https://localhost:8089` | Splunk REST API URL |
| `SPLUNK_USER` | `SPLUNK_USER` | `admin` | Splunk username |
| `SPLUNK_PASS` | `SPLUNK_PASS` | `Cybercapstone123!` | Splunk password |
| `PCAP_DIRECTORY` | `PCAP_DIRECTORY` | `/Users/josephstafford/Downloads/CodePathProject` | Directory containing PCAP files |
| `REQUIRED_PCAPS` | `REQUIRED_PCAPS` | `pcapA.pcap,pcapB.pcap` | Comma-separated list of PCAP filenames |
| `OLLAMA_HOST` | `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `LLM_MODEL` | `LLM_MODEL` | `qwen2.5:14b` | Ollama model name |

In Docker the following overrides are set automatically via `docker-compose.yml`:
- `SPLUNK_HOST=https://splunk:8089` (reaches the Splunk container by service name)
- `OLLAMA_HOST=http://host.docker.internal:11434` (reaches host Ollama from container)
- `PCAP_DIRECTORY=/workspace/pcap` (matches the mounted volume)

---

## Git Workflow Standards

### Branch Naming
- Feature branches: `feature/<short-description>` (e.g., `feature/agent-prompt-refactor`)
- Bug fixes: `fix/<short-description>` (e.g., `fix/pcap-timeout-handling`)
- Infrastructure: `chore/<short-description>` (e.g., `chore/docker-compose-setup`)
- Use kebab-case for descriptions

### Commit Messages
Format: `<type>: <imperative description>`

Types:
- `feat` — New feature or capability
- `fix` — Bug fix
- `docs` — Documentation changes (AGENTS.md, README, etc.)
- `refactor` — Code restructuring without functional change
- `chore` — Build, CI, or tooling changes

Examples:
```
feat: extract agent prompts to markdown files
docs: add git workflow standards to AGENTS.md
fix: handle TShark timeout gracefully
chore: add docker-compose with Splunk and hunt services
```

Rules:
- Never push directly to `main` — all changes must go through a PR
- First line ≤ 72 characters
- Use imperative mood ("add" not "added" or "adds")
- Reference issue numbers when applicable

### Pull Request Process
1. Create a branch from `main` following the naming convention
2. Make changes and commit following the commit message format
3. Push the branch: `git push -u origin <branch-name>`
4. Open a PR against `main`
5. PR title should be descriptive, matching the branch scope
6. PR description should include:
   - What changed and why
   - How to test (e.g., `docker compose up -d`)
   - Any configuration changes needed
   - Screenshots or logs showing the change works

---

## Adding a New Agent

1. Create `agents/agentN_name.md` with sections for prompts (use `## section_name` headers)
2. Call `load_section()` in `multi_agent.py` to load prompts at runtime
3. Write the agent function (follow pattern of existing agents)
4. Wire it into the `main()` pipeline
5. Update this AGENTS.md with the new agent details

Example skeleton:

```python
def run_agent_4_<name>() -> str:
    print("\n=== [AGENT 4: NAME] ===")
    prompt = load_section(
        os.path.join(AGENTS_DIR, "agent4_name.md"), "my_prompt"
    )
    prompt = prompt.replace("{{PLACEHOLDER}}", dynamic_data)
    response = ollama.chat(
        model=CONFIG["LLM_MODEL"],
        messages=[{"role": "user", "content": prompt}],
    )
    return response["message"]["content"]
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ConnectionError: Failed to connect to Ollama` | Ollama not running | Start Ollama: `ollama serve` or launch Ollama app |
| `FileNotFoundError: agents/agent1_siem.md` | Docker COPY flattened directory | Verify `COPY agents/ agents/` in Dockerfile (not `COPY agents/ ./`) |
| `SPLUNK_WARNING: 0 events found` | Splunk has no matching data | Check Splunk is ingesting data; verify credentials and index names |
| `PCAP_ERROR: File not found` | PCAP files missing from configured directory | Place `.pcap` files in `pcap/` or update `PCAP_DIRECTORY` |
| Container exits immediately | Python error or Ollama unreachable | Run `docker logs multi-agent-hunt` and check for stack trace |
| Splunk container keeps restarting | License not accepted | Verify `SPLUNK_GENERAL_TERMS` and `SPLUNK_START_ARGS` in `docker-compose.yml` |
