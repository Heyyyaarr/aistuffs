import os
import re
import json
import datetime
import requests
import subprocess
import urllib3
import ollama

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
CONFIG = {
    "SPLUNK_HOST": os.environ.get("SPLUNK_HOST", "https://localhost:8089"),
    "SPLUNK_USER": os.environ.get("SPLUNK_USER", "admin"),
    "SPLUNK_PASS": os.environ.get("SPLUNK_PASS", "Cybercapstone123!"),
    "PCAP_DIRECTORY": os.environ.get("PCAP_DIRECTORY", "/Users/josephstafford/Downloads/CodePathProject"),
    "REQUIRED_PCAPS": os.environ.get("REQUIRED_PCAPS", "pcapA.pcap,pcapB.pcap").split(","),
    "OLLAMA_HOST": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
    "LLM_MODEL": os.environ.get("LLM_MODEL", "qwen2.5:14b"),
}

AGENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents")


def load_section(filepath: str, section: str) -> str:
    with open(filepath, "r") as f:
        content = f.read()
    pattern = rf"^## {re.escape(section)}\s*$(.*?)(?=^## |\Z)"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1).strip()
    raise ValueError(f"Section '{section}' not found in {filepath}")


# ==========================================
# TOOL DEFINITIONS
# ==========================================

def tool_query_splunk(search_query: str) -> str:
    print(f"  [Splunk Tool] SPL: {search_query}")

    clean_query = search_query.strip()
    if not clean_query.startswith("search") and not clean_query.startswith("|"):
        clean_query = f"search {clean_query}"

    try:
        url = f"{CONFIG['SPLUNK_HOST']}/services/search/jobs"

        payload = {
            "search": clean_query,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "earliest_time": "0",
            "latest_time": "now",
        }

        res = requests.post(
            url,
            auth=(CONFIG["SPLUNK_USER"], CONFIG["SPLUNK_PASS"]),
            data=payload,
            verify=False,
            timeout=30,
        )

        data = res.json().get("results", []) if res.status_code == 200 else []

        if not data:
            print("  [Splunk Tool] 0 results. Executing wide raw log search for JNDI/LDAP...")
            fallback_spl = 'search index=* "jndi" OR "${" OR "ldap" OR "rmi" | stats count min(_time) as earliest max(_time) as latest by _time, src_ip, dest_ip, _raw'

            res = requests.post(
                url,
                auth=(CONFIG["SPLUNK_USER"], CONFIG["SPLUNK_PASS"]),
                data={"search": fallback_spl, "exec_mode": "oneshot", "output_mode": "json", "earliest_time": "0", "latest_time": "now"},
                verify=False,
                timeout=30,
            )
            if res.status_code == 200:
                data = res.json().get("results", [])

        if not data:
            return "SPLUNK_WARNING: 0 events found across indexed data."

        timestamps = sorted([item.get("_time") for item in data if item.get("_time")])
        time_summary = f"TIME RANGE OF LOG ACTIVITY: Earliest = {timestamps[0]} | Latest = {timestamps[-1]} (Total Events: {len(data)})\n\n"

        raw_logs = [item.get("_raw", str(item)) for item in data[:25]]
        return time_summary + json.dumps(raw_logs, indent=2)

    except Exception as e:
        return f"SPLUNK_ERROR: {str(e)}"


def tool_analyze_pcap(pcap_filename: str) -> str:
    target_path = os.path.join(CONFIG["PCAP_DIRECTORY"], pcap_filename)
    if not os.path.exists(target_path):
        return f"PCAP_ERROR: File '{pcap_filename}' not found."

    print(f"  [PCAP Tool] Extracting full frame payloads from: {pcap_filename}...")
    try:
        tshark_cmd = [
            "tshark", "-r", target_path, "-n",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.user_agent",
            "-e", "http.file_data",
            "-e", "tcp.dstport",
            "-e", "text",
        ]

        res = subprocess.run(tshark_cmd, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return f"PCAP_ERROR: TShark error: {res.stderr}"

        lines = res.stdout.strip().splitlines()
        if not lines:
            return f"PCAP_SUCCESS: '{pcap_filename}' parsed, 0 usable IP frames."

        total_packets = len(lines)
        target_ports = {"389", "636", "1099", "1389"}
        summaries = []
        jndi_count = 0

        for line in lines:
            parts = line.split("\t")
            if len(parts) < 5:
                continue

            frame_num, frame_time = parts[0], parts[1]
            src = parts[2] if parts[2] else "N/A"
            dst = parts[3] if parts[3] else "N/A"
            proto = parts[4] if parts[4] else "N/A"
            method = parts[5] if len(parts) > 5 else ""
            uri = parts[6] if len(parts) > 6 else ""
            ua = parts[7] if len(parts) > 7 else ""
            body = parts[8] if len(parts) > 8 else ""
            dstport = parts[9] if len(parts) > 9 else ""
            raw_text = parts[10] if len(parts) > 10 else ""

            combined_payload = f"{uri} {ua} {body} {raw_text}".lower()
            contains_jndi = "jndi" in combined_payload or "${" in combined_payload or "ldap" in combined_payload
            is_outbound_ldap = dstport in target_ports

            if contains_jndi or is_outbound_ldap or method:
                entry = f"Frame {frame_num}: {frame_time} | {src} -> {dst} | {proto}"
                if method or uri:
                    entry += f" | HTTP {method} {uri}"
                if ua:
                    entry += f" | UA: {ua}"
                if body:
                    entry += f" | Body: {body[:120]}"

                if contains_jndi:
                    entry += " | *** CRITICAL ALERT: Log4j/JNDI Exploit String Detected ***"
                    jndi_count += 1
                if is_outbound_ldap:
                    entry += f" | *** ALERT: Outbound JNDI/LDAP/RMI Connection on Port {dstport} ***"

                summaries.append(entry)

        earliest_time = lines[0].split("\t")[1]
        latest_time = lines[-1].split("\t")[1]

        header = (
            f"=== PCAP TIMELINE SUMMARY: {pcap_filename} ===\n"
            f"• Capture Window: {earliest_time} to {latest_time}\n"
            f"• Total Packets Scanned: {total_packets}\n"
            f"• Critical JNDI Indicators Found: {jndi_count}\n"
            f"===========================================\n"
        )

        return header + "\n".join(summaries[:60])

    except subprocess.TimeoutExpired:
        return f"PCAP_TIMEOUT_ERROR: TShark timed out processing {pcap_filename}."
    except Exception as e:
        return f"PCAP_EXECUTION_ERROR on {pcap_filename}: {str(e)}"


# ==========================================
# AGENT DEFINITIONS
# ==========================================

def run_agent_1_splunk() -> str:
    print("\n=== [AGENT 1: SPLUNK LOG COLLECTOR] ===")

    agent1_path = os.path.join(AGENTS_DIR, "agent1_siem.md")
    system_prompt = load_section(agent1_path, "system_prompt")
    user_message = load_section(agent1_path, "user_message")

    tools_schema = [
        {
            "type": "function",
            "function": {
                "name": "query_splunk",
                "description": load_section(agent1_path, "tool_query_splunk").replace("Description: ", ""),
                "parameters": {
                    "type": "object",
                    "properties": {"search_query": {"type": "string"}},
                    "required": ["search_query"],
                },
            },
        }
    ]

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    response = ollama.chat(
        model=CONFIG["LLM_MODEL"], messages=messages, tools=tools_schema
    )
    msg = response["message"]

    if msg.get("tool_calls"):
        for call in msg["tool_calls"]:
            args = call["function"]["arguments"]
            raw_tool_output = tool_query_splunk(**args)

            messages.append(msg)
            messages.append({"role": "tool", "content": raw_tool_output})

            second_response = ollama.chat(
                model=CONFIG["LLM_MODEL"], messages=messages
            )
            return second_response["message"]["content"]

    return "No Splunk queries were triggered by Agent 1."


def run_agent_2_pcap() -> str:
    print("\n=== [AGENT 2: PCAP DISSECTION ANALYST] ===")

    combined_pcap_data = []
    for pcap in CONFIG["REQUIRED_PCAPS"]:
        output = tool_analyze_pcap(pcap)
        combined_pcap_data.append(output)

    pcap_text = "\n\n".join(combined_pcap_data)

    prompt_template = load_section(
        os.path.join(AGENTS_DIR, "agent2_pcap.md"), "analysis_prompt"
    )
    prompt = prompt_template.replace("{{PCAP_DATA}}", pcap_text)

    response = ollama.chat(
        model=CONFIG["LLM_MODEL"],
        messages=[{"role": "user", "content": prompt}],
    )

    return response["message"]["content"]


def run_agent_3_synthesis(splunk_findings: str, pcap_findings: str) -> str:
    print("\n=== [AGENT 3: IR REPORT SYNTHESIZER] ===")

    system_prompt = load_section(
        os.path.join(AGENTS_DIR, "agent3_synthesis.md"), "system_prompt"
    )
    user_content_template = load_section(
        os.path.join(AGENTS_DIR, "agent3_synthesis.md"), "user_content_template"
    )

    user_content = (
        user_content_template.replace("{{SPLUNK_FINDINGS}}", splunk_findings)
        .replace("{{PCAP_FINDINGS}}", pcap_findings)
    )

    response = ollama.chat(
        model=CONFIG["LLM_MODEL"],
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    )
    return response["message"]["content"]


# ==========================================
# PIPELINE ORCHESTRATOR
# ==========================================

def main():
    print("[PIPELINE INITIALIZED] Launching 3-Agent Threat Hunt...")

    ollama_host = CONFIG["OLLAMA_HOST"]
    os.environ["OLLAMA_HOST"] = ollama_host

    splunk_results = run_agent_1_splunk()
    pcap_results = run_agent_2_pcap()
    final_report = run_agent_3_synthesis(splunk_results, pcap_results)

    print("\n============================================================")
    print("                FINAL PLAYBOOK INCIDENT REPORT              ")
    print("============================================================")
    print(final_report)

    OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "output"))
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(OUTPUT_DIR, f"incident_report_{timestamp}.md")
    with open(report_path, "w") as f:
        f.write(final_report)
    print(f"\n[OUTPUT] Report saved to {report_path}")


if __name__ == "__main__":
    main()
