from __future__ import annotations

import concurrent.futures
import datetime
import json
import logging
import logging.handlers
import os
import re
import subprocess
import sys
import time

import ollama
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)

_log_dir = os.environ.get(
    "OUTPUT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "output"),
)
os.makedirs(_log_dir, exist_ok=True)
_log_path = os.path.join(_log_dir, "pipeline.log")
try:
    _file_handler = logging.handlers.RotatingFileHandler(
        _log_path, maxBytes=5 * 1024 * 1024, backupCount=3,
    )
    _file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.getLogger().addHandler(_file_handler)
except (OSError, PermissionError):
    pass

log = logging.getLogger(__name__)

_splunk_pass = os.environ.get("SPLUNK_PASS")
if not _splunk_pass:
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(_env_path):
        with open(_env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("SPLUNK_PASS="):
                    _splunk_pass = line.split("=", 1)[1].strip("\"'")
                    break
if not _splunk_pass:
    sys.exit("FATAL: SPLUNK_PASS environment variable is required.")

CONFIG = {
    "SPLUNK_HOST": os.environ.get("SPLUNK_HOST", "https://localhost:8089"),
    "SPLUNK_USER": os.environ.get("SPLUNK_USER", "admin"),
    "SPLUNK_PASS": _splunk_pass,
    "SPLUNK_VERIFY_SSL": os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "true",
    "PCAP_DIRECTORY": os.environ.get(
        "PCAP_DIRECTORY", "/Users/josephstafford/Downloads/CodePathProject"
    ),
    "REQUIRED_PCAPS": os.environ.get("REQUIRED_PCAPS", "pcapA.pcap,pcapB.pcap").split(
        ","
    ),
    "OLLAMA_HOST": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
    "LLM_MODEL": os.environ.get("LLM_MODEL", "qwen2.5:14b"),
    "MAX_LOG_EVENTS": int(os.environ.get("MAX_LOG_EVENTS", "25")),
    "MAX_PCAP_PACKETS": int(os.environ.get("MAX_PCAP_PACKETS", "50000")),
    "HTTP_RETRIES": int(os.environ.get("HTTP_RETRIES", "3")),
    "HTTP_RETRY_DELAY": int(os.environ.get("HTTP_RETRY_DELAY", "2")),
    "SCAN_TARGET": os.environ.get("SCAN_TARGET", ""),
    "MAX_TOOL_ROUNDS": int(os.environ.get("MAX_TOOL_ROUNDS", "3")),
}

AGENTS_DIR = os.environ.get(
    "AGENTS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents"),
)


class PipelineTelemetry:
    def __init__(self):
        self.agent_durations: dict[str, float] = {}
        self.splunk_results_count = 0
        self.pcap_packets_processed = 0
        self.pcap_packets_flagged = 0
        self.vuln_packages_found = 0
        self.vuln_cves_found = 0
        self.errors: list[str] = []
        self.report_missing_sections: list[str] = []

    def summary(self) -> str:
        parts = ["Pipeline Telemetry:"]
        for agent, dur in self.agent_durations.items():
            parts.append(f"  {agent}: {dur:.2f}s")
        parts.append(f"  Splunk results: {self.splunk_results_count}")
        parts.append(f"  PCAP packets: {self.pcap_packets_processed} processed, {self.pcap_packets_flagged} flagged")
        parts.append(f"  Vulnerabilities: {self.vuln_packages_found} packages, {self.vuln_cves_found} CVEs")
        if self.report_missing_sections:
            parts.append(f"  Report missing sections: {', '.join(self.report_missing_sections)}")
        if self.errors:
            parts.append(f"  Errors ({len(self.errors)}):")
            for e in self.errors:
                parts.append(f"    - {e}")
        return "\n".join(parts)


telemetry = PipelineTelemetry()

REQUIRED_REPORT_SECTIONS = [
    (r"§\s*1.*Timeline", "§1 — Timeline"),
    (r"§\s*2.*Affected Systems", "§2 — Affected Systems"),
    (r"§\s*3.*Exploitation Detection.*Log Analysis", "§3 — Exploitation Detection — Log Analysis"),
    (r"§\s*4.*Exploitation Detection.*Network Analysis", "§4 — Exploitation Detection — Network Analysis"),
    (r"§\s*5.*Exploitation Detection.*Endpoint Analysis", "§5 — Exploitation Detection — Endpoint Analysis"),
    (r"§\s*6.*IP Categorization", "§6 — IP Categorization"),
    (r"§\s*7.*Preventative Recommendations", "§7 — Preventative Recommendations"),
    (r"§\s*8.*Additional Resources", "§8 — Additional Resources"),
]


def validate_report_structure(report: str) -> list[str]:
    missing = []
    for pattern, name in REQUIRED_REPORT_SECTIONS:
        if not re.search(pattern, report):
            missing.append(name)
    return missing


def load_section(filepath: str, section: str) -> str:
    with open(filepath, "r") as f:
        content = f.read()
    pattern = rf"^## {re.escape(section)}\s*$(.*?)(?=^## |\Z)"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1).strip()
    raise ValueError(f"Section '{section}' not found in {filepath}")


def retry_request(
    method: str, url: str, max_retries: int = None, **kwargs
) -> requests.Response:
    max_retries = max_retries or CONFIG["HTTP_RETRIES"]
    delay = CONFIG["HTTP_RETRY_DELAY"]
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            res = requests.request(method, url, **kwargs)
            if res.status_code < 500:
                return res
            log.warning("HTTP %d on %s (attempt %d/%d)", res.status_code, url, attempt, max_retries)
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            log.warning("Request failed for %s: %s (attempt %d/%d)", url, e, attempt, max_retries)
        if attempt < max_retries:
            time.sleep(delay * (2 ** (attempt - 1)))
    raise last_exc or RuntimeError(f"Request to {url} failed after {max_retries} retries")


def normalize_jndi_payload(text: str) -> str:
    resolved = text
    for _ in range(10):
        prev = resolved
        resolved = re.sub(
            r'\$\{(lower):([^}]*)\}',
            lambda m: m.group(2).lower(),
            resolved,
            flags=re.IGNORECASE,
        )
        resolved = re.sub(
            r'\$\{(upper):([^}]*)\}',
            lambda m: m.group(2).upper(),
            resolved,
            flags=re.IGNORECASE,
        )
        resolved = re.sub(
            r'\$\{(?:env|sys|hn|host):([^}]*)\}',
            lambda m: m.group(1),
            resolved,
            flags=re.IGNORECASE,
        )
        resolved = re.sub(
            r'\$\{::([^}]*)\}',
            lambda m: m.group(1).lstrip("-"),
            resolved,
        )
        if resolved == prev:
            break
    return resolved


IOC_FEED_URLS = [
    "https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217/raw",
    "https://raw.githubusercontent.com/CriticalPathSecurity/Zeek-Intelligence-Feeds/master/log4j_ip.intel",
]

KNOWN_MALICIOUS_IPS = {
    "49.7.224.217",
    "104.248.144.120",
    "46.105.95.220",
    "5.157.38.50",
    "2.57.121.36",
    "198.71.247.91",
    "175.6.210.66",
    "195.54.160.149",
    "191.232.38.25",
    "107.189.1.178",
    "147.182.202.30",
}

_ioc_cache = None  # type: set[str] | None


def _load_ioc_feeds(timeout: int = 10) -> set[str]:
    global _ioc_cache
    if _ioc_cache is not None:
        return _ioc_cache
    iocs: set[str] = set()
    for url in IOC_FEED_URLS:
        try:
            res = requests.get(url, timeout=timeout)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        for token in line.split(","):
                            token = token.strip()
                            if token:
                                iocs.add(token)
        except Exception as e:
            log.warning("Failed to fetch IOC feed %s: %s", url, e)
    _ioc_cache = iocs
    log.info("Loaded %d IOC indicators from %d feeds", len(iocs), len(IOC_FEED_URLS))
    return iocs


def enrich_iocs(ips: list[str], domains: list[str]) -> dict[str, list[str]]:
    iocs = _load_ioc_feeds()
    matches: dict[str, list[str]] = {"ips": [], "domains": []}
    for ip in ips:
        if ip in iocs:
            matches["ips"].append(ip)
    for domain in domains:
        if domain in iocs:
            matches["domains"].append(domain)
    return matches


# ==========================================
# VULNERABILITY SCANNING (Syft + Grype)
# ==========================================

def tool_syft_sbom(scan_target: str = None) -> str:
    target = scan_target or CONFIG["SCAN_TARGET"]
    if not target:
        return "VULN_SKIP: No scan target configured (set SCAN_TARGET env)."
    log.info("Running Syft SBOM on: %s", target)
    try:
        res = subprocess.run(
            ["syft", target, "-o", "json"],
            capture_output=True, text=True, timeout=300,
        )
        if res.returncode != 0:
            return f"VULN_ERROR: Syft failed: {res.stderr[:500]}"
        return res.stdout
    except FileNotFoundError:
        return "VULN_ERROR: Syft not found on PATH."
    except subprocess.TimeoutExpired:
        return "VULN_ERROR: Syft timed out (120s)."
    except Exception as e:
        return f"VULN_ERROR: Syft exception: {e}"


def tool_grype_scan(scan_target: str = None) -> str:
    target = scan_target or CONFIG["SCAN_TARGET"]
    if not target:
        return "VULN_SKIP: No scan target configured (set SCAN_TARGET env)."
    log.info("Running Grype vulnerability scan on: %s", target)
    try:
        res = subprocess.run(
            ["grype", target, "-o", "json"],
            capture_output=True, text=True, timeout=300,
        )
        if res.returncode != 0:
            return f"VULN_ERROR: Grype failed: {res.stderr[:500]}"
        return res.stdout
    except FileNotFoundError:
        return "VULN_ERROR: Grype not found on PATH."
    except subprocess.TimeoutExpired:
        return "VULN_ERROR: Grype timed out (300s)."
    except Exception as e:
        return f"VULN_ERROR: Grype exception: {e}"


def summarize_vuln_scan(grype_json: str, syft_json: str) -> str:
    try:
        grype_data = json.loads(grype_json)
    except (json.JSONDecodeError, ValueError):
        grype_data = {}
    try:
        syft_data = json.loads(syft_json)
    except (json.JSONDecodeError, ValueError):
        syft_data = {}
    if not grype_data and not syft_data:
        return "VULN_ERROR: Failed to parse vulnerability scan output."

    artifacts = syft_data.get("artifacts", [])
    matches = grype_data.get("matches", [])

    telemetry.vuln_packages_found = len(artifacts)
    telemetry.vuln_cves_found = len(matches)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0}
    by_severity: dict[str, list[dict]] = {s: [] for s in severity_counts}

    log4j_cves = {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"}
    log4j_matches = []

    for m in matches:
        vuln = m.get("vulnerability", {})
        sev = vuln.get("severity", "Unknown")
        if sev in severity_counts:
            severity_counts[sev] += 1
            by_severity[sev].append(m)
        if vuln.get("id") in log4j_cves:
            log4j_matches.append(m)

    lines = [
        "=== VULNERABILITY SCAN SUMMARY ===",
        f"Packages cataloged: {len(artifacts)}",
        f"Vulnerabilities found: {len(matches)}",
        "",
        "Severity Breakdown:",
    ]
    for sev in ("Critical", "High", "Medium", "Low", "Negligible"):
        if severity_counts[sev]:
            lines.append(f"  {sev}: {severity_counts[sev]}")

    if log4j_matches:
        lines.extend(["", "Log4j-Related Vulnerabilities:"])
        for m in log4j_matches[:5]:
            v = m.get("vulnerability", {})
            art = m.get("artifact", {})
            fix = v.get("fix", {}).get("versions", ["none"])
            lines.append(
                f"  {v.get('id')} | {art.get('name')} {art.get('version')} "
                f"| Severity: {v.get('severity')} | Fix: {', '.join(fix)}"
            )

    top_critical = by_severity.get("Critical", [])[:5]
    top_high = by_severity.get("High", [])[:5]
    top_all = (top_critical + top_high)[:10]

    if top_all:
        lines.extend(["", "Top Critical/High Vulnerabilities:"])
        for m in top_all:
            v = m.get("vulnerability", {})
            art = m.get("artifact", {})
            fix = v.get("fix", {}).get("versions", ["none"])
            lines.append(
                f"  {v.get('id')} | {art.get('name')} {art.get('version')} "
                f"| {v.get('severity')} | Fix: {', '.join(fix)}"
            )

    return "\n".join(lines)


# ==========================================
# TOOL DEFINITIONS
# ==========================================

def tool_query_splunk(search_query: str) -> str:
    log.info("Splunk query: %s", search_query)
    log.info("Splunk query: %s", search_query)

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

        res = retry_request(
            "POST",
            url,
            auth=(CONFIG["SPLUNK_USER"], CONFIG["SPLUNK_PASS"]),
            data=payload,
            verify=CONFIG["SPLUNK_VERIFY_SSL"],
            timeout=30,
        )

        data = res.json().get("results", []) if res.status_code == 200 else []

        if not data:
            telemetry.splunk_results_count = 0
            return "SPLUNK_WARNING: 0 events found. Try a broader query."

        timestamps = sorted([item.get("_time") for item in data if item.get("_time")])
        if not timestamps:
            telemetry.splunk_results_count = len(data)
            return f"SPLUNK_WARNING: {len(data)} events found but none contain _time fields."

        telemetry.splunk_results_count = len(data)
        time_summary = (
            f"TIME RANGE OF LOG ACTIVITY: Earliest = {timestamps[0]}"
            f" | Latest = {timestamps[-1]} (Total Events: {len(data)})\n\n"
        )

        max_events = CONFIG["MAX_LOG_EVENTS"]
        raw_logs = [item.get("_raw", str(item)) for item in data[:max_events]]
        return time_summary + json.dumps(raw_logs, indent=2)

    except Exception as e:
        telemetry.errors.append(f"Splunk query failed: {e}")
        return f"SPLUNK_ERROR: {str(e)}"


def _get_json_field(pkt: dict, *keys: str) -> str:
    try:
        layers = pkt.get("_source", {}).get("layers", {})
        if keys[-1] in layers:
            val = layers[keys[-1]]
            if isinstance(val, list) and val:
                return str(val[0])
            return str(val) if val else ""
        val = layers
        for key in keys:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                return ""
        if isinstance(val, list) and val:
            return str(val[0])
        return str(val) if val else ""
    except (KeyError, IndexError, TypeError):
        return ""


def _parse_tshark_field_output(output: str) -> list[dict]:
    try:
        packets = json.loads(output)
        if not isinstance(packets, list):
            return []
        result = []
        for pkt in packets:
            result.append(
                {
                    "frame.number": _get_json_field(pkt, "frame", "frame.number"),
                    "frame.time": _get_json_field(pkt, "frame", "frame.time"),
                    "ip.src": _get_json_field(pkt, "ip", "ip.src"),
                    "ip.dst": _get_json_field(pkt, "ip", "ip.dst"),
                    "protocol": _get_json_field(pkt, "_ws", "_ws.col.Protocol"),
                    "http.request.method": _get_json_field(
                        pkt, "http", "http.request.method"
                    ),
                    "http.request.uri": _get_json_field(
                        pkt, "http", "http.request.uri"
                    ),
                    "http.user_agent": _get_json_field(
                        pkt, "http", "http.user_agent"
                    ),
                    "http.file_data": _get_json_field(
                        pkt, "http", "http.file_data"
                    ),
                    "http.authorization": _get_json_field(
                        pkt, "http", "http.authorization"
                    ),
                    "tcp.dstport": _get_json_field(pkt, "tcp", "tcp.dstport"),
                    "text": _get_json_field(pkt, "text", "text"),
                    "data": _get_json_field(pkt, "data", "data"),
                    "dns.qry.name": _get_json_field(pkt, "dns", "dns.qry.name"),
                    "dns.flags.response": _get_json_field(
                        pkt, "dns", "dns.flags.response"
                    ),
                }
            )
        return result
    except (json.JSONDecodeError, TypeError):
        return []


def tool_analyze_pcap(pcap_filename: str) -> str:
    target_path = os.path.join(CONFIG["PCAP_DIRECTORY"], pcap_filename)
    if not os.path.exists(target_path):
        return f"PCAP_ERROR: File '{pcap_filename}' not found."

    log.info("Analyzing PCAP: %s", pcap_filename)
    try:
        ws_filters = [
            'frame matches "(?i)jndi"',
            'ip contains "jndi"',
            'ip contains "jndi" || http.user_agent contains "jndi"',
            'frame matches "(?i)jndi" || frame matches "\\$\\{" || ldap || tcp.port == 1389 || tcp.port == 1099',
        ]
        packets = []
        for wsf in ws_filters:
            log.info("Trying Wireshark filter: %s", wsf)
            filter_cmd = [
                "tshark", "-r", target_path, "-n",
                "-Y", wsf,
                "-T", "json",
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
            res = subprocess.run(filter_cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                packets = _parse_tshark_field_output(res.stdout.strip())
                if packets:
                    log.info("Wireshark filter matched %d packets", len(packets))
                    break

        if not packets:
            all_cmd = [
                "tshark",
                "-r", target_path, "-n",
                "-T", "json",
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
            res = subprocess.run(all_cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                return f"PCAP_ERROR: TShark error: {res.stderr}"
            packets = _parse_tshark_field_output(res.stdout.strip())
            max_packets = CONFIG["MAX_PCAP_PACKETS"]
            if len(packets) > max_packets:
                log.warning("Truncating to %d packets (of %d)", max_packets, len(packets))
                packets = packets[:max_packets]

        if not packets:
            return f"PCAP_SUCCESS: '{pcap_filename}' parsed, 0 usable IP frames."

        total_packets = len(packets)
        telemetry.pcap_packets_processed += total_packets
        jndi_ports = {"389", "636", "1099", "1389"}
        suspicious_uas = {
            "curl",
            "wget",
            "powershell",
            "python-requests",
            "go-http-client",
            "bot",
            "scanner",
        }
        summaries = []
        jndi_count = 0
        obfuscated_jndi_count = 0
        suspicious_ua_count = 0
        callback_count = 0
        known_malicious_ip_count = 0
        dns_queries = []

        for pkt in packets:
            frame_num = pkt.get("frame.number", "?")
            frame_time = pkt.get("frame.time", "?")
            src = pkt.get("ip.src") or "N/A"
            dst = pkt.get("ip.dst") or "N/A"
            proto = pkt.get("protocol") or "N/A"
            method = pkt.get("http.request.method", "")
            uri = pkt.get("http.request.uri", "")
            ua = pkt.get("http.user_agent", "")
            body = pkt.get("http.file_data", "")
            auth = pkt.get("http.authorization", "")
            dstport = pkt.get("tcp.dstport", "")
            raw_text = pkt.get("text", "")
            raw_data = pkt.get("data", "")

            combined_payload = f"{uri} {ua} {body} {auth} {raw_text} {raw_data}".lower()
            normalized_payload = normalize_jndi_payload(combined_payload)

            contains_jndi = "jndi:" in combined_payload or "${" in combined_payload
            contains_obfuscated = (
                "jndi:" in normalized_payload
                and normalized_payload != combined_payload
            ) or bool(
                re.search(r'\$\{(lower|upper|env|::-|sys|hn|host)', combined_payload)
            )
            is_outbound_jndi = dstport in jndi_ports
            has_suspicious_ua = (
                any(sua in ua.lower() for sua in suspicious_uas) if ua else False
            )
            is_callback = bool(method and dstport == "80" and not uri.startswith("/"))
            is_known_malicious = (src in KNOWN_MALICIOUS_IPS or dst in KNOWN_MALICIOUS_IPS)

            if (
                contains_jndi
                or contains_obfuscated
                or is_outbound_jndi
                or has_suspicious_ua
                or is_callback
                or method
                or is_known_malicious
            ):
                entry = f"Frame {frame_num}: {frame_time} | {src} -> {dst} | {proto}"
                if method or uri:
                    entry += f" | HTTP {method} {uri}"
                if ua:
                    entry += f" | UA: {ua}"
                if body:
                    entry += f" | Body: {body[:120]}"
                if auth:
                    entry += f" | Auth: {auth[:120]}"

                if contains_jndi:
                    entry += " | *** CRITICAL: Log4j JNDI Exploit String ***"
                    jndi_count += 1
                if contains_obfuscated:
                    entry += " | *** CRITICAL: Obfuscated JNDI Exploit ***"
                    obfuscated_jndi_count += 1
                if is_outbound_jndi:
                    entry += f" | *** ALERT: Outbound JNDI/LDAP/RMI on Port {dstport} ***"
                if has_suspicious_ua:
                    entry += " | *** ALERT: Suspicious UA (curl/wget/powershell) ***"
                    suspicious_ua_count += 1
                if is_callback:
                    entry += " | *** ALERT: Potential C2 Callback ***"
                    callback_count += 1
                if is_known_malicious:
                    entry += " | *** ALERT: Known Malicious IP ***"
                    known_malicious_ip_count += 1

                summaries.append(entry)

        telemetry.pcap_packets_flagged += len(summaries)

        dns_cmd = [
            "tshark",
            "-r", target_path, "-n",
            "-T", "json",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "dns.qry.name",
            "-e", "dns.flags.response",
            "-Y", "dns",
        ]
        dns_res = subprocess.run(dns_cmd, capture_output=True, text=True, timeout=15)
        if dns_res.returncode == 0:
            dns_packets = _parse_tshark_field_output(dns_res.stdout.strip())
            if dns_packets:
                for dp in dns_packets:
                    qry_name = dp.get("dns.qry.name", "")
                    flags = dp.get("dns.flags.response", "")
                    if qry_name and flags != "1":
                        dns_queries.append(
                            f"Frame {dp.get('frame.number', '?')}: "
                            f"{dp.get('frame.time', '?')} | "
                            f"{dp.get('ip.src', '?')} -> {dp.get('ip.dst', '?')} | "
                            f"DNS query: {qry_name}"
                        )

        dns_section = ""
        if dns_queries:
            dns_section = (
                "\n--- DNS Queries (Playbook §4.3) ---\n"
                + "\n".join(dns_queries[:20])
                + "\n"
            )

        earliest_time = packets[0].get("frame.time", "?")
        latest_time = packets[-1].get("frame.time", "?")

        header = (
            f"=== PCAP TIMELINE SUMMARY: {pcap_filename} ===\n"
            f"Capture Window: {earliest_time} to {latest_time}\n"
            f"Total Packets Scanned: {total_packets}\n"
            f"Critical JNDI Indicators: {jndi_count}\n"
            f"Obfuscated JNDI Indicators: {obfuscated_jndi_count}\n"
            f"Suspicious User-Agents: {suspicious_ua_count}\n"
            f"Potential Callbacks: {callback_count}\n"
            f"Known Malicious IP Matches: {known_malicious_ip_count}\n"
            f"===========================================\n"
        )

        return header + "\n".join(summaries[:60]) + dns_section

    except subprocess.TimeoutExpired:
        return f"PCAP_TIMEOUT_ERROR: TShark timed out processing {pcap_filename}."
    except Exception as e:
        telemetry.errors.append(f"PCAP analysis failed for {pcap_filename}: {e}")
        return f"PCAP_EXECUTION_ERROR on {pcap_filename}: {str(e)}"


# ==========================================
# AGENT BASE CLASS + REGISTRY
# ==========================================

class AgentBase:
    name: str
    agent_file: str

    def __init__(self) -> None:
        self.agent_path = os.path.join(AGENTS_DIR, self.agent_file)

    def load_prompt(self, section: str) -> str:
        return load_section(self.agent_path, section)

    def ollama_chat(self, messages: list[dict], tools: list | None = None) -> dict:
        kwargs: dict = {"model": CONFIG["LLM_MODEL"], "messages": messages}
        if tools:
            kwargs["tools"] = tools
        return retry_request_ollama(**kwargs)

    def run(self, **kwargs) -> str:
        raise NotImplementedError


class LlmAgent(AgentBase):
    """Agent that calls Ollama with a single prompt (no tool calling)."""

    def run(self, **kwargs) -> str:
        log.info("=== [AGENT %s] ===", self.name)
        try:
            response = self.ollama_chat(kwargs.get("messages", []))
            return response["message"]["content"]
        except Exception as e:
            telemetry.errors.append(f"Agent {self.name} failed: {e}")
            log.error("Agent %s failed: %s", self.name, e)
            return f"AGENT_ERROR: {self.name} unavailable — {e}"


class ToolAgent(AgentBase):
    """Agent that uses function-calling (tools) to interact with tools."""

    tool_name: str = ""
    tool_fn = None
    tool_parameters: dict = None

    def _tool_schema(self) -> list[dict]:
        params = self.tool_parameters or {
            "type": "object",
            "properties": {"search_query": {"type": "string"}},
            "required": ["search_query"],
        }
        return [
            {
                "type": "function",
                "function": {
                    "name": self.tool_name,
                    "description": self.load_prompt(f"tool_{self.tool_name}").replace("Description: ", ""),
                    "parameters": params,
                },
            }
        ]

    def run(self, **kwargs) -> str:
        log.info("=== [AGENT %s] ===", self.name)
        try:
            tools_schema = self._tool_schema()
            messages = [
                {"role": "system", "content": self.load_prompt("system_prompt")},
                {"role": "user", "content": self.load_prompt("user_message")},
            ]
            max_rounds = CONFIG["MAX_TOOL_ROUNDS"]
            for _ in range(max_rounds):
                response = self.ollama_chat(messages, tools=tools_schema)
                msg = response["message"]
                if not msg.get("tool_calls"):
                    return msg.get("content", f"No {self.tool_name} calls triggered.")
                for call in msg["tool_calls"]:
                    args = call["function"]["arguments"]
                    if isinstance(args, dict):
                        raw_output = self.tool_fn(**args)
                    elif isinstance(args, str):
                        raw_output = self.tool_fn(args)
                    else:
                        raw_output = self.tool_fn(*args) if isinstance(args, (list, tuple)) else str(args)
                    messages.append(msg)
                    messages.append({"role": "tool", "content": raw_output})
            log.info("Max tool rounds (%d) reached.", max_rounds)
            return str(messages[-1]["content"]) if messages else "No results."
        except Exception as e:
            telemetry.errors.append(f"Agent {self.name} failed: {e}")
            log.error("Agent %s failed: %s", self.name, e)
            return f"AGENT_ERROR: {self.name} unavailable — {e}"


# --- Concrete agents ---

class Agent1Splunk(ToolAgent):
    name = "Agent 1 (Splunk)"
    agent_file = "agent1_siem.md"
    tool_name = "query_splunk"
    tool_fn = tool_query_splunk


class Agent2Pcap(LlmAgent):
    name = "Agent 2 (PCAP)"

    @property
    def agent_file(self) -> str:
        return "agent2_pcap.md"

    def run(self, **kwargs) -> str:
        log.info("=== [AGENT %s] ===", self.name)
        combined_pcap_data = []
        for pcap in CONFIG["REQUIRED_PCAPS"]:
            output = tool_analyze_pcap(pcap)
            combined_pcap_data.append(output)
        pcap_text = "\n\n".join(combined_pcap_data)
        prompt = self.load_prompt("analysis_prompt").replace("{{PCAP_DATA}}", pcap_text)
        try:
            response = self.ollama_chat([{"role": "user", "content": prompt}])
            return response["message"]["content"]
        except Exception as e:
            telemetry.errors.append(f"Agent {self.name} failed: {e}")
            log.error("Agent %s failed: %s", self.name, e)
            return f"AGENT_ERROR: {self.name} unavailable — {e}"


class Agent3Synthesis(AgentBase):
    name = "Agent 3 (Synthesis)"
    agent_file = "agent3_synthesis.md"

    def run(self, **kwargs) -> str:
        log.info("=== [AGENT %s] ===", self.name)
        splunk_findings = kwargs.get("splunk_findings", "")
        pcap_findings = kwargs.get("pcap_findings", "")
        vuln_findings = kwargs.get("vuln_findings", "")
        investigator_name = os.environ.get("INVESTIGATOR_NAME", "Lead Incident Response Agent")
        current_date = datetime.datetime.now().strftime("%B %d, %Y")
        user_content = (
            self.load_prompt("user_content_template")
            .replace("{{SPLUNK_FINDINGS}}", splunk_findings)
            .replace("{{PCAP_FINDINGS}}", pcap_findings)
            .replace("{{VULN_FINDINGS}}", vuln_findings)
        )
        full_prompt = (
            f"Investigator: {investigator_name}\n"
            f"Date: {current_date}\n\n{user_content}"
        )
        try:
            response = self.ollama_chat([
                {"role": "system", "content": self.load_prompt("system_prompt")},
                {"role": "user", "content": full_prompt},
            ])
            report = response["message"]["content"]
            missing = validate_report_structure(report)
            if missing:
                telemetry.report_missing_sections = missing
                log.warning("Report missing %d required section(s): %s", len(missing), ", ".join(missing))
            return report
        except Exception as e:
            telemetry.errors.append(f"Agent {self.name} failed: {e}")
            log.error("Agent %s failed: %s", self.name, e)
            return f"AGENT_ERROR: {self.name} unavailable — {e}"


class Agent4VulnScan(ToolAgent):
    name = "Agent 4 (Vulnerability)"
    agent_file = "agent4_vuln_scan.md"
    tool_name = "scan_vulnerabilities"
    tool_parameters = {"type": "object", "properties": {}, "required": []}

    def run(self, **kwargs) -> str:
        log.info("=== [AGENT %s] ===", self.name)
        if not CONFIG["SCAN_TARGET"]:
            log.warning("No SCAN_TARGET configured — skipping vulnerability scan.")
            return "VULN_SKIP: No SCAN_TARGET configured (set SCAN_TARGET env var)."
        try:
            syft_output = tool_syft_sbom()
            if syft_output.startswith("VULN_ERROR") or syft_output.startswith("VULN_SKIP"):
                return syft_output
            grype_output = tool_grype_scan()
            if grype_output.startswith("VULN_ERROR") or grype_output.startswith("VULN_SKIP"):
                return grype_output
            summary = summarize_vuln_scan(grype_output, syft_output)
            log.info("Vulnerability summary generated:\n%s", summary)
            messages = [
                {"role": "system", "content": self.load_prompt("system_prompt")},
                {"role": "user", "content": self.load_prompt("user_message")},
            ]
            tools_schema = [
                {
                    "type": "function",
                    "function": {
                        "name": "scan_vulnerabilities",
                        "description": self.load_prompt("tool_scan_vulnerabilities").replace("Description: ", ""),
                        "parameters": {"type": "object", "properties": {}, "required": []},
                    },
                }
            ]
            response = self.ollama_chat(messages, tools=tools_schema)
            msg = response["message"]
            if msg.get("tool_calls"):
                messages.append(msg)
                messages.append({"role": "tool", "content": summary})
                second = self.ollama_chat(messages)
                return second["message"]["content"]
            return summary
        except Exception as e:
            telemetry.errors.append(f"Agent {self.name} failed: {e}")
            log.error("Agent %s failed: %s", self.name, e)
            return f"AGENT_ERROR: {self.name} unavailable — {e}"


def discover_agents() -> dict[str, AgentBase]:
    registry: dict[str, AgentBase] = {}
    for cls in [Agent1Splunk, Agent2Pcap, Agent3Synthesis, Agent4VulnScan]:
        inst = cls()
        agent_key = cls.name
        registry[agent_key] = inst
    return registry


AGENT_REGISTRY = discover_agents()
DEFAULT_PIPELINE = ["Agent 1 (Splunk)", "Agent 2 (PCAP)", "Agent 4 (Vulnerability)", "Agent 3 (Synthesis)"]


# ==========================================
# OLD AGENT FUNCTIONS (keep for backward compat)
# ==========================================

def run_agent_1_splunk() -> str:
    return AGENT_REGISTRY["Agent 1 (Splunk)"].run()

def run_agent_2_pcap() -> str:
    return AGENT_REGISTRY["Agent 2 (PCAP)"].run()

def run_agent_3_synthesis(splunk_findings: str = "", pcap_findings: str = "", vuln_findings: str = "") -> str:
    return AGENT_REGISTRY["Agent 3 (Synthesis)"].run(
        splunk_findings=splunk_findings, pcap_findings=pcap_findings, vuln_findings=vuln_findings
    )

def run_agent_4_vuln_scan() -> str:
    return AGENT_REGISTRY["Agent 4 (Vulnerability)"].run()


def retry_request_ollama(**kwargs) -> dict:
    max_retries = CONFIG["HTTP_RETRIES"]
    delay = CONFIG["HTTP_RETRY_DELAY"]
    for attempt in range(1, max_retries + 1):
        try:
            return ollama.chat(**kwargs)
        except Exception as e:
            log.warning("Ollama call failed (attempt %d/%d): %s", attempt, max_retries, e)
            if attempt < max_retries:
                time.sleep(delay * (2 ** (attempt - 1)))
    raise RuntimeError(f"Ollama call failed after {max_retries} retries")


# ==========================================
# PIPELINE ORCHESTRATOR
# ==========================================

def main():
    log.info("[PIPELINE INITIALIZED] Launching 4-Agent Threat Hunt...")

    ollama_host = CONFIG["OLLAMA_HOST"]
    os.environ["OLLAMA_HOST"] = ollama_host

    pipeline = os.environ.get("PIPELINE", ",".join(DEFAULT_PIPELINE)).split(",")
    parallel_agents = [name for name in pipeline if name != "Agent 3 (Synthesis)"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(parallel_agents)) as executor:
        futures = {name: executor.submit(AGENT_REGISTRY[name].run) for name in parallel_agents}
        results: dict[str, str] = {}
        for name, future in futures.items():
            t0 = time.time()
            results[name] = future.result()
            telemetry.agent_durations[name] = time.time() - t0

    t0 = time.time()
    synthesis = AGENT_REGISTRY["Agent 3 (Synthesis)"]
    final_report = synthesis.run(
        splunk_findings=results.get("Agent 1 (Splunk)", ""),
        pcap_findings=results.get("Agent 2 (PCAP)", ""),
        vuln_findings=results.get("Agent 4 (Vulnerability)", ""),
    )
    telemetry.agent_durations["Agent 3 (Synthesis)"] = time.time() - t0

    log.info("\n" + "=" * 60)
    log.info("          FINAL PLAYBOOK INCIDENT REPORT")
    log.info("=" * 60)
    log.info("\n%s", final_report)

    OUTPUT_DIR = os.environ.get(
        "OUTPUT_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "output"),
    )
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    report_path = os.path.join(OUTPUT_DIR, f"incident_report_{timestamp}.md")
    with open(report_path, "w") as f:
        f.write(final_report)
    log.info("Report saved to %s", report_path)

    json_path = os.path.join(OUTPUT_DIR, f"incident_report_{timestamp}.json")
    structured = {
        "timestamp": timestamp,
        "investigator": os.environ.get("INVESTIGATOR_NAME", "Lead Incident Response Agent"),
        "splunk_findings": results.get("Agent 1 (Splunk)", ""),
        "pcap_findings": results.get("Agent 2 (PCAP)", ""),
        "vuln_findings": results.get("Agent 4 (Vulnerability)", ""),
        "report": final_report,
        "telemetry": {
            "agent_durations": telemetry.agent_durations,
            "splunk_results_count": telemetry.splunk_results_count,
            "pcap_packets_processed": telemetry.pcap_packets_processed,
            "pcap_packets_flagged": telemetry.pcap_packets_flagged,
            "vuln_packages_found": telemetry.vuln_packages_found,
            "vuln_cves_found": telemetry.vuln_cves_found,
            "report_missing_sections": telemetry.report_missing_sections,
        },
    }
    with open(json_path, "w") as f:
        json.dump(structured, f, indent=2)
    log.info("JSON report saved to %s", json_path)

    log.info("\n" + telemetry.summary())


if __name__ == "__main__":
    main()
