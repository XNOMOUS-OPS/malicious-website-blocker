# 🛡️ Malicious Website Blocker & SIEM Threat Intel Hub

A cybersecurity endpoint and network defense project that identifies malicious URLs using VirusTotal v3 Threat Intelligence, enforces DNS/Hosts sinkholing, and generates structured SIEM security logs (**CEF**, **JSON RFC 5424**, and **Syslog**) for SOC ingestion (Splunk, Elastic/ELK, Wazuh, Graylog).

Supports both **Docker container deployment** (with Web SOC Dashboard & REST API) and **Standalone Desktop execution** (Tkinter GUI).

---

## 📋 Table of Contents

- [Project Architecture](#-project-architecture)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Quickstart with Docker (Recommended)](#-quickstart-with-docker-recommended)
- [Running Desktop GUI Locally](#-running-desktop-gui-locally)
- [SIEM Integration Lab Guide](#-siem-integration-lab-guide)
  - [1. Elastic Stack (ELK / Filebeat)](#1-elastic-stack-elk--filebeat)
  - [2. Wazuh Agent Integration](#2-wazuh-agent-integration)
  - [3. Splunk Universal Forwarder / CEF Ingest](#3-splunk-universal-forwarder--cef-ingest)
- [Sample SIEM Event Logs](#-sample-siem-event-logs)
- [REST API Endpoints](#-rest-api-endpoints)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Troubleshooting](#-troubleshooting)

---

## 🏗️ Project Architecture

```
                                  ┌─────────────────────────────┐
                                  │   VirusTotal v3 Cloud API   │
                                  └──────────────▲──────────────┘
                                                 │
                                                 │ (Threat Intel Query)
                                                 ▼
┌──────────────────┐               ┌───────────────────────────┐
│   Web SOC UI     │◄─────────────►│    Core Detection Engine  │
│ (http://:5000)   │  REST API     │    (core_blocker.py)      │
└──────────────────┘               └─────────────┬─────────────┘
                                                 │
                   ┌─────────────────────────────┼─────────────────────────────┐
                   ▼                             ▼                             ▼
       ┌───────────────────────┐    ┌─────────────────────────┐   ┌─────────────────────────┐
       │   Hosts Sinkhole /    │    │  Structured JSON Logs   │   │     CEF / Syslog Stream │
       │   Pi-hole Blocklist   │    │  (logs/siem_events.json)│   │   (RFC 5424 to SIEM)    │
       └───────────────────────┘    └────────────┬────────────┘   └────────────┬────────────┘
                                                 │                             │
                                                 ▼                             ▼
                                    ┌─────────────────────────┐   ┌─────────────────────────┐
                                    │    Wazuh / Filebeat     │   │   Splunk / QRadar /     │
                                    │      (Elasticsearch)    │   │         Graylog         │
                                    └─────────────────────────┘   └─────────────────────────┘
```

---

## ✨ Features

- **Automated Threat Intelligence**: Submits suspicious URLs to VirusTotal API v3 and evaluates threat scores (malicious/suspicious detection ratios).
- **Automated Remediation & Sinkholing**: Automatically diverts malicious domains to `127.0.0.1` locally or exports standard sinkhole lists for Pi-hole/dnsmasq/AdGuard.
- **Enterprise SIEM Security Event Generation**:
  - **Structured JSON (ECS-aligned)** for Elasticsearch, Wazuh, and Graylog.
  - **Common Event Format (CEF)** for ArcSight, Splunk, and QRadar.
  - **Network Syslog Forwarding** (UDP/TCP direct transmission).
- **Web SOC Dashboard**: Dark-themed cybersecurity analyst dashboard with live scanner, blocklist management, and real-time SIEM audit stream.
- **REST API**: Clean endpoints for automation, SOAR playbooks, and external security tooling.
- **Container Ready**: Packaged for Docker and Docker Compose with health checks and volume persistence.
- **Legacy Desktop Compatibility**: Original desktop GUI script (`Block_malicious_website.py`) remains fully functional with added SIEM logging.

---

## 🖥️ Prerequisites

- **Docker & Docker Compose** (for containerized mode) OR **Python 3.8+** (for desktop GUI).
- A free **VirusTotal API Key** (register at [virustotal.com](https://www.virustotal.com)).
- Optional: Local SIEM lab instance (Wazuh, Elastic, Splunk, or Graylog).

---

## 🐳 Quickstart with Docker (Recommended)

### 1. Clone Repository & Setup Environment

```bash
git clone https://github.com/XNOMOUS-OPS/malicious-website-blocker.git
cd malicious-website-blocker
cp .env.example .env
```

Edit `.env` and insert your VirusTotal API key:
```env
VT_API_KEY=your_actual_virustotal_api_key_here
PORT=5000
```

### 2. Launch with Docker Compose

```bash
docker compose up -d --build
```

### 3. Access the SOC Dashboard

Open your web browser and navigate to:
```
http://localhost:5000
```

- Submit any URL (e.g. `http://malicious-test-site.com`) to run threat analysis.
- If flagged, the domain is auto-blocked and dispatched to `logs/siem_events.json` and `logs/siem_events.log`.
- Download the DNS Sinkhole export file via the dashboard or `/api/blocklist/export`.

To stop the container:
```bash
docker compose down
```

---

## 💻 Running Desktop GUI Locally

If you prefer using the desktop Tkinter application:

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure your API key in `.env` or set as environment variable:
   ```bash
   # Windows (PowerShell)
   $env:VT_API_KEY="your_api_key"

   # Linux / macOS
   export VT_API_KEY="your_api_key"
   ```

3. Run the script with Administrator / root privileges (needed to edit the system `hosts` file):
   - **Windows**: Run Command Prompt or PowerShell as Administrator:
     ```bash
     python Block_malicious_website.py
     ```
   - **Linux / macOS**:
     ```bash
     sudo python3 Block_malicious_website.py
     ```

---

## 📡 SIEM Integration Lab Guide

The blocker writes structured logs to the `./logs/` directory mounted on the host machine.

### 1. Elastic Stack (ELK / Filebeat)

Add the following input configuration to your `filebeat.yml` to ingest events into Elasticsearch:

```yaml
filebeat.inputs:
  - type: filestream
    id: malicious-blocker-events
    enabled: true
    paths:
      - /path/to/malicious-website-blocker/logs/siem_events.json
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true

output.elasticsearch:
  hosts: ["http://localhost:9200"]
  index: "soc-malicious-blocker-%{+yyyy.MM.dd}"
```

### 2. Wazuh Agent Integration

Add this snippet to `/var/ossec/etc/ossec.conf` on the endpoint running the blocker:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/malicious-website-blocker/logs/siem_events.json</location>
</localfile>
```

Example custom Wazuh rule (`/var/ossec/etc/rules/local_rules.xml`):

```xml
<group name="threat_intel,malicious_blocker,">
  <rule id="100501" level="10">
    <decoded_as>json</decoded_as>
    <field name="event.action">threat_detected</field>
    <description>Malicious Domain Detected by VirusTotal: $(details.domain)</description>
    <mitre>
      <id>T1566</id>
      <id>T1071.001</id>
    </mitre>
  </rule>
</group>
```

### 3. Splunk Universal Forwarder / CEF Ingest

In `inputs.conf`:
```ini
[monitor:///path/to/malicious-website-blocker/logs/siem_events.log]
sourcetype = cef
index = security_alerts
```

Or configure direct UDP Syslog forwarding in `.env`:
```env
SIEM_SYSLOG_HOST=192.168.1.50
SIEM_SYSLOG_PORT=514
SIEM_SYSLOG_PROTOCOL=UDP
```

---

## 📜 Sample SIEM Event Logs

### Structured JSON Event (`logs/siem_events.json`):
```json
{
  "@timestamp": "2026-08-19T12:00:00.000000+00:00",
  "event": {
    "dataset": "malicious_website_blocker.events",
    "action": "threat_detected",
    "category": "threat-intel",
    "severity": 8,
    "severity_label": "HIGH"
  },
  "details": {
    "summary": "Malicious domain detected via VirusTotal: phishing-portal.xyz (malicious=14, suspicious=2)",
    "url": "http://phishing-portal.xyz/login.php",
    "domain": "phishing-portal.xyz",
    "malicious_count": 14,
    "suspicious_count": 2,
    "harmless_count": 0,
    "undetected_count": 72,
    "verdict": "MALICIOUS"
  }
}
```

### ArcSight Common Event Format (`logs/siem_events.log`):
```text
CEF:0|SecOpsLab|MaliciousWebsiteBlocker|1.2|THREAT_DETECTED|Malicious domain detected via VirusTotal: phishing-portal.xyz (malicious=14, suspicious=2)|8|rt=1787140800000 cat=THREAT_DETECTED sev=HIGH cs_summary=Malicious domain detected via VirusTotal: phishing-portal.xyz (malicious=14, suspicious=2) cs_url=http://phishing-portal.xyz/login.php cs_domain=phishing-portal.xyz cn_malicious_count=14 cn_suspicious_count=2 cn_harmless_count=0 cn_undetected_count=72 cs_verdict=MALICIOUS
```

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web SOC Analyst Dashboard UI |
| `GET` | `/api/status` | Health check, API key status, and blocked domain count |
| `GET` | `/api/blocklist` | List of all currently blocked domains |
| `GET` | `/api/blocklist/export` | Download standard hosts / DNS sinkhole blocklist file |
| `POST` | `/api/scan` | Scan URL with VirusTotal (JSON payload: `{"url": "..."}`) |
| `POST` | `/api/block` | Manually block domain (JSON payload: `{"url": "...", "reason": "..."}`) |
| `POST` | `/api/unblock` | Unblock domain (JSON payload: `{"url": "..."}`) |
| `GET` | `/api/events` | Retrieve recent JSON SIEM security events |
| `GET` | `/api/events/cef` | Retrieve raw CEF log feed |

---

## 🎯 MITRE ATT&CK Mapping

This project maps directly to common SOC threat detection and defense techniques:

- **T1566 (Phishing)**: Scanning inbound suspicious links in incident response.
- **T1071.001 (Web Protocols C2)**: Blocking outbound communication to flagged C2 servers.
- **T1584 (DNS Sinkholing / Hosts Redirection)**: Neutralizing malicious name resolution locally.
- **T1036 (Masquerading)**: Detecting deceptive typo-squatted domains via VirusTotal reputation.

---

## 🔧 Troubleshooting

| Issue | Solution |
|---|---|
| `VirusTotal API key is not configured` | Set `VT_API_KEY` in `.env` file or environment variables. |
| `VirusTotal rate limit exceeded (HTTP 429)` | Free VT tier allows 4 requests/min. Wait 60 seconds between batches. |
| `PermissionError modifying hosts file` | On Windows run as Administrator; on Linux use `sudo`; inside Docker use the `/api/blocklist/export` endpoint with a local DNS resolver. |
| Docker port conflict | Change `PORT=5000` to another port in `.env` (e.g. `PORT=8080`) and restart. |

---

## 📄 License

MIT License. Created for student cybersecurity labs, SOC training, and defense research.
