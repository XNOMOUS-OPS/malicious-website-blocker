# 🛡️ Malicious Website Blocker

A student cybersecurity project built to protect computers from phishing links, fake websites, and malware domains. It scans URLs using the free **VirusTotal API**, automatically blocks dangerous websites by redirecting them to `127.0.0.1` (DNS/Hosts sinkhole), and writes structured security logs ready for SIEM tools (like Splunk, ELK, or Wazuh).

You can run this project using **Docker** (web dashboard) or as a **Desktop app** (Python Tkinter).

---

## 📌 Project Workflow

Here is the simple step-by-step workflow of how the tool works:

```
[ Enter URL ] 
      │
      ▼
[ Step 1: VirusTotal Scan ] ──► Sends URL to VirusTotal API v3
      │
      ▼
[ Step 2: Verdict Check ]
   ├── Safe / Clean ────────► Displays clean verdict
   └── Malicious / Suspicious
            │
            ▼
[ Step 3: Auto-Block Action ] ──► Adds domain to blocklist / hosts file (127.0.0.1)
            │
            ▼
[ Step 4: Security Log ] ──────► Records event in JSON & CEF format for SIEM
```

---

## ✨ Features & How They Work

### 1. 🔍 VirusTotal Threat Scanner
- **How it works:** When you input a website link, the app calls the VirusTotal v3 API. Over 70 antivirus engines analyze the URL.
- **Result:** Shows how many security vendors flagged the link as malicious, suspicious, or clean.

### 2. 🚫 Automatic & Manual Domain Blocking
- **How it works:** If a site is flagged as dangerous, the tool automatically adds the domain name to the blocklist.
- **Local Sinkhole:** The domain is mapped to `127.0.0.1` (localhost), which stops your browser or any app on your computer from connecting to the dangerous site.

### 3. 🌐 Web SOC Dashboard (Docker Mode)
- **How it works:** A simple web interface running on port `5000`. You can scan links, manage your blocked domains list, export sinkhole files, and watch security logs update live.

### 4. 💻 Desktop Application (Python GUI)
- **How it works:** A classic Tkinter desktop window for quick standalone use without needing Docker.

### 5. 📡 SIEM-Ready Security Logs
- **How it works:** Every scan, block, and unblock action is saved in two formats inside the `logs/` folder:
  - `siem_events.json`: Structured JSON logs for tools like Wazuh, Elastic (ELK), or Graylog.
  - `siem_events.log`: Common Event Format (CEF) logs for Splunk and ArcSight.

---

## 🚀 Quick Setup & Usage

### Option A: Run with Docker (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/XNOMOUS-OPS/malicious-website-blocker.git
   cd malicious-website-blocker
   ```

2. **Add your VirusTotal API key:**
   - Copy `.env.example` to `.env`:
     ```bash
     cp .env.example .env
     ```
   - Open `.env` and paste your free key from [virustotal.com](https://www.virustotal.com):
     ```env
     VT_API_KEY=your_virustotal_api_key_here
     ```

3. **Start the container:**
   ```bash
   docker compose up -d --build
   ```

4. **Open in browser:**
   Go to `http://localhost:5000` to access the web dashboard.

---

### Option B: Run as Desktop App (Local Python)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set your API key:**
   Add your `VT_API_KEY` inside `.env` or set it in your environment.

3. **Run the script:**
   - **Windows** (Run PowerShell or Command Prompt as Administrator):
     ```bash
     python Block_malicious_website.py
     ```
   - **Linux / macOS**:
     ```bash
     sudo python3 Block_malicious_website.py
     ```

---

## 📁 Project Structure

```
├── Block_malicious_website.py   # Desktop GUI application (Tkinter)
├── app.py                       # Web dashboard & REST API server
├── core_blocker.py              # Domain extraction & blocking logic
├── siem_logger.py               # JSON & CEF log generator for SIEM
├── templates/
│   └── index.html               # Web dashboard interface
├── requirements.txt             # Python libraries needed
├── Dockerfile                   # Docker container build instructions
├── docker-compose.yml           # Docker compose file
├── .env.example                 # Example configuration file
└── README.md                    # Project documentation
```

---

## 📜 Example Log Outputs

### JSON Log (`logs/siem_events.json`):
```json
{
  "@timestamp": "2026-04-26T12:00:00.000000+00:00",
  "event": {
    "action": "threat_detected",
    "severity_label": "HIGH"
  },
  "details": {
    "summary": "Malicious domain detected via VirusTotal: phishing-site.xyz",
    "domain": "phishing-site.xyz",
    "malicious_count": 12,
    "verdict": "MALICIOUS"
  }
}
```

### CEF Log (`logs/siem_events.log`):
```text
CEF:0|SecOpsLab|MaliciousWebsiteBlocker|1.2|THREAT_DETECTED|Malicious domain detected: phishing-site.xyz|8|cs_domain=phishing-site.xyz cs_verdict=MALICIOUS
```

---

## 🎯 Summary of Protection

- **Phishing Protection**: Stops users from visiting fake login and scam pages.
- **Malware Prevention**: Cuts off connections to servers known to distribute viruses.
- **DNS Sinkholing**: Safely loops back dangerous network requests locally.
- **Easy Audit Trail**: Keeps a timestamped record of every security event.

---

## 📄 License

MIT License. Developed for student cybersecurity learning and lab practice.
