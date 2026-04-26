# 🛡️ Malicious Website Blocker

A Python desktop application that lets you **block, unblock, and scan websites** for malicious content — with VirusTotal integration and hosts-file-based blocking.

---

## 📋 Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [How to Use](#how-to-use)
- [How It Works](#how-it-works)
- [Logging](#logging)
- [Limitations & Notes](#limitations--notes)
- [Troubleshooting](#troubleshooting)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🚫 Block Website | Adds a domain to your system `hosts` file, redirecting it to `127.0.0.1` |
| ✅ Unblock Website | Removes the domain from your `hosts` file |
| 🔬 Scan with VirusTotal | Submits the URL to VirusTotal API and auto-blocks if flagged malicious/suspicious |
| 📋 View Blocked Sites | Live list of all currently blocked sites managed by this app |
| 📝 Logging | Every block/unblock action is timestamped and saved to `log.txt` |

---

## 🖥️ Requirements

- **Python** 3.7 or higher
- **Operating System**: Windows, macOS, or Linux
- **Admin/Root privileges** (required to edit the hosts file)
- A **VirusTotal API Key** (free tier available at [virustotal.com](https://www.virustotal.com))

### Python Dependencies

Install required packages with:

```bash
pip install requests
```

> `tkinter` is included in the Python standard library. If it's missing on Linux, install it with:
> ```bash
> sudo apt install python3-tk
> ```

---

## 🚀 Installation

1. **Clone or download** this repository:
   ```bash
   git clone https://github.com/XNOMOUS-OPS/malicious-website-blocker.git
   cd malicious-website-blocker
   ```

2. **Install dependencies**:
   ```bash
   pip install requests
   ```

3. **Add your VirusTotal API key** (see [Configuration](#configuration) below).

4. **Run the app**:

   - **Windows** — Right-click the script and choose *Run as Administrator*, or run from an elevated command prompt:
     ```bash
     python Block_malicious_website.py
     ```
     > On Windows, the app will automatically prompt for administrator privileges via a UAC dialog.

   - **macOS / Linux** — Run with `sudo`:
     ```bash
     sudo python3 Block_malicious_website.py
     ```

---

## ⚙️ Configuration

Open `Block_malicious_website.py` and replace the placeholder with your VirusTotal API key:

```python
VT_API_KEY = "YOUR_API_KEY"   # <-- Replace this
```

To get a free API key:
1. Sign up at [https://www.virustotal.com](https://www.virustotal.com)
2. Go to your profile → **API Key**
3. Copy and paste it into the script

---

## 📖 How to Use

### 1. Block a Website Manually

1. Launch the application.
2. Enter a URL in the **"Website URL"** field (e.g., `http://malicious-site.com` or just `malicious-site.com`).
3. Click **"Block Website"**.
4. The domain is immediately added to your hosts file and appears in the **Currently Blocked Sites** list.

### 2. Unblock a Website

1. Enter the URL of a previously blocked site in the **"Website URL"** field.
2. Click **"Unblock Website"**.
3. The domain is removed from your hosts file.

### 3. Scan with VirusTotal

1. Enter any URL in the **"Website URL"** field.
2. Click **"Scan with VirusTotal"**.
3. A dialog box will inform you that scanning has started (takes ~20 seconds).
4. Results are displayed showing detection counts (malicious, suspicious, harmless, etc.).
5. **If the site is flagged**, it is **automatically blocked** and logged.
6. **If the site is clean**, you'll see a ✅ confirmation.

### 4. View Blocked Sites

The **"Currently Blocked Sites"** listbox at the bottom of the window shows all sites currently blocked via this app (entries pointing to `127.0.0.1` in the hosts file). This list refreshes automatically after every block/unblock action.

---

## ⚙️ How It Works

```
User enters URL
      │
      ▼
Domain extracted from URL
      │
      ├──[Block]──► Appends "127.0.0.1  domain" to hosts file
      │
      ├──[Unblock]──► Removes matching lines from hosts file
      │
      └──[VT Scan]──► POST to VirusTotal API
                           │
                           ▼
                    Poll for results (up to 5 times, ~20s)
                           │
                    ┌──────┴──────┐
               Malicious?        Clean?
                    │                │
               Auto-block       Show ✅ message
               + log action
```

**Hosts file blocking** works by redirecting the domain to `127.0.0.1` (your own machine), so the browser can never reach the real server.

| OS | Hosts File Location |
|---|---|
| Windows | `C:\Windows\System32\drivers\etc\hosts` |
| macOS | `/etc/hosts` |
| Linux | `/etc/hosts` |

---

## 📝 Logging

Every action is automatically recorded to **`log.txt`** in the same directory as the script.

Example log entries:
```
[2025-04-26 10:15:32] Blocked: malicious-site.com
[2025-04-26 10:18:45] Auto-blocked: phishing-example.com due to VirusTotal verdict (malicious:3, suspicious:1)
[2025-04-26 10:22:10] Unblocked: malicious-site.com
```

---

## ⚠️ Limitations & Notes

- **Admin rights are mandatory.** The hosts file is a protected system file. Without elevated privileges, all write operations will fail.
- **Browser caching**: After blocking a site, you may need to clear your browser's DNS cache or restart the browser for the block to take effect.
- **DNS cache flush** (recommended after blocking):
  - Windows: `ipconfig /flushdns`
  - macOS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
  - Linux: `sudo systemd-resolve --flush-caches`
- **VirusTotal free tier** is limited to 4 requests/minute. Scanning too many URLs rapidly may result in API errors.
- The VirusTotal scan polls up to **5 times with 4-second intervals** (~20 seconds total). If the scan doesn't complete in time, a timeout message is shown.
- This app only blocks sites **at the system level** — it does not inspect HTTPS traffic or act as a firewall.

---

## 🔧 Troubleshooting

| Issue | Solution |
|---|---|
| `Permission Error` on block/unblock | Run the script as Administrator (Windows) or with `sudo` (macOS/Linux) |
| `tkinter` not found | Install via `sudo apt install python3-tk` (Linux) |
| VirusTotal scan times out | The site may be newly submitted; try again after a moment |
| `Network/API Error` | Check your internet connection and verify your `VT_API_KEY` is correct |
| Blocked site still loads in browser | Flush DNS cache and restart the browser |
| Site not appearing in blocked list | Ensure the URL entered matches the previously blocked domain exactly |

---

## 📄 License

This project is for educational purposes. Use responsibly and only on systems you own or have explicit permission to manage.
