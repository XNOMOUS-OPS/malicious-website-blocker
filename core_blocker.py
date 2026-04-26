"""
Core Detection, Threat Intel & Blocking Engine
=============================================
Provides URL extraction, VirusTotal v3 API scanning, blocklist management,
and hosts file synchronization with integrated SIEM auditing.
"""

import os
import time
import platform
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

import siem_logger

# Load environment variables if .env exists
load_dotenv()

DATA_DIR = os.getenv("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
BLOCKED_DOMAINS_FILE = os.path.join(DATA_DIR, "blocked_domains.txt")
REDIRECT_IP = os.getenv("REDIRECT_IP", "127.0.0.1")

VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_API_KEY")
VT_HEADERS = {"x-apikey": VT_API_KEY}


def _ensure_data_dir():
    """Ensure data storage directory exists."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)


def get_hosts_path() -> str:
    """Returns path to the system hosts file based on OS or custom path."""
    custom_path = os.getenv("HOSTS_FILE_PATH")
    if custom_path:
        return custom_path
        
    os_name = platform.system()
    if os_name == "Windows":
        return r"C:\Windows\System32\drivers\etc\hosts"
    elif os_name in ["Linux", "Darwin"]:
        return "/etc/hosts"
    else:
        return "/etc/hosts"


def extract_domain(url: str) -> str:
    """Extracts clean domain/hostname from a given URL or domain string."""
    if not url or not url.strip():
        return ""
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url
    try:
        parsed = urlparse(clean_url)
        host = parsed.hostname
        if host:
            return host.lower()
        return clean_url.split("/")[0].lower()
    except Exception:
        return url.strip().lower()


def vt_scan_url(url: str, api_key: str = None) -> dict:
    """
    Submits a URL to VirusTotal v3 API for analysis and polls for completion.
    Returns detection statistics dict or error information.
    """
    key = api_key or os.getenv("VT_API_KEY", VT_API_KEY)
    if not key or key == "YOUR_API_KEY":
        return {
            "error": "VirusTotal API key is missing. Please set VT_API_KEY in .env or your environment variables."
        }

    headers = {"x-apikey": key}

    try:
        # Submit URL for scanning
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if response.status_code == 401:
            return {"error": "Invalid VirusTotal API Key (HTTP 401)."}
        if response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded (HTTP 429). Please wait before scanning again."}

        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        # Poll for completion (up to 5 attempts, ~20 seconds)
        for _ in range(5):
            time.sleep(4)
            r = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            attributes = data.get("attributes", {})
            
            if attributes.get("status") == "completed":
                stats = attributes.get("stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "status": "completed"
                }

        return {"error": "Scan timed out waiting for VirusTotal verdict."}

    except requests.exceptions.RequestException as e:
        return {"error": f"Network/API Error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected scan error: {str(e)}"}


def get_blocked_domains() -> list:
    """Retrieves list of currently blocked domains from data file and hosts file."""
    _ensure_data_dir()
    domains = set()

    # 1. Read from persistent file
    if os.path.exists(BLOCKED_DOMAINS_FILE):
        try:
            with open(BLOCKED_DOMAINS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    dom = line.strip()
                    if dom and not dom.startswith("#"):
                        domains.add(dom.lower())
        except Exception:
            pass

    # 2. Read from system hosts file if accessible
    try:
        hosts_path = get_hosts_path()
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if line_str.startswith(REDIRECT_IP):
                        parts = line_str.split()
                        if len(parts) >= 2:
                            domains.add(parts[1].lower())
    except Exception:
        pass

    return sorted(list(domains))


def save_blocked_domains_file(domains: list):
    """Saves the current domain list to the internal storage file."""
    _ensure_data_dir()
    with open(BLOCKED_DOMAINS_FILE, "w", encoding="utf-8") as f:
        f.write("# Malicious Website Blocker - Managed Domains\n")
        for d in sorted(list(set(domains))):
            f.write(f"{d}\n")


def block_domain(raw_url: str, reason: str = "Manual Block", is_auto: bool = False) -> tuple[bool, str]:
    """
    Blocks a domain by updating the internal database and attempting to update the hosts file.
    Emits a SIEM security event.
    """
    domain = extract_domain(raw_url)
    if not domain:
        return False, "Invalid URL or domain provided."

    current_domains = set(get_blocked_domains())
    if domain in current_domains:
        return True, f"Domain '{domain}' is already blocked."

    current_domains.add(domain)
    save_blocked_domains_file(list(current_domains))

    # Attempt to write to system hosts file
    hosts_updated = False
    try:
        hosts_path = get_hosts_path()
        with open(hosts_path, "a", encoding="utf-8") as file:
            file.write(f"\n{REDIRECT_IP}\t{domain}")
        hosts_updated = True
    except PermissionError:
        # Expected if running without admin or inside isolated Docker container
        pass
    except Exception:
        pass

    # SIEM Logging
    siem_logger.log_block_event(domain, reason=reason, is_auto=is_auto)

    msg = f"Successfully blocked '{domain}'."
    if not hosts_updated and platform.system() == "Windows":
        msg += " (Note: Run as Administrator to write to C:\\Windows\\System32\\drivers\\etc\\hosts directly)"
    return True, msg


def unblock_domain(raw_url: str, reason: str = "Manual Unblock") -> tuple[bool, str]:
    """
    Removes a domain from the blocklist and attempts to clean the system hosts file.
    Emits a SIEM audit event.
    """
    domain = extract_domain(raw_url)
    if not domain:
        return False, "Invalid URL or domain provided."

    current_domains = set(get_blocked_domains())
    if domain not in current_domains:
        return False, f"Domain '{domain}' is not in the active blocklist."

    current_domains.discard(domain)
    save_blocked_domains_file(list(current_domains))

    # Attempt to clean hosts file
    try:
        hosts_path = get_hosts_path()
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
            new_lines = [line for line in lines if not (line.strip().startswith(REDIRECT_IP) and domain in line)]
            with open(hosts_path, "w", encoding="utf-8") as file:
                file.writelines(new_lines)
    except Exception:
        pass

    # SIEM Logging
    siem_logger.log_unblock_event(domain, reason=reason)
    return True, f"Successfully unblocked '{domain}'."


def generate_sinkhole_blocklist() -> str:
    """Generates standard hosts/sinkhole format text for Pi-hole, AdGuard, or /etc/hosts."""
    domains = get_blocked_domains()
    lines = [
        "# Malicious Website Blocker - Sinkhole Blocklist",
        f"# Total Blocked Domains: {len(domains)}",
        f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        ""
    ]
    for dom in domains:
        lines.append(f"{REDIRECT_IP} {dom}")
    return "\n".join(lines)
