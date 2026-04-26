"""
SIEM Logging Module for Malicious Website Blocker
=================================================
Formats and dispatches security events to local log files and remote Syslog/SIEM collectors.
Supports:
  - Structured JSON (compatible with ELK / Wazuh / Graylog / Splunk JSON ingest)
  - Common Event Format - CEF (ArcSight / QRadar / Splunk CEF)
  - Remote Syslog (RFC 3164 / RFC 5424 over UDP/TCP)
"""

import os
import json
import socket
import threading
from datetime import datetime, timezone

LOG_DIR = os.getenv("LOG_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"))
JSON_LOG_FILE = os.path.join(LOG_DIR, "siem_events.json")
CEF_LOG_FILE = os.path.join(LOG_DIR, "siem_events.log")
LEGACY_LOG_FILE = os.path.join(LOG_DIR, "log.txt")

# Remote Syslog / SIEM Forwarder Configuration
SIEM_SYSLOG_HOST = os.getenv("SIEM_SYSLOG_HOST", "")
SIEM_SYSLOG_PORT = int(os.getenv("SIEM_SYSLOG_PORT", "514"))
SIEM_SYSLOG_PROTOCOL = os.getenv("SIEM_SYSLOG_PROTOCOL", "UDP").upper()

_lock = threading.Lock()

def _ensure_log_dir():
    """Ensure the log directory exists."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)

def _send_syslog_message(message: str):
    """Sends a raw syslog message over UDP/TCP if configured."""
    if not SIEM_SYSLOG_HOST:
        return

    try:
        if SIEM_SYSLOG_PROTOCOL == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT))
                sock.sendall((message + "\n").encode("utf-8"))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(message.encode("utf-8"), (SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT))
    except Exception as e:
        # Avoid crashing application if remote SIEM listener is unreachable
        pass

def format_cef(event_id: str, event_name: str, severity: int, extension: dict) -> str:
    """
    Constructs an ArcSight Common Event Format (CEF) string.
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    vendor = "SecOpsLab"
    product = "MaliciousWebsiteBlocker"
    version = "1.2"
    
    # Format extension key=value pairs
    ext_parts = []
    for k, v in extension.items():
        val_str = str(v).replace("\\", "\\\\").replace("=", "\\=")
        ext_parts.append(f"{k}={val_str}")
    ext_str = " ".join(ext_parts)
    
    return f"CEF:0|{vendor}|{product}|{version}|{event_id}|{event_name}|{severity}|{ext_str}"

def emit_event(event_type: str, severity_level: str, details: dict):
    """
    Main entrypoint to emit a security event.
    Writes structured JSON and CEF logs, updates legacy log, and optionally forwards to remote SIEM.
    """
    _ensure_log_dir()
    
    now_utc = datetime.now(timezone.utc)
    timestamp_iso = now_utc.isoformat()
    
    # Severity mapping for CEF (0-10)
    sev_map = {
        "INFORMATIONAL": 1,
        "LOW": 3,
        "MEDIUM": 5,
        "HIGH": 8,
        "CRITICAL": 10
    }
    cef_severity = sev_map.get(severity_level.upper(), 1)
    
    event_payload = {
        "@timestamp": timestamp_iso,
        "event": {
            "dataset": "malicious_website_blocker.events",
            "action": event_type.lower(),
            "category": "threat-intel",
            "severity": cef_severity,
            "severity_label": severity_level.upper()
        },
        "details": details
    }
    
    cef_extension = {
        "rt": int(now_utc.timestamp() * 1000),
        "cat": event_type,
        "sev": severity_level.upper(),
        **{f"cs_{k}" if isinstance(v, str) else f"cn_{k}": v for k, v in details.items() if not isinstance(v, (dict, list))}
    }
    
    cef_string = format_cef(
        event_id=event_type,
        event_name=details.get("summary", event_type),
        severity=cef_severity,
        extension=cef_extension
    )
    
    with _lock:
        try:
            # 1. Structured JSON log (one JSON object per line)
            with open(JSON_LOG_FILE, "a", encoding="utf-8") as f_json:
                f_json.write(json.dumps(event_payload) + "\n")
            
            # 2. Standard CEF log
            with open(CEF_LOG_FILE, "a", encoding="utf-8") as f_cef:
                f_cef.write(cef_string + "\n")
                
            # 3. Legacy plaintext log for desktop compatibility
            with open(LEGACY_LOG_FILE, "a", encoding="utf-8") as f_leg:
                f_leg.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {details.get('summary', event_type)}\n")
        except Exception as e:
            print(f"[SIEM Logger Error] Failed to write logs: {e}")
            
    # Forward over network to SIEM listener
    _send_syslog_message(cef_string)

def log_scan_event(url: str, domain: str, vt_stats: dict, is_malicious: bool):
    """Logs a URL Threat Intelligence Scan event."""
    malicious_count = vt_stats.get("malicious", 0)
    suspicious_count = vt_stats.get("suspicious", 0)
    harmless_count = vt_stats.get("harmless", 0)
    undetected_count = vt_stats.get("undetected", 0)
    
    if is_malicious:
        severity = "HIGH" if malicious_count > 2 else "MEDIUM"
        event_type = "THREAT_DETECTED"
        summary = f"Malicious domain detected via VirusTotal: {domain} (malicious={malicious_count}, suspicious={suspicious_count})"
    else:
        severity = "INFORMATIONAL"
        event_type = "URL_SCAN_CLEAN"
        summary = f"VirusTotal scan clean for: {domain}"
        
    details = {
        "summary": summary,
        "url": url,
        "domain": domain,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count": harmless_count,
        "undetected_count": undetected_count,
        "verdict": "MALICIOUS" if is_malicious else "CLEAN"
    }
    emit_event(event_type, severity, details)

def log_block_event(domain: str, reason: str = "Manual Block", is_auto: bool = False):
    """Logs a domain block enforcement event."""
    event_type = "AUTO_BLOCKED" if is_auto else "DOMAIN_BLOCKED"
    severity = "HIGH" if is_auto else "LOW"
    details = {
        "summary": f"{'Auto-blocked' if is_auto else 'Blocked'}: {domain} (Reason: {reason})",
        "domain": domain,
        "reason": reason,
        "action": "BLOCK_REDIRECT_127.0.0.1"
    }
    emit_event(event_type, severity, details)

def log_unblock_event(domain: str, reason: str = "Manual Unblock"):
    """Logs a domain unblock event."""
    details = {
        "summary": f"Unblocked: {domain} (Reason: {reason})",
        "domain": domain,
        "reason": reason,
        "action": "REMOVE_BLOCK_ENTRY"
    }
    emit_event("DOMAIN_UNBLOCKED", "INFORMATIONAL", details)

def get_recent_events(limit: int = 50) -> list:
    """Reads the most recent JSON SIEM events for dashboard viewing."""
    if not os.path.exists(JSON_LOG_FILE):
        return []
    
    events = []
    try:
        with open(JSON_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in reversed(lines[-limit:]):
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"[SIEM Logger Error] Failed to read events: {e}")
    return events
