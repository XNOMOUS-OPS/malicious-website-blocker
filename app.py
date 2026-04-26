"""
Malicious Website Blocker - Web Dashboard & SIEM API
===================================================
Flask-based SOC analyst dashboard and REST API designed for Docker container execution.
"""

import os
from flask import Flask, render_template, request, jsonify, Response
from dotenv import load_dotenv

import core_blocker
import siem_logger

load_dotenv()

app = Flask(__name__)

PORT = int(os.getenv("PORT", "5000"))
HOST = os.getenv("HOST", "0.0.0.0")


@app.route("/")
def index():
    """Renders the main SOC analyst triage dashboard."""
    vt_key = os.getenv("VT_API_KEY", "")
    has_api_key = bool(vt_key and vt_key != "YOUR_API_KEY")
    return render_template("index.html", has_api_key=has_api_key)


@app.route("/api/status", methods=["GET"])
def api_status():
    """Returns application status and summary metrics."""
    blocked = core_blocker.get_blocked_domains()
    vt_key = os.getenv("VT_API_KEY", "")
    return jsonify({
        "status": "online",
        "service": "Malicious Website Blocker & SIEM Threat Intel Hub",
        "api_key_configured": bool(vt_key and vt_key != "YOUR_API_KEY"),
        "total_blocked": len(blocked),
        "syslog_forwarding": bool(siem_logger.SIEM_SYSLOG_HOST)
    })


@app.route("/api/blocklist", methods=["GET"])
def api_get_blocklist():
    """Returns the list of currently blocked domains."""
    return jsonify({
        "blocked_domains": core_blocker.get_blocked_domains()
    })


@app.route("/api/blocklist/export", methods=["GET"])
def api_export_blocklist():
    """Exports blocklist in standard hosts / DNS sinkhole format."""
    content = core_blocker.generate_sinkhole_blocklist()
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=hosts_sinkhole.txt"}
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Scans a URL with VirusTotal and auto-blocks if flagged malicious."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"success": False, "error": "URL parameter is required."}), 400

    domain = core_blocker.extract_domain(url)
    stats = core_blocker.vt_scan_url(url)
    
    if "error" in stats:
        return jsonify({"success": False, "error": stats["error"]}), 400

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    is_threat = (malicious > 0 or suspicious > 0)
    
    auto_blocked = False
    if is_threat:
        core_blocker.block_domain(
            url,
            reason=f"VirusTotal Detection (Malicious: {malicious}, Suspicious: {suspicious})",
            is_auto=True
        )
        auto_blocked = True

    # Log SIEM event
    siem_logger.log_scan_event(url, domain, stats, is_threat)

    return jsonify({
        "success": True,
        "url": url,
        "domain": domain,
        "stats": stats,
        "is_threat": is_threat,
        "auto_blocked": auto_blocked,
        "verdict": "MALICIOUS" if is_threat else "CLEAN"
    })


@app.route("/api/block", methods=["POST"])
def api_block():
    """Manually blocks a domain/URL."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    reason = data.get("reason", "Manual Block via Web API")
    
    if not url:
        return jsonify({"success": False, "error": "URL or domain is required."}), 400

    success, message = core_blocker.block_domain(url, reason=reason, is_auto=False)
    return jsonify({
        "success": success,
        "message": message,
        "domain": core_blocker.extract_domain(url)
    })


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    """Unblocks a domain/URL."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    reason = data.get("reason", "Manual Unblock via Web API")
    
    if not url:
        return jsonify({"success": False, "error": "URL or domain is required."}), 400

    success, message = core_blocker.unblock_domain(url, reason=reason)
    return jsonify({
        "success": success,
        "message": message,
        "domain": core_blocker.extract_domain(url)
    })


@app.route("/api/events", methods=["GET"])
def api_get_events():
    """Returns recent structured JSON SIEM security events."""
    limit = int(request.args.get("limit", 50))
    events = siem_logger.get_recent_events(limit=limit)
    return jsonify({"events": events, "count": len(events)})


@app.route("/api/events/cef", methods=["GET"])
def api_get_cef_events():
    """Returns raw CEF logs for SIEM ingestion."""
    if not os.path.exists(siem_logger.CEF_LOG_FILE):
        return Response("", mimetype="text/plain")
    with open(siem_logger.CEF_LOG_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    return Response(content, mimetype="text/plain")


if __name__ == "__main__":
    print(f"[*] Starting Malicious Website Blocker Web Service on {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)
