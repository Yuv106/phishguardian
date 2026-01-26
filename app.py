from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import time

# ================= CONFIG =================

VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

app = Flask(__name__)
CORS(app)

# ================= HEALTH =================

@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"

# ================= VIRUSTOTAL =================

def scan_with_virustotal(url):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}

    headers = {"x-apikey": VT_API_KEY}

    # 1️⃣ Submit URL
    submit = requests.post(
        f"{VT_BASE}/urls",
        headers=headers,
        data={"url": url},
        timeout=15
    )

    if submit.status_code != 200:
        return {"error": "VirusTotal submit failed"}

    analysis_id = submit.json()["data"]["id"]

    # 2️⃣ Wait briefly (VT async)
    time.sleep(3)

    # 3️⃣ Fetch results
    report = requests.get(
        f"{VT_BASE}/analyses/{analysis_id}",
        headers=headers,
        timeout=15
    )

    if report.status_code != 200:
        return {"error": "VirusTotal fetch failed"}

    stats = (
        report.json()
        .get("data", {})
        .get("attributes", {})
        .get("stats", {})
    )

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }

# ================= VERDICT LOGIC =================

def interpret_vt(stats):
    """
    Convert raw VT numbers into a risk level
    """
    if not stats:
        return "unknown"

    mal = stats.get("malicious", 0)
    susp = stats.get("suspicious", 0)

    if mal >= 3:
        return "high"
    if mal >= 1 or susp >= 2:
        return "medium"
    if mal == 0 and susp == 0:
        return "unknown"

    return "low"

def compute_confidence(heuristic_score, vt_stats):
    """
    Confidence = weighted blend (heuristics + VT)
    """
    mal = vt_stats.get("malicious", 0)
    susp = vt_stats.get("suspicious", 0)

    confidence = (
        heuristic_score * 12 +
        mal * 20 +
        susp * 10
    )

    # Clamp to sane range
    return max(15, min(95, confidence))

def final_verdict(heuristic_score, vt_stats):
    vt_level = interpret_vt(vt_stats)

    if vt_level == "high":
        verdict = "Dangerous"
        reason = "Detected by multiple security engines"
    elif vt_level == "medium":
        verdict = "Suspicious"
        reason = "Flagged by security engines"
    elif vt_level == "unknown" and heuristic_score >= 6:
        verdict = "Dangerous"
        reason = "Strong phishing indicators with unknown reputation"
    elif vt_level == "unknown" and heuristic_score >= 3:
        verdict = "Suspicious"
        reason = "Phishing indicators detected"
    else:
        verdict = "Safe"
        reason = "No strong indicators detected"

    confidence = compute_confidence(heuristic_score, vt_stats)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason
    }

# ================= ANALYZE =================

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json() or {}
    url = data.get("url", "").strip()

    # ⛳ TEMP heuristic score
    # (Frontend already computes real one; this keeps backend compatible)
    heuristic_score = data.get("heuristic_score", 1)

    vt_stats = scan_with_virustotal(url)
    vt_stats = vt_stats if isinstance(vt_stats, dict) else {}

    final = final_verdict(heuristic_score, vt_stats)

    return jsonify({
        "backend": "alive",
        "engine": "VirusTotal",
        "url": url,
        "virustotal": vt_stats,
        "final_verdict": final
    })

# ================= RUN =================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
