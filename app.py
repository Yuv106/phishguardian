from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import time

# ================= CONFIG =================
VT_API_KEY = os.environ.get("VT_API_KEY")

app = Flask(__name__)
CORS(app)

# ================= HEALTH CHECK =================
@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"

# ================= VIRUSTOTAL CORE =================
def scan_with_virustotal(url):
    """
    Submits a URL to VirusTotal and returns engine statistics.
    """
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}

    headers = {
        "x-apikey": VT_API_KEY
    }

    # 1️⃣ Submit URL to VirusTotal
    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=15
    )

    if submit_response.status_code != 200:
        return {"error": "VirusTotal submit failed"}

    analysis_id = submit_response.json()["data"]["id"]

    # 2️⃣ Wait briefly for analysis to complete
    time.sleep(3)

    # 3️⃣ Fetch analysis results
    analysis_response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=15
    )

    if analysis_response.status_code != 200:
        return {"error": "VirusTotal analysis fetch failed"}

    stats = (
        analysis_response
        .json()
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

# ================= VT INTERPRETATION (NEW) =================
def vt_verdict(stats):
    """
    Converts VirusTotal stats into a verdict + confidence.
    """
    if not stats or "error" in stats:
        return {
            "verdict": "unknown",
            "confidence": 0
        }

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    # Strong malicious signal
    if malicious >= 3:
        return {
            "verdict": "dangerous",
            "confidence": 95
        }

    # Medium signal
    if malicious >= 1 or suspicious >= 2:
        return {
            "verdict": "suspicious",
            "confidence": 75
        }

    # Clean but never 100%
    return {
        "verdict": "clean",
        "confidence": 40
    }

# ================= MAIN ANALYZE API =================
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "")

    vt_stats = scan_with_virustotal(url)
    vt_result = vt_verdict(vt_stats)

    return jsonify({
        "url": url,
        "backend": "alive",
        "virustotal": vt_stats,
        "vt_verdict": vt_result["verdict"],
        "vt_confidence": vt_result["confidence"]
    })

# ================= ENTRY POINT =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
