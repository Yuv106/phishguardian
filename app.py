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

# ================= VT SCAN =================
def scan_with_virustotal(url: str):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}

    headers = {
        "x-apikey": VT_API_KEY
    }

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

    # 2️⃣ Wait briefly (VT is async)
    time.sleep(3)

    # 3️⃣ Fetch analysis result
    analysis = requests.get(
        f"{VT_BASE}/analyses/{analysis_id}",
        headers=headers,
        timeout=15
    )

    if analysis.status_code != 200:
        return {"error": "VirusTotal analysis fetch failed"}

    stats = analysis.json() \
        .get("data", {}) \
        .get("attributes", {}) \
        .get("stats", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }

# ================= VT VERDICT =================
def vt_verdict_and_confidence(vt):
    """
    VirusTotal OVERRIDES everything.
    This mirrors real security products.
    """

    if not vt or "error" in vt:
        return {
            "verdict": "Unknown",
            "confidence": 0,
            "reason": "VirusTotal unavailable"
        }

    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)

    if malicious > 0:
        return {
            "verdict": "Dangerous",
            "confidence": min(98, 90 + malicious * 2),
            "reason": f"Detected by {malicious} security engines"
        }

    if suspicious > 0:
        return {
            "verdict": "Suspicious",
            "confidence": min(90, 70 + suspicious * 4),
            "reason": f"Flagged suspicious by {suspicious} engines"
        }

    return {
        "verdict": "Safe",
        "confidence": 55,
        "reason": "No engines flagged this URL"
    }

# ================= ANALYZE =================
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL missing"}), 400

    vt_result = scan_with_virustotal(url)
    vt_final = vt_verdict_and_confidence(vt_result)

    return jsonify({
        "url": url,
        "backend": "alive",
        "engine": "VirusTotal",
        "virustotal": vt_result,
        "final_verdict": vt_final
    })

# ================= RUN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
