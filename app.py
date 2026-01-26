from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import time

VT_API_KEY = os.environ.get("VT_API_KEY")

app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"


# -----------------------------
# VirusTotal Scan
# -----------------------------
def scan_with_virustotal(url):
    if not VT_API_KEY:
        return None

    headers = {"x-apikey": VT_API_KEY}

    # 1️⃣ Submit URL
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=15
    )

    if submit.status_code != 200:
        return None

    analysis_id = submit.json()["data"]["id"]

    # 2️⃣ Wait briefly
    time.sleep(3)

    # 3️⃣ Fetch analysis
    analysis = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=15
    )

    if analysis.status_code != 200:
        return None

    stats = analysis.json()["data"]["attributes"]["stats"]

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


# -----------------------------
# Merge Logic (STEP 1)
# -----------------------------
def merge_scores(heuristic_score, vt):
    risk = 0
    reasons = []

    # Heuristic weight (frontend intent)
    if heuristic_score >= 5:
        risk += 40
        reasons.append("Strong phishing indicators (heuristics)")
    elif heuristic_score >= 2:
        risk += 20
        reasons.append("Moderate phishing indicators (heuristics)")

    # VirusTotal weight (reputation)
    if vt:
        if vt["malicious"] > 0:
            risk += 60
            reasons.append("Detected malicious by security engines")
        elif vt["suspicious"] > 0:
            risk += 30
            reasons.append("Flagged suspicious by security engines")

    # Final verdict
    if risk >= 60:
        verdict = "Dangerous"
    elif risk >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    confidence = min(95, max(5, risk))

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk,
        "reasons": reasons or ["No strong indicators detected"]
    }


# -----------------------------
# Analyze Endpoint
# -----------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "")
    heuristic_score = int(data.get("heuristic_score", 0))

    vt_result = scan_with_virustotal(url)
    final = merge_scores(heuristic_score, vt_result)

    return jsonify({
        "backend": "alive",
        "engine": "VirusTotal + Heuristics",
        "url": url,
        "heuristic_score": heuristic_score,
        "virustotal": vt_result,
        "final_verdict": final
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
