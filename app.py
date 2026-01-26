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

def scan_with_virustotal(url):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}

    headers = {
        "x-apikey": VT_API_KEY
    }

    # 1️⃣ Submit URL
    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=15
    )

    if submit_response.status_code != 200:
        return {"error": "VirusTotal request failed"}

    analysis_id = submit_response.json()["data"]["id"]

    # 2️⃣ Wait briefly
    time.sleep(3)

    # 3️⃣ Fetch analysis
    analysis_response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=15
    )

    if analysis_response.status_code != 200:
        return None

    data = analysis_response.json()
    stats = data.get("data", {}).get("attributes", {}).get("stats", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "")

    vt_result = scan_with_virustotal(url)

    return jsonify({
        "url": url,
        "backend": "alive",
        "virustotal": vt_result
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
