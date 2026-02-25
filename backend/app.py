from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import time
import re
from urllib.parse import urlparse

VT_API_KEY = os.environ.get("VT_API_KEY")

app = Flask(__name__)
CORS(app)

# =====================================================
# CONFIG
# =====================================================

SUSPICIOUS_TLDS = [".tk", ".xyz", ".top", ".gq", ".ml", ".cf", ".click", ".support"]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "password", "bank", "wallet", "urgent", "alert",
    "suspended", "bonus", "reward", "claim"
]

BRAND_KEYWORDS = [
    "paypal", "appleid", "google", "microsoft",
    "amazon", "netflix", "bank", "hdfc", "sbi"
]

# =====================================================
# HEALTH CHECK
# =====================================================

@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"


# =====================================================
# BASIC HEURISTIC ENGINE (Backend Version)
# =====================================================

def calculate_heuristic_score(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    host = parsed.netloc.lower()

    # Raw IP
    if re.match(r"\d+\.\d+\.\d+\.\d+", host):
        score += 3
        reasons.append("Uses raw IP address")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 2
            reasons.append(f"Suspicious TLD ({tld})")

    # Phishing keywords
    for word in PHISHING_KEYWORDS:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains phishing keyword: {word}")

    # Brand impersonation
    for brand in BRAND_KEYWORDS:
        if brand in url.lower():
            score += 1
            reasons.append(f"Impersonates brand: {brand}")

    return score, reasons


# =====================================================
# VIRUSTOTAL SCAN
# =====================================================

def scan_with_virustotal(url):
    if not VT_API_KEY:
        return None

    headers = {"x-apikey": VT_API_KEY}

    try:
        # Submit URL
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )

        if submit.status_code != 200:
            return None

        analysis_id = submit.json()["data"]["id"]

        # Wait briefly
        time.sleep(3)

        # Get analysis
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

    except Exception:
        return None


# =====================================================
# MERGE LOGIC (HEURISTICS + VT)
# =====================================================

def merge_scores(heuristic_score, heuristic_reasons, vt):
    risk = 0
    reasons = []

    # Heuristic Weight
    if heuristic_score >= 5:
        risk += 40
        reasons.append("Strong phishing indicators (heuristics)")
    elif heuristic_score >= 2:
        risk += 20
        reasons.append("Moderate phishing indicators (heuristics)")

    reasons.extend(heuristic_reasons)

    # VirusTotal Weight
    if vt:
        if vt["malicious"] > 0:
            risk += 60
            reasons.append("Detected malicious by security engines")
        elif vt["suspicious"] > 0:
            risk += 30
            reasons.append("Flagged suspicious by security engines")

    # Final Verdict
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
        "reasons": reasons if reasons else ["No strong indicators detected"]
    }


# =====================================================
# ANALYZE ENDPOINT
# =====================================================

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    heuristic_score, heuristic_reasons = calculate_heuristic_score(url)
    vt_result = scan_with_virustotal(url)

    final = merge_scores(heuristic_score, heuristic_reasons, vt_result)

    return jsonify({
        "backend": "alive",
        "engine": "Heuristics + VirusTotal",
        "url": url,
        "heuristic_score": heuristic_score,
        "virustotal": vt_result,
        "final_verdict": final
    })


# =====================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)