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

# =============================
# CONFIG
# =============================

SUSPICIOUS_TLDS = [
    ".tk", ".xyz", ".top", ".gq", ".ml", ".cf", ".click", ".support"
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "password", "bank", "wallet", "urgent", "alert",
    "suspended", "bonus", "reward", "claim"
]

BRAND_KEYWORDS = [
    "paypal", "appleid", "google", "microsoft",
    "amazon", "netflix", "bank", "hdfc", "sbi"
]

# =============================
# HEALTH
# =============================

@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"

# =============================
# HEURISTIC ENGINE
# =============================

def analyze_heuristics(url):
    risk = 0
    reasons = []

    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()

    full_url = url.lower()

    # 1️⃣ Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            risk += 20
            reasons.append(f"Suspicious TLD detected ({tld})")
            break

    # 2️⃣ IP address URL
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        risk += 25
        reasons.append("URL uses raw IP address")

    # 3️⃣ Punycode detection
    if "xn--" in host:
        risk += 25
        reasons.append("Punycode domain detected")

    # 4️⃣ Excessive hyphens
    if host.count("-") >= 2:
        risk += 15
        reasons.append("Excessive hyphens in domain")

    # 5️⃣ Phishing keywords
    keyword_hits = [k for k in PHISHING_KEYWORDS if k in full_url]
    if keyword_hits:
        risk += 20
        reasons.append("Phishing keywords detected")

    # 6️⃣ Brand impersonation
    brand_hits = [b for b in BRAND_KEYWORDS if b in host]
    if brand_hits and any(k in full_url for k in PHISHING_KEYWORDS):
        risk += 30
        reasons.append("Brand impersonation suspected")

    # 7️⃣ Excessive subdomains
    if host.count(".") >= 3:
        risk += 10
        reasons.append("Excessive subdomains")

    # 8️⃣ Long URL
    if len(url) > 120:
        risk += 10
        reasons.append("Unusually long URL")

    return risk, reasons

# =============================
# VIRUSTOTAL
# =============================

def scan_with_virustotal(url):
    if not VT_API_KEY:
        return None

    headers = {"x-apikey": VT_API_KEY}

    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=15
    )

    if submit.status_code != 200:
        return None

    analysis_id = submit.json()["data"]["id"]

    time.sleep(3)

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

# =============================
# MERGE ENGINE
# =============================

def merge_results(heuristic_risk, heuristic_reasons, vt_stats):
    risk = heuristic_risk
    reasons = list(heuristic_reasons)

    if vt_stats:
        if vt_stats["malicious"] >= 2:
            risk += 60
            reasons.append("Detected malicious by multiple engines")
        elif vt_stats["malicious"] >= 1:
            risk += 40
            reasons.append("Detected malicious by security engine")
        elif vt_stats["suspicious"] >= 1:
            risk += 20
            reasons.append("Flagged suspicious by security engine")

    if risk >= 70:
        verdict = "Dangerous"
    elif risk >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    confidence = min(95, max(5, risk))

    return verdict, confidence, reasons

# =============================
# ANALYZE ENDPOINT
# =============================

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "")

    heuristic_risk, heuristic_reasons = analyze_heuristics(url)
    vt_stats = scan_with_virustotal(url)

    verdict, confidence, reasons = merge_results(
        heuristic_risk,
        heuristic_reasons,
        vt_stats
    )

    return jsonify({
        "backend": "alive",
        "engine": "Heuristics + VirusTotal",
        "url": url,
        "heuristic_risk": heuristic_risk,
        "virustotal": vt_stats,
        "final_verdict": {
            "verdict": verdict,
            "confidence": confidence,
            "reasons": reasons or ["No strong indicators detected"]
        }
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)