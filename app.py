from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import time
import re
import base64
from urllib.parse import urlparse

VT_API_KEY = os.environ.get("VT_API_KEY")

app = Flask(__name__)
CORS(app)

# =============================
# CONFIG
# =============================

# High-risk TLDs frequently used in phishing
SUSPICIOUS_TLDS = [
".tk",".xyz",".top",".gq",".ml",".cf",".click",".support",".zip",".mov",".work",".country",".stream",".download",".xin",".gdn",".mom",".men",".date",".review",".trade",".account",".loan",".finance",".science",".party",".racing",".win",".bid",".faith",".cricket",".jetzt",".cam",".buzz",".link",".live",".site",".online",".monster",".world",".today",".pro",".pw",".rest",".website",".space",".icu",".fun",".uno",".cfd",".lol",".shop",".cloud"
]

# Words commonly seen in phishing URLs
PHISHING_KEYWORDS = [

# authentication
"login","signin","logon","verify","verification","secure","security","account",
"update","password","passcode","pin","auth","authenticate","validation",

# urgency
"urgent","alert","warning","immediate","suspended","locked","restricted",
"attention","important","action","required","security-check",

# financial
"bank","wallet","payment","billing","invoice","refund","transfer",
"transaction","deposit","withdraw","balance","card","credit","debit",

# rewards / scams
"bonus","reward","claim","gift","prize","free","promo","offer",

# services
"support","service","helpdesk","recovery","reset","confirmation",

# fake portals
"portal","dashboard","webscr","client","customer","member",

# verification traps
"validate","confirm","secure-update","account-update"
]

# Brands frequently impersonated in phishing
BRAND_KEYWORDS = [

# Big tech
"google","gmail","youtube","microsoft","office","outlook","live",
"apple","icloud","appleid",

# Social media
"facebook","instagram","whatsapp","snapchat","twitter","x","tiktok",

# E-commerce
"amazon","ebay","aliexpress","flipkart","shopify","temu",

# Payments
"paypal","stripe","paytm","phonepe","gpay","googlepay","razorpay",

# Crypto
"binance","coinbase","kraken","metamask","trustwallet","phantom",
"blockchain","ledger","crypto","walletconnect",

# Streaming
"netflix","spotify","primevideo","disney","hulu",

# Banks global
"bank","chase","citi","wellsfargo","hsbc","barclays","capitalone",
"deutschebank","santander","lloyds",

# Banks india
"hdfc","icici","sbi","axis","kotak","yesbank","pnb","idfc","indusind",

# SaaS
"github","slack","zoom","dropbox","notion","atlassian"
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
    full_url = url.lower()

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            risk += 20
            reasons.append(f"Suspicious TLD detected ({tld})")
            break

    # Raw IP URL
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        risk += 25
        reasons.append("URL uses raw IP address")

    # Punycode detection
    if "xn--" in host:
        risk += 25
        reasons.append("Punycode domain detected")

    # Homograph detection
    if re.search(r"[0-9]", host):
        if any(c in host for c in ["0","1","3","5","7"]):
            risk += 10
            reasons.append("Possible homograph character substitution")

    # Excessive hyphens
    if host.count("-") >= 2:
        risk += 15
        reasons.append("Excessive hyphens in domain")

    # Phishing keywords
    keyword_hits = [k for k in PHISHING_KEYWORDS if k in full_url]
    if keyword_hits:
        risk += 20
        reasons.append("Phishing keywords detected")

    # Brand impersonation
    brand_hits = [b for b in BRAND_KEYWORDS if b in host]
    if brand_hits and keyword_hits:
        risk += 30
        reasons.append("Brand impersonation suspected")

    # Suspicious subdomains
    if host.count(".") >= 3:
        risk += 15
        reasons.append("Excessive subdomains detected")

    for brand in BRAND_KEYWORDS:
        if brand in host and not host.startswith(brand):
            risk += 10
            reasons.append("Brand name found in subdomain")
            break

    # Long URL
    if len(url) > 120:
        risk += 10
        reasons.append("Unusually long URL")

    return risk, reasons


# =============================
# VIRUSTOTAL (IMPROVED)
# =============================

def scan_with_virustotal(url):

    if not VT_API_KEY:
        return None

    headers = {"x-apikey": VT_API_KEY}

    # Encode URL for lookup
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # 1️⃣ Check if VT already has report
    report = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )

    if report.status_code == 200:

        stats = report.json()["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    # 2️⃣ Submit new scan
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if submit.status_code != 200:
        return None

    analysis_id = submit.json()["data"]["id"]

    time.sleep(3)

    analysis = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
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