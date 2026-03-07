from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import time
import re
import base64
import math
import whois
from urllib.parse import urlparse
from datetime import datetime

VT_API_KEY = os.environ.get("VT_API_KEY")
GOOGLE_SAFE_BROWSING_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")

app = Flask(__name__)
CORS(app)

# =============================
# CONFIG
# =============================

OPENPHISH_FEED = "https://openphish.com/feed.txt"

SUSPICIOUS_TLDS = [
".tk",".xyz",".top",".gq",".ml",".cf",".click",".support",".zip",".mov",
".work",".country",".stream",".download",".xin",".gdn",".mom",".men",".date",
".review",".trade",".account",".loan",".finance",".science",".party",".racing",
".win",".bid",".faith",".cam",".buzz",".link",".live",".site",".online",".monster",
".world",".today",".pro",".pw",".rest",".website",".space",".icu",".fun",".uno",
".cfd",".lol",".shop",".cloud"
]

PHISHING_KEYWORDS = [
"login","signin","verify","secure","account","update","password",
"bank","wallet","payment","billing","invoice","refund",
"urgent","alert","suspended","locked","confirm","validation",
"bonus","reward","claim","gift","free","promo"
]

BRAND_KEYWORDS = [
"google","gmail","youtube","microsoft","office","outlook","live",
"apple","icloud","appleid","facebook","instagram","whatsapp",
"amazon","ebay","flipkart","shopify","paypal","stripe","paytm",
"phonepe","gpay","binance","coinbase","kraken","metamask",
"netflix","spotify","primevideo","bank","hdfc","icici","sbi",
"axis","kotak","github","slack","zoom"
]

# =============================
# HEALTH CHECK
# =============================

@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"

# =============================
# SHANNON ENTROPY
# =============================

def shannon_entropy(domain):

    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy

# =============================
# DOMAIN AGE CHECK
# =============================

def domain_age(host):

    try:

        w = whois.whois(host)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:

            age_days = (datetime.now() - creation_date).days
            return age_days

        return None

    except:
        return None

# =============================
# HEURISTICS ENGINE
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

    # Raw IP
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        risk += 25
        reasons.append("URL uses raw IP address")

    # Punycode
    if "xn--" in host:
        risk += 25
        reasons.append("Punycode domain detected")

    # Hyphens
    if host.count("-") >= 2:
        risk += 15
        reasons.append("Excessive hyphens in domain")

    # Keywords
    keyword_hits = [k for k in PHISHING_KEYWORDS if k in full_url]

    if keyword_hits:
        risk += 20
        reasons.append("Phishing keywords detected")

    # Brand impersonation
    brand_hits = [b for b in BRAND_KEYWORDS if b in host]

    if brand_hits and keyword_hits:
        risk += 30
        reasons.append("Brand impersonation suspected")

    # Subdomains
    if host.count(".") >= 3:
        risk += 15
        reasons.append("Excessive subdomains detected")

    # URL length
    if len(url) > 120:
        risk += 10
        reasons.append("Unusually long URL")

    # Entropy
    entropy = shannon_entropy(host)

    if entropy > 4:
        risk += 15
        reasons.append("High entropy domain (randomized domain)")

    # Domain age
    age = domain_age(host)

    if age and age < 30:
        risk += 25
        reasons.append("Very new domain (less than 30 days old)")

    return risk, reasons

# =============================
# OPENPHISH CHECK
# =============================

def check_openphish(url):

    try:

        r = requests.get(OPENPHISH_FEED, timeout=10)

        if r.status_code != 200:
            return False

        feed_urls = r.text.splitlines()

        for p in feed_urls:

            if url.startswith(p):
                return True

        return False

    except:
        return False

# =============================
# GOOGLE SAFE BROWSING
# =============================

def check_google_safe_browsing(url):

    if not GOOGLE_SAFE_BROWSING_KEY:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"

    payload = {
        "client": {
            "clientId": "phishguardian",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    r = requests.post(endpoint, json=payload)

    if r.status_code != 200:
        return False

    data = r.json()

    if "matches" in data:
        return True

    return False

# =============================
# VIRUSTOTAL
# =============================

def scan_with_virustotal(url):

    if not VT_API_KEY:
        return None

    headers = {"x-apikey": VT_API_KEY}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    report = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )

    if report.status_code == 200:

        stats = report.json()["data"]["attributes"]["last_analysis_stats"]

        return stats

    return None

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

    # OpenPhish
    if check_openphish(url):

        return jsonify({
            "backend": "alive",
            "engine": "OpenPhish",
            "url": url,
            "final_verdict": {
                "verdict": "Dangerous",
                "confidence": 95,
                "reasons": ["URL found in OpenPhish phishing database"]
            }
        })

    # Google Safe Browsing
    if check_google_safe_browsing(url):

        return jsonify({
            "backend": "alive",
            "engine": "Google Safe Browsing",
            "url": url,
            "final_verdict": {
                "verdict": "Dangerous",
                "confidence": 95,
                "reasons": ["Flagged by Google Safe Browsing"]
            }
        })

    heuristic_risk, heuristic_reasons = analyze_heuristics(url)

    vt_stats = scan_with_virustotal(url)

    verdict, confidence, reasons = merge_results(
        heuristic_risk,
        heuristic_reasons,
        vt_stats
    )

    return jsonify({
        "backend": "alive",
        "engine": "Heuristics + Threat Intelligence",
        "url": url,
        "heuristic_risk": heuristic_risk,
        "virustotal": vt_stats,
        "final_verdict": {
            "verdict": verdict,
            "confidence": confidence,
            "reasons": reasons or ["No strong indicators detected"]
        }
    })

# =============================
# START SERVER
# =============================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(host="0.0.0.0", port=port)