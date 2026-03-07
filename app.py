from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import re
import base64
import math
from collections import Counter
from urllib.parse import urlparse
import whois
from datetime import datetime

VT_API_KEY = os.environ.get("VT_API_KEY")
GOOGLE_SAFE_API_KEY = os.environ.get("GOOGLE_SAFE_API_KEY")

app = Flask(__name__)
CORS(app)

# =============================
# CONFIG
# =============================

SUSPICIOUS_TLDS = [
".tk",".xyz",".top",".gq",".ml",".cf",".click",".support",".zip",".mov",".work",".country",".stream",".download",".xin",".gdn",".mom",".men",".date",".review",".trade",".account",".loan",".finance",".science",".party",".racing",".win",".bid",".faith",".cricket",".jetzt",".cam",".buzz",".link",".live",".site",".online",".monster",".world",".today",".pro",".pw",".rest",".website",".space",".icu",".fun",".uno",".cfd",".lol",".shop",".cloud"
]

PHISHING_KEYWORDS = [
"login","signin","verify","secure","account","update",
"password","bank","wallet","urgent","alert",
"suspended","bonus","reward","claim","payment"
]

BRAND_KEYWORDS = [
"paypal","apple","google","microsoft","amazon","netflix",
"bank","hdfc","sbi","icici","axis","github"
]

# =============================
# HEALTH CHECK
# =============================

@app.route("/", methods=["GET"])
def home():
    return "PhishGuardian backend is alive 🟢"

# =============================
# ENTROPY
# =============================

def calculate_entropy(domain):

    if not domain:
        return 0

    prob = [n/len(domain) for n in Counter(domain).values()]
    entropy = -sum(p * math.log2(p) for p in prob)

    return entropy

# =============================
# DOMAIN AGE
# =============================

def get_domain_age(host):

    try:

        w = whois.whois(host)

        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            return None

        age = (datetime.now() - creation).days

        return age

    except:
        return None

# =============================
# GOOGLE SAFE BROWSING
# =============================

def check_google_safe(url):

    if not GOOGLE_SAFE_API_KEY:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_API_KEY}"

    body = {
        "client": {
            "clientId": "phishguardian",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:

        r = requests.post(endpoint, json=body, timeout=10)
        data = r.json()

        return "matches" in data

    except:
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

        return {
            "malicious": stats.get("malicious",0),
            "suspicious": stats.get("suspicious",0)
        }

    return None

# =============================
# HEURISTICS
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

    # Hyphen detection
    if host.count("-") >= 2:
        risk += 10
        reasons.append("Excessive hyphens in domain")

    # Phishing keywords
    if any(k in full_url for k in PHISHING_KEYWORDS):
        risk += 20
        reasons.append("Phishing keywords detected")

    # Brand impersonation
    if any(b in host for b in BRAND_KEYWORDS) and any(k in full_url for k in PHISHING_KEYWORDS):
        risk += 30
        reasons.append("Brand impersonation suspected")

    # Entropy detection
    entropy = calculate_entropy(host.replace(".", ""))

    if entropy > 2.9:
        risk += 15
        reasons.append("High entropy domain")

    # Digit ratio detection
    digits = sum(c.isdigit() for c in host)
    ratio = digits / max(len(host),1)

    if ratio > 0.3:
        risk += 15
        reasons.append("High digit ratio domain")

    # Domain age detection
    domain_age = get_domain_age(host)

    if domain_age is not None and domain_age < 30:
        risk += 20
        reasons.append("Domain is very new (<30 days)")

    return risk, reasons, domain_age

# =============================
# ANALYZE ENDPOINT
# =============================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()
    url = data.get("url","")

    heuristic_risk, heuristic_reasons, domain_age = analyze_heuristics(url)

    reasons = list(heuristic_reasons)
    risk = heuristic_risk

    # Google Safe Browsing
    if check_google_safe(url):

        return jsonify({
            "backend":"alive",
            "engine":"Google Safe Browsing",
            "url":url,
            "domain_age_days":domain_age,
            "final_verdict":{
                "verdict":"Dangerous",
                "confidence":95,
                "reasons":["Flagged by Google Safe Browsing"]
            }
        })

    # VirusTotal
    vt = scan_with_virustotal(url)

    if vt:

        if vt["malicious"] >= 1:
            risk += 40
            reasons.append("Detected malicious by security engine")

    # Final verdict
    if risk >= 70:
        verdict = "Dangerous"
    elif risk >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    confidence = min(95,max(5,risk))

    return jsonify({
        "backend":"alive",
        "engine":"Heuristics + Threat Intelligence",
        "url":url,
        "domain_age_days":domain_age,
        "final_verdict":{
            "verdict":verdict,
            "confidence":confidence,
            "reasons":reasons if reasons else ["No strong indicators detected"]
        }
    })

# =============================
# RUN SERVER
# =============================

if __name__ == "__main__":

    port = int(os.environ.get("PORT",5000))

    app.run(host="0.0.0.0",port=port)