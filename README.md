# PhishGuardian 🛡️
Client-side phishing detection with live backend threat intelligence.

PhishGuardian is a web-based phishing detection tool that analyzes URLs using heuristics, domain intelligence, and security threat feeds to determine whether a link is Safe, Suspicious, or Dangerous.

It combines local detection logic with external security intelligence sources such as Google Safe Browsing and VirusTotal.

-------------------------------------

LIVE DEMO

Frontend (GitHub Pages)
https://yuv106.github.io/phishguardian

Backend API (Render)
https://phishguardian-backend.onrender.com

-------------------------------------

PROJECT ARCHITECTURE

User URL Input
↓
Frontend Analyzer (JavaScript)
↓
Flask Backend API
↓
Heuristic Detection Engine
↓
Threat Intelligence APIs
↓
Final Risk Score + Explainable Verdict

-------------------------------------

FEATURES

Heuristic Phishing Detection

The backend analyzes multiple URL characteristics commonly used in phishing attacks.

Detection includes:
- Suspicious Top-Level Domains
- Raw IP address URLs
- Excessive hyphen usage
- Phishing keywords in URL
- Brand impersonation attempts

Example:
paypal-account-security-check.top

Detection result:

Dangerous
• Suspicious TLD detected
• Phishing keywords detected
• Brand impersonation suspected

-------------------------------------

Entropy-Based Domain Detection

PhishGuardian detects algorithmically generated domains (DGA) using Shannon entropy.

Example:
k29sj2kd82jsad.com

Detection reason:
High entropy domain

-------------------------------------

Digit Ratio Detection

Many phishing and malware domains contain excessive numbers.

Example:
s9d9sd9sd9sd9sd.com

Detection reason:
High digit ratio domain

-------------------------------------

Domain Age Analysis (WHOIS)

Newly registered domains are commonly used in phishing campaigns.

PhishGuardian retrieves domain age using WHOIS.

Example output:

Domain age: 6723 days

If a domain is very new:

Domain is very new (<30 days)

-------------------------------------

Google Safe Browsing Integration

The backend checks URLs against Google Safe Browsing.

Example test URL:

http://testsafebrowsing.appspot.com/s/malware.html

Detection result:

Dangerous
Flagged by Google Safe Browsing

-------------------------------------

VirusTotal Threat Intelligence

PhishGuardian checks URL reputation against VirusTotal.

If security vendors flag the URL:

Detected malicious by security engine

-------------------------------------

Explainable Security Decisions

Instead of only returning a label, the system explains why a URL was flagged.

Example:

Suspicious
Confidence: 60%

Reasons:
• URL uses raw IP address
• Phishing keywords detected
• Excessive subdomains detected

-------------------------------------

RISK SCORING SYSTEM

0–29 → Safe  
30–69 → Suspicious  
70+ → Dangerous  

Confidence scores are calculated based on cumulative risk indicators.

-------------------------------------

TECHNOLOGY STACK

Frontend
- HTML
- CSS
- JavaScript
- GitHub Pages

Backend
- Python
- Flask
- Flask-CORS

Threat Intelligence
- Google Safe Browsing API
- VirusTotal API
- WHOIS Domain Lookup

Deployment
- Render (Flask API hosting)

-------------------------------------

PROJECT STRUCTURE

phishguardian/

index.html  
README.md  

backend/
app.py
requirements.txt
venv/

-------------------------------------

LOCAL INSTALLATION

Clone repository

git clone https://github.com/Yuv106/phishguardian

Navigate to backend

cd phishguardian/backend

Create virtual environment

python -m venv venv

Activate environment

Windows

venv\Scripts\activate

Install dependencies

pip install -r requirements.txt

Run backend

python app.py

Backend runs at

http://127.0.0.1:5000


-------------------------------------


CURRENT STATUS

Phase 2 Complete

✔ Live Python backend deployed (Render)
✔ Heuristic phishing detection
✔ VirusTotal integration
✔ Google Safe Browsing integration
✔ Domain age analysis (WHOIS)
✔ Entropy-based detection
✔ Explainable detection reasons

-------------------------------------

UPCOMING (Phase 3)

- Machine learning phishing classifier
- Adaptive risk scoring
- Continuous phishing dataset training

-------------------------------------

DISCLAIMER

PhishGuardian is built for educational and cybersecurity awareness purposes.

It should not be considered a replacement for professional security tools.

-------------------------------------

AUTHOR

Yuvraj Patel  
MIT World Peace University  
BTech Computer Science (Cybersecurity)

GitHub
https://github.com/Yuv106