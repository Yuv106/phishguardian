# 🐟 PhishGuardian

Catch the bait before it catches you.

PhishGuardian is a lightweight, explainable phishing URL analyzer built to help users quickly identify suspicious links using transparent security checks.

Live demo (frontend):  
https://yuv106.github.io/phishguardian/

---

## 🚀 Current Status

### ✅ Phase 1 — Frontend (Completed)
- Rules-based phishing URL analyzer
- Runs fully in the browser
- No data collection or tracking
- Explainable results (why a URL is flagged)

Checks include:
- Suspicious TLDs
- Raw IP URLs
- Punycode domains
- Typosquatting & brand abuse
- Excessive subdomains
- Long / obfuscated URLs

---

### ✅ Phase 2 — Python Backend (LIVE)
- Flask backend deployed on Render
- `/analyze` API endpoint live
- CORS enabled
- Auto port binding for cloud deployment
- Frontend automatically switches:
  - `localhost` → local backend
  - GitHub Pages → live Render backend
- Used for validation and future threat-intelligence integration

Backend status:
🟢 Live & reachable

---

## 🧭 Roadmap

### 🔜 Phase 3 — Threat Intelligence
- VirusTotal integration
- OpenPhish / PhishTank feeds
- Reputation-based scoring

### 🔜 Phase 4 — Smart Detection
- Heuristic weighting
- Pattern correlation
- Confidence score (0–100%)

### 🔜 Phase 5 — UX & Distribution
- Browser extension
- Message / email link scanning
- Enhanced explanations
- Mobile optimization

---

## ⚠️ Disclaimer
Educational project.  
Do not submit sensitive or private URLs.
