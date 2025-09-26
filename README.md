# PhishGuardian 🐟

**Live Demo (Frontend):** [https://yuv106.github.io/phishguardian/](https://yuv106.github.io/phishguardian/)  

PhishGuardian is a lightweight cybersecurity tool designed to help users **detect and analyze suspicious URLs**.  
Currently in **Phase 1** (frontend complete), it runs fully in the **browser (client‑side JavaScript)** with no backend or data sharing.  

---

## 🔎 Features (Phase 1 — Frontend Rules-Based Analyzer)

- **Client‑side URL checker** (works in any browser, no server needed)
- Detection rules include:
  - 🚩 Suspicious TLDs (`.ru`, `.cn`, `.tk`, `.zip`, `.mov`, etc.)
  - 🚩 Raw IP addresses in place of domains (`http://192.168.0.10/login`)
  - 🚩 Punycode / homoglyph domains (`xn--pple-43d.com` → looks like "apple.com")
  - 🚩 Excessive subdomains (`secure.login.verify.update.example.com`)
  - 🚩 Userinfo in URL (`username@site.com` trick)
  - 🚩 Overly long URLs
  - 🚩 Common phishing keywords (`login`, `verify`, `reset`, `secure`, `bonus`, etc.)
  - 🚩 Brand typos (`paypai → paypal`, `faceb00k → facebook`, `amaz0n → amazon`)
  - 🚩 Brand abuse (`fake-hdfcbank.com` flagged, while real `hdfcbank.com` marked safe)
- **Whitelist for official domains and subdomains**:
  - ✅ `hdfcbank.com`  
  - ✅ `microsoft.com` + `microsoftonline.com`  
  - ✅ `paypal.com`  
- **Verdict system**
  - ✅ Safe (Score ≤ 1)  
  - ⚠️ Suspicious (Score 2–4)  
  - ❌ Dangerous (Score ≥ 5)  

---

## 🚀 How to Use

1. Visit the [live demo page](https://yuv106.github.io/phishguardian/).
2. Paste any URL (real or test).
3. Click **Scan**.
4. Verdict appears: Safe ✅ / Suspicious ⚠️ / Dangerous ❌  
   + detailed reasons for the decision.  

---

## 🛠 Run Locally

1. Clone/download this repo.  
2. Open `index.html` in any browser.  
   - Or run a quick local server:  
     ```bash
     python -m http.server 8000
     ```  
     Visit: `http://127.0.0.1:8000`

---

🗺️ Roadmap
Phase 1 — Frontend Rules-Based Analyzer (DONE, v1.0)
Tech: HTML/CSS/JavaScript (client-side only)
Capabilities:
Suspicious TLDs (.ru, .cn, .tk, .zip, .mov), raw IPs, punycode (xn--), excessive subdomains
user@host trick, long URL detection
Gentle keyword scoring (+1 total)
Brand typos (paypai, faceb00k, amaz0n, g00gle)
Brand-abuse (e.g., fake-hdfcbank.com flagged)
Whitelist (official domains + subdomains): microsoft.com, microsoftonline.com, hdfcbank.com, paypal.com
Verdicts: Safe (0–1), Suspicious (2–4), Dangerous (≥5)
Deliverables: Live site (index.html), README
Status: Completed
Release: v1.0



Phase 2 — Python Backend + Threat Intelligence (NEXT, v2.0)
Tech: Python (Flask), VirusTotal (later OpenPhish), HTTPS deploy (Render/Railway)
Goals:
Build a small API: POST /analyze → returns VirusTotal stats + score bump
Scoring hint: +3 if malicious ≥1, +1 if suspicious ≥1
1‑hour caching to reduce rate limits
CORS restricted to your site (e.g., https://yuv106.github.io)
Frontend calls the backend, appends “VirusTotal → Malicious/Suspicious/Harmless” line, adjusts verdict
Deliverables:
Backend repo (app.py, requirements.txt, .env.example, deploy config)
HTTPS endpoint live on Render/Railway
Frontend updated to use the endpoint
Exit criteria:
20 test domains (legit + known bad) show sensible results
Live site works end-to-end (HTTPS → HTTPS)
Release: v2.0



Phase 3 — Smarter Rules + Text Analyzer (v3.0)
Tech: Regex, URL parsing libs, simple text processing
Goals:
Regex upgrades: encoded IPs, mixed Unicode, excessive trackers
Text/Email analyzer: extract URLs; add urgency/scare-language cues
Move whitelist/keywords to JSON for easy editing (no code change)
Deliverables: Text mode in UI, JSON config files
Release: v3.0



Phase 4 — AI Engine (Baseline ML/NLP) (v4.0)
Tech: scikit-learn (TF‑IDF + Logistic Regression), optional Transformers
Goals:
Train phishing vs. legit text classifier on public datasets
Backend endpoint /analyze-text returns probability + top contributing tokens
Combine ML probability with rule score for final verdict
Deliverables: Model (.joblib), training script, evaluation report (e.g., F1 score)
Release: v4.0



Phase 5 — Packaging, Extension, Recognition (v5.0)
Goals:
Browser extension (pre-check links via backend)
Dockerize backend; add screenshots, demo video, docs polish
Optional blog/research write-up
Deliverables: Extension MVP, Dockerfile, documentation
Release: v5.0



Version Plan
v1.x: Frontend-only improvements (UI/rules)
v2.x: Backend online + VirusTotal integration
v3.x: Regex/text analyzer + JSON configs
v4.x: ML/NLP baseline + explainability
v5.x: Packaging, extension, docs polish



Repos
Frontend (current): yuv106/phishguardian — GitHub Pages (index.html, README)
Backend (Phase 2): yuv106/phishguardian-backend — Flask app (deployed to HTTPS)
---

## 🛡️ Disclaimer
This is a **student cybersecurity project** for learning and educational use.  
Do not rely on PhishGuardian as a substitute for professional enterprise security products.  

---

## 👤 Author
Made by **Yuvraj Patel**  
📧 Email: [yuvraj.patel@mitwpu.edu.in](mailto:yuvraj.patel@mitwpu.edu.in)  
2nd Year CSE Cybersecurity Student · MITWPU  
