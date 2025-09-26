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

## 📌 Roadmap  

PhishGuardian Roadmap (Updated)

Phase 1 — Frontend Rules-Based Analyzer (DONE, v1.0)

Tech: HTML/CSS/JavaScript (client-side only)
What it does:
Detects suspicious TLDs (.ru, .cn, .tk, .zip, .mov), raw IPs, punycode (xn--), excessive subdomains, user@ trick, long URLs
Softer keyword scoring (+1 total) and brand-typo detection (paypai, faceb00k, amaz0n, g00gle)
Brand-abuse check (fake-hdfcbank.com flagged; official subdomains allowed)
Whitelist (with subdomains): hdfcbank.com, microsoft.com, microsoftonline.com, paypal.com
Verdicts: Safe (0–1), Suspicious (2–4), Dangerous (≥5)
Deliverables:
Live site (index.html) published to GitHub Pages
README with features and roadmap
Version tag: v1.0 — Phase 1 complete
Phase 2 — Python Backend + Threat Intelligence (NEXT)

Tech: Python (Flask), VirusTotal (and later OpenPhish), HTTPS deploy (Render/Railway)
Goals:
Build a small Flask API (POST /analyze) that takes a domain and returns VT stats + a score bump (+3 if malicious, +1 if suspicious)
Add 1‑hour caching to reduce VT rate limits; enable CORS only for your site
Deploy backend to an HTTPS host and update the frontend to call it
Deliverables:
Backend repo with app.py, requirements.txt, .env.example, deployment config
Frontend shows a “VirusTotal → Malicious/Suspicious/Harmless” line and adjusts verdict accordingly
Version tag: v2.0 — Backend online + VT integration
Phase 3 — Smarter Rules + Text Analyzer (UX Boost)

Tech: Regex, URL parsing libs, simple text processing
Goals:
Regex upgrades (encoded IPs, Unicode traps, excessive trackers)
Text/Email analyzer: extract URLs from pasted text, run URL checks + “urgency/fear” language cues
Move whitelist/keywords to a JSON config for easy edits
Deliverables:
Text analysis mode in UI
Config JSON files (trusted domains, risky keywords)
Version tag: v3.0
Phase 4 — AI Engine (Baseline ML/NLP)

Tech: scikit‑learn (TF‑IDF + Logistic Regression) → optional upgrade to Transformers
Goals:
Train a phishing vs. legit text classifier using public datasets
Add /analyze-text endpoint in backend; combine ML probability with rule score
Show top contributing tokens/phrases (basic explainability)
Deliverables:
Model file (.joblib), training script, evaluation report (e.g., F1 score)
Version tag: v4.0
Phase 5 — Packaging, Extension, and Recognition

Goals:
Browser extension (pre-check links via backend)
Dockerize the backend; improve docs and screenshots
Optional: blog/research write‑up
Deliverables:
Extension MVP, Dockerfile, polished README/docs
Version tag: v5.0
TL;DR Evolution

v1.x: Frontend-only rules analyzer (DONE)
v2.x: Python backend + VirusTotal
v3.x: Regex/text analyzer + JSON configs
v4.x: ML/NLP baseline + explainability
v5.x: Packaging, browser extension, docs
---

## 🛡️ Disclaimer
This is a **student cybersecurity project** for learning and educational use.  
Do not rely on PhishGuardian as a substitute for professional enterprise security products.  

---

## 👤 Author
Made by **Yuvraj Patel**  
📧 Email: [yuvraj.patel@mitwpu.edu.in](mailto:yuvraj.patel@mitwpu.edu.in)  
2nd Year CSE Cybersecurity Student · MITWPU  
