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

## 🗺️ PhishGuardian Roadmap

[Live demo](https://yuv106.github.io/phishguardian/) • Status: v1.0 (Phase 1 complete)

### Timeline
`🟩🟩🟩🟩🟩🟨🟨🟨🟨🟨`  
Legend: 🟩 done • 🟨 planned

### Phases (at a glance)

| Phase | Focus | Tech | Status | Version |
|------:|------|------|--------|---------|
| 1 | Frontend rules analyzer | HTML/CSS/JS | ✅ Complete | v1.0 |
| 2 | Python backend + VirusTotal | Flask + VT API + Render/Railway | 🔜 Next | v2.0 |
| 3 | Smarter rules + Text analyzer | Regex + URL parsing + JSON configs | 🔜 Planned | v3.0 |
| 4 | Baseline AI/NLP | scikit‑learn (TF‑IDF + LR), optional Transformers | 🔜 Planned | v4.0 |
| 5 | Packaging + Extension + Docs | Browser extension, Docker, docs | 🔜 Planned | v5.0 |

---

<details>
<summary>Phase 1 — Frontend Rules-Based Analyzer (DONE ✅)</summary>

- Client-side only (no data sent anywhere)
- Detects:
  - Suspicious TLDs (.ru, .cn, .tk, .zip, .mov), raw IPs, punycode (xn--), many subdomains
  - user@host trick, very long URLs
  - Gentle keyword scoring (+1): login, verify, reset, secure, bonus, free…
  - Brand typos: paypai→paypal, faceb00k→facebook, amaz0n→amazon, g00gle→google
  - Brand-abuse: e.g., fake-hdfcbank.com flagged
- Whitelist (with subdomains): microsoft.com, microsoftonline.com, hdfcbank.com, paypal.com
- Verdicts: Safe (0–1), Suspicious (2–4), Dangerous (≥5)
- Deliverables: index.html (GitHub Pages) + README
</details>

<details>
<summary>Phase 2 — Python Backend + Threat Intelligence (NEXT 🔜)</summary>

- Build Flask API: `POST /analyze` → returns VirusTotal stats + score bump
  - Scoring hint: +3 if malicious ≥ 1, +1 if suspicious ≥ 1
- 1‑hour caching (avoid free-tier rate limits)
- CORS restricted to your site (https://yuv106.github.io)
- Deploy to HTTPS (Render/Railway) and call from frontend
- Deliverables:
  - Backend repo: `app.py`, `requirements.txt`, `.env.example`, deploy config
  - Frontend shows: “VirusTotal → Malicious/Suspicious/Harmless” and adjusts verdict
- Exit criteria:
  - 20 test domains (10 legit, 10 known bad) behave sensibly end‑to‑end (HTTPS → HTTPS)
- Release: v2.0
</details>

<details>
<summary>Phase 3 — Smarter Rules + Text Analyzer (Planned)</summary>

- Regex upgrades: encoded IPs, mixed Unicode, excessive tracking params
- Text/Email analyzer:
  - Extract URLs from pasted text, run URL checks
  - Add urgency/scare‑language cues
- Move whitelist/keywords to JSON configs (edit without code)
- Release: v3.0
</details>

<details>
<summary>Phase 4 — AI Engine (Baseline ML/NLP) (Planned)</summary>

- Train TF‑IDF + Logistic Regression (baseline) on phishing vs legit datasets
- New endpoint `/analyze-text`: return probability + top contributing tokens
- Combine ML probability with rule score for final verdict
- Deliverables: model (.joblib), training script, evaluation report (F1)
- Release: v4.0
</details>

<details>
<summary>Phase 5 — Packaging, Extension, Recognition (Planned)</summary>

- Browser extension (pre‑check links via backend)
- Dockerize backend; add screenshots, demo video, docs polish
- Optional blog/research write‑up
- Release: v5.0
</details>

### Repos
- Frontend (current): `yuv106/phishguardian` — GitHub Pages (index.html, README)  
- Backend (Phase 2): `yuv106/phishguardian-backend` — Flask app (to be deployed to HTTPS)
---

## 🛡️ Disclaimer
This is a **student cybersecurity project** for learning and educational use.  
Do not rely on PhishGuardian as a substitute for professional enterprise security products.  

---

## 👤 Author
Made by **Yuvraj Patel**  
📧 Email: [yuvraj.patel@mitwpu.edu.in](mailto:yuvraj.patel@mitwpu.edu.in)  
2nd Year CSE Cybersecurity Student · MITWPU  
