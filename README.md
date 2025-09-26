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

- **Phase 1 (✅ Complete):** Frontend-only rules-based analyzer.  
- **Phase 2 (🔜 Next):**  
  - Add **Python (Flask) backend**.  
  - Integrate **VirusTotal** / **OpenPhish** APIs for live threat checks.  
  - Combine frontend rules + backend intelligence.  
- **Phase 3:** Flask GUI + packaged tool.  
- **Phase 4:** AI/NLP phishing detection + OCR for image phishing.  
- **Phase 5:** Browser extension + Explainable AI (XAI) + research publication.  

---

## 🛡️ Disclaimer
This is a **student cybersecurity project** for learning and educational use.  
Do not rely on PhishGuardian as a substitute for professional enterprise security products.  

---

## 👤 Author
Made by **Yuvraj Patel**  
📧 Email: [yuvraj.patel@mitwpu.edu.in](mailto:yuvraj.patel@mitwpu.edu.in)  
2nd Year Cybersecurity Student · MITWPU  
