# 🐟🛡️ PhishGuardian

Lightweight phishing URL analyzer that runs entirely in your browser (Phase 1).  
Live demo: https://yuv106.github.io/phishguardian/

Status: v1.0 • Phase 1 complete (frontend rules-based analyzer)

---

## 🔎 Overview
PhishGuardian helps users identify and analyze suspicious URLs using transparent, explainable checks. Phase 1 is 100% client‑side (no data sent anywhere). Next phases add a Python backend with real threat intelligence and, later, AI.

---

## ✅ Features (Phase 1 — Frontend Rules-Based Analyzer)
- Client-side URL analysis (no server calls)
- Detects:
  - Suspicious TLDs: `.ru`, `.cn`, `.tk`, `.zip`, `.mov` (and more)
  - Raw IP addresses in place of domains (e.g., `http://1.2.3.4/login`)
  - Punycode/homoglyphs (`xn--…`)
  - Excessive subdomains (obfuscation)
  - user@host trick in URL
  - Unusually long URLs
  - Gentle keyword scoring (+1 total): login, verify, reset, secure, bonus, free, etc.
  - Common brand typos: `paypai→paypal`, `faceb00k→facebook`, `amaz0n→amazon`, `g00gle→google`
  - Brand abuse (e.g., `fake-hdfcbank.com` flagged)
- Whitelist (official domains + subdomains):
  - `microsoft.com`, `microsoftonline.com`, `hdfcbank.com`, `paypal.com`
- Verdicts by score:
  - Safe: 0–1
  - Suspicious: 2–4
  - Dangerous: 5+

---

## 🚀 How to Use (Website)
1. Open: https://yuv106.github.io/phishguardian/
2. Paste a URL and click Scan.
3. See a verdict (Safe / Suspicious / Dangerous) and the exact reasons.

Note: All analysis runs in your browser. No URLs are sent to a server in Phase 1.

---

## 💻 Run Locally (Optional)
- Download `index.html` and double‑click to open in your browser.
- Or serve locally:
  ```bash
  python -m http.server 8000
