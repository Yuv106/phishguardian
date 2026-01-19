# 🐟🛡️ PhishGuardian

**PhishGuardian** is a lightweight, explainable phishing detection project built step-by-step while learning cybersecurity and backend development.

Live demo (Phase 1):  
👉 https://yuv106.github.io/phishguardian/

---

## 🔍 Overview

PhishGuardian helps users identify suspicious URLs using transparent, explainable checks.

- **Phase 1** runs fully in the browser (no data sent anywhere)
- **Phase 2** introduces a Python backend API
- Future phases add real threat intelligence and ML

This project is built while learning — clean, simple, and understandable by design.

---

## 🚀 Current Status

### ✅ Phase 1 — Frontend Rules-Based Analyzer (Completed)
- Client-side only (HTML / CSS / JavaScript)
- Detects:
  - Suspicious TLDs
  - Raw IP URLs
  - Punycode domains
  - Excessive subdomains
  - `user@host` tricks
  - Brand typos & brand abuse
- Verdicts:
  - **Safe (0–1)**
  - **Suspicious (2–4)**
  - **Dangerous (5+)**
- Fully explainable scoring
- No backend, no tracking

---

## Phase 2 — Python Backend (In Progress ✅)

### Phase 2 – Python Backend (Live)

- Flask backend deployed on Render
- `/analyze` API endpoint live
- Frontend automatically switches:
  - Localhost → local backend
  - GitHub Pages → Render backend
- Used for validation & future intelligence hooks

