# AI ScamShield – Intelligent Online Scam Detection and Prevention System

An enterprise-grade, multi-modal cybersecurity defense platform designed to analyze suspicious digital communications (SMS messages, emails, URLs, and image screenshots) using Google Gemini 2.0/3.5, Explainable AI (XAI), and heuristic threat scoring.

---

## 🌟 Key Features

1. **Multi-Vector Threat Scanner**:
   - **Text & SMS Inspector**: Fast paste buffer with character normalization and homoglyph detection.
   - **Email Analyzer**: Dual-mode input for raw body and RFC 822 email headers.
   - **URL & Domain Reputation Inspector**: Anti-SSRF domain inspection, suspicious TLD detection, typosquatting analysis, and DNS IP resolution.
   - **Screenshot & OCR Scanner**: Drag-and-drop image upload (PNG, JPG, WEBP) analyzing fake payment slips, altered typography, and fraudulent login dialogs.
2. **Explainable AI (XAI) Scoring Engine**:
   - Normalized 0–100 Scam Risk Score.
   - 5 Threat Tiers: `SAFE` (0–19), `LOW` (20–39), `MEDIUM` (40–69), `HIGH` (70–89), `CRITICAL` (90–100).
   - Psychological manipulation vectors (Urgency, Panic, Authority Impersonation, Greed).
   - Discrete Indicators of Compromise (IOCs) with extracted evidence snippets.
3. **Actionable Remediation Playbook**:
   - Prioritized incident checklist (Immediate, Secondary, Preventative) with verified reporting hotlines.
4. **Live Community Threat Intelligence Feed**:
   - Real-time stream of anonymized, PII-scrubbed community submissions with upvoting.
5. **Scam Awareness Academy**:
   - In-depth guides on modern scam schemes: Pig Butchering, Remote Job Tasks, Package Smishing, and Tech Support Lockdowns.

---

## 🚀 Quick Start

### 1. Launch the Server
Double-click `run.bat` or run:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Open the Application
Open your browser to:
**[http://localhost:8000](http://localhost:8000)**

---

## 🛡️ Security Features
- **Anti-SSRF Protection**: Prevents internal network pivoting and cloud metadata probing.
- **PII Scrubbing**: Automatically redacts credit cards and OTP codes before logging or persistence.
- **Rate Limiting**: Sliding window rate limiter (60 scans/min per IP).
- **Hashed IP Identity**: SHA-256 salted hashes for anonymous users.
