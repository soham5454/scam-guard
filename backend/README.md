# Scam Guard backend

FastAPI service used by the Scam Guard Flutter app (`../scam_guard_app`).

> **Note:** the original backend, built by Ayus Chakraborty, was lost in an accidental folder deletion.
> This is a rebuild (written with AI assistance) of that design, matching the exact API contract the app expects.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/scan` | body `{message, lang, user_id}` -> `{is_scam, match{category_name, explanation, signals, urls}, risk_level, confidence, warning, lang}` |
| `GET` | `/digest/{user_id}?days=7` | family digest -> `{total_scans, scams_flagged, categories, digest_text}` |
| `GET` | `/` | health check |

Interactive docs: http://127.0.0.1:8000/docs

## How detection works
Rule-based (no ML): weighted regex rules for 11 scam types (KYC fraud, OTP theft, UPI collect-request,
lottery, fake jobs, courier/customs, utility bills, digital arrest, investment, loan apps, SIM) in English,
Hinglish, Hindi and Bengali, plus link heuristics (shorteners, look-alike brand domains, odd TLDs, IP hosts)
and an optional VirusTotal lookup. Real bank OTP messages ("do not share this OTP") are not flagged.
Spoken warnings come in English, Hindi and Bengali (`lang`: `en`, `hi`, `bn`).

Only the verdict and category are stored for the digest - never the message text.

## Run (Windows PowerShell)
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    uvicorn app.main:app --host 0.0.0.0 --reload

Optional: copy `.env.example` to `.env` and add a `VT_API_KEY` to enable VirusTotal checks.

## Test
    pip install -r requirements-dev.txt
    python -m pytest
