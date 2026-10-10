"""Scam Guard API.

Run:  uvicorn app.main:app --host 0.0.0.0 --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

from datetime import datetime, timezone  # noqa: E402

from fastapi import FastAPI, Path, Query  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from . import db  # noqa: E402
from .detector import analyze  # noqa: E402
from .reputation import virustotal_malicious_count  # noqa: E402
from .translations import normalize_lang, warning_for  # noqa: E402

app = FastAPI(
    title="Scam Guard API",
    version="1.0.0",
    description="Detects scam/phishing messages and builds a weekly digest for family members.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class ScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000)
    lang: str = "en"
    user_id: str = Field("demo_user", min_length=1, max_length=64)


@app.get("/")
def health():
    return {"service": "scam-guard", "status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest):
    # Plain `def` (not async) so the optional VirusTotal call runs in a worker thread.
    verdict = analyze(req.message, url_checker=virustotal_malicious_count)
    lang = normalize_lang(req.lang)
    db.log_scan(req.user_id, verdict.is_scam, verdict.category, lang)

    match = None
    if verdict.is_scam:
        match = {
            "category_name": verdict.category or "Unknown",
            "explanation": verdict.explanation,
            "signals": verdict.signals,
            "urls": verdict.urls,
        }
    return {
        "is_scam": verdict.is_scam,
        "match": match,
        "risk_level": verdict.risk_level,
        "confidence": verdict.confidence,
        "warning": warning_for(lang, verdict.is_scam),
        "lang": lang,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/digest/{user_id}")
def digest(
    user_id: str = Path(..., min_length=1, max_length=64),
    days: int = Query(7, ge=1, le=90),
):
    total, scams, by_category = db.stats(user_id, days)
    if total == 0:
        text = f"No messages were checked by Scam Guard in the last {days} days."
    else:
        noun = "message" if total == 1 else "messages"
        text = f"Scam Guard report for the last {days} days: {total} {noun} checked, {scams} flagged as scams."
        if by_category:
            top, count = by_category.most_common(1)[0]
            text += f" Most common threat: {top} ({count})."
        text += " Reminder: never share your OTP, PIN or password, and do not open unknown links."
    return {
        "user_id": user_id,
        "days": days,
        "total_scans": total,
        "scams_flagged": scams,
        "categories": dict(by_category),
        "digest_text": text,
    }
