import uuid
import time
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.config import ALLOWED_ORIGINS, BASE_DIR, RATE_LIMIT_PER_MINUTE
from backend.security import hash_client_ip, sanitize_pii, validate_url_safe
from backend.gemini_service import analyze_threat_with_gemini
from backend.url_service import inspect_url_heuristics
from backend.database import (
    save_analysis,
    get_analysis_by_id,
    get_threat_feed,
    add_to_threat_feed,
    vote_feed_item,
    get_threat_stats,
)

app = FastAPI(
    title="AI ScamShield - Intelligent Online Scam Detection Platform",
    version="1.0.0",
    description="Enterprise-grade AI Cybersecurity Platform for detecting phishing, financial fraud, smishing, and malicious links."
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory Rate Limiting
rate_limit_cache: Dict[str, List[float]] = {}

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    # Only rate-limit /api/ endpoints
    if request.url.path.startswith("/api/v1/scan"):
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        window_start = now - 60.0

        if client_ip not in rate_limit_cache:
            rate_limit_cache[client_ip] = []
        
        # Prune old timestamps
        rate_limit_cache[client_ip] = [ts for ts in rate_limit_cache[client_ip] if ts > window_start]

        if len(rate_limit_cache[client_ip]) >= RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Rate limit exceeded. Maximum 60 scans per minute allowed."}
            )

        rate_limit_cache[client_ip].append(now)

    response = await call_next(request)
    return response

# Pydantic Request Models
class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=10, max_length=10000)
    language: str = Field(default="en")
    sessionId: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))

class EmailScanRequest(BaseModel):
    emailRaw: str = Field(..., min_length=10, max_length=50000)
    headersRaw: Optional[str] = Field(default="")
    language: str = Field(default="en")
    sessionId: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))

class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2000)
    sessionId: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))

class VoteRequest(BaseModel):
    feedId: str
    voteType: str = Field(..., pattern="^(UPVOTE|FALSE_POSITIVE)$")

# --- API ROUTES ---

@app.post("/api/v1/scan/text")
async def scan_text(payload: TextScanRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    ip_hash = hash_client_ip(client_ip)
    sanitized_text = sanitize_pii(payload.text)

    try:
        analysis = analyze_threat_with_gemini(
            content_text=sanitized_text,
            input_type="TEXT",
            language=payload.language
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Threat Engine error: {str(e)}")

    record = {
        "id": str(uuid.uuid4()),
        "sessionId": payload.sessionId,
        "inputType": "TEXT",
        "rawInputSnippet": sanitized_text[:300],
        "sanitizedInput": sanitized_text,
        "riskScore": analysis.get("risk_score", 50),
        "riskLevel": analysis.get("risk_level", "MEDIUM"),
        "primaryCategory": analysis.get("primary_category", "PHISHING_CREDENTIAL_THEFT"),
        "confidenceScore": analysis.get("confidence_score", 0.95),
        "summary": analysis.get("summary", "Analysis completed."),
        "isSafeToEngage": analysis.get("is_safe_to_engage", False),
        "psychologicalTriggers": analysis.get("psychological_triggers", []),
        "indicators": analysis.get("indicators", []),
        "technicalForensics": analysis.get("technical_forensics", {}),
        "recommendedActions": analysis.get("recommended_actions", []),
        "clientIpHash": ip_hash
    }

    saved = await save_analysis(record)

    # Automatically submit to community feed if high risk
    if record["riskScore"] >= 70:
        await add_to_threat_feed(record)

    return saved

@app.post("/api/v1/scan/email")
async def scan_email(payload: EmailScanRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    ip_hash = hash_client_ip(client_ip)

    combined_content = f"--- EMAIL HEADERS ---\n{payload.headersRaw or 'None Provided'}\n\n--- EMAIL BODY ---\n{payload.emailRaw}"
    sanitized = sanitize_pii(combined_content)

    try:
        analysis = analyze_threat_with_gemini(
            content_text=sanitized,
            input_type="EMAIL",
            language=payload.language
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email Threat Engine error: {str(e)}")

    record = {
        "id": str(uuid.uuid4()),
        "sessionId": payload.sessionId,
        "inputType": "EMAIL",
        "rawInputSnippet": payload.emailRaw[:300],
        "sanitizedInput": sanitized,
        "riskScore": analysis.get("risk_score", 50),
        "riskLevel": analysis.get("risk_level", "MEDIUM"),
        "primaryCategory": analysis.get("primary_category", "PHISHING_CREDENTIAL_THEFT"),
        "confidenceScore": analysis.get("confidence_score", 0.95),
        "summary": analysis.get("summary", "Email analyzed."),
        "isSafeToEngage": analysis.get("is_safe_to_engage", False),
        "psychologicalTriggers": analysis.get("psychological_triggers", []),
        "indicators": analysis.get("indicators", []),
        "technicalForensics": analysis.get("technical_forensics", {}),
        "recommendedActions": analysis.get("recommended_actions", []),
        "clientIpHash": ip_hash
    }

    saved = await save_analysis(record)
    if record["riskScore"] >= 70:
        await add_to_threat_feed(record)

    return saved

@app.post("/api/v1/scan/url")
async def scan_url(payload: UrlScanRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    ip_hash = hash_client_ip(client_ip)

    # 1. Anti-SSRF & Heuristic domain analysis
    heuristic_res = inspect_url_heuristics(payload.url)
    if not heuristic_res.get("is_valid"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Security check failed: {heuristic_res.get('error')}"
        )

    # 2. Enrich with Gemini Deep Analysis
    prompt_context = f"""
Target URL: {heuristic_res['url']}
Domain: {heuristic_res['hostname']}
Identified Suspicious Flags: {', '.join(heuristic_res['flags']) if heuristic_res['flags'] else 'None detected by heuristic'}
Calculated Suspicion Score: {heuristic_res['suspicion_score']}/100
Resolved IP Address: {heuristic_res.get('resolved_ip', 'Unresolved')}
"""

    try:
        analysis = analyze_threat_with_gemini(
            content_text=prompt_context,
            input_type="URL",
            language="en"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL Analysis error: {str(e)}")

    record = {
        "id": str(uuid.uuid4()),
        "sessionId": payload.sessionId,
        "inputType": "URL",
        "rawInputSnippet": heuristic_res["url"],
        "sanitizedInput": heuristic_res["url"],
        "riskScore": max(analysis.get("risk_score", 0), heuristic_res["suspicion_score"]),
        "riskLevel": analysis.get("risk_level", "LOW"),
        "primaryCategory": analysis.get("primary_category", "MALICIOUS_SOFTWARE_URL"),
        "confidenceScore": analysis.get("confidence_score", 0.92),
        "summary": analysis.get("summary", "URL reputation verified."),
        "isSafeToEngage": analysis.get("is_safe_to_engage", False),
        "psychologicalTriggers": analysis.get("psychological_triggers", []),
        "indicators": analysis.get("indicators", []),
        "technicalForensics": {
            **analysis.get("technical_forensics", {}),
            "heuristic_flags": heuristic_res["flags"],
            "resolved_ip": heuristic_res.get("resolved_ip"),
            "domain": heuristic_res["hostname"]
        },
        "recommendedActions": analysis.get("recommended_actions", []),
        "clientIpHash": ip_hash
    }

    saved = await save_analysis(record)
    if record["riskScore"] >= 70:
        await add_to_threat_feed(record)

    return saved

@app.post("/api/v1/scan/image")
async def scan_image(
    file: UploadFile = File(...),
    sessionId: str = Form(default_factory=lambda: str(uuid.uuid4())),
    language: str = Form("en"),
    request: Request = None
):
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    ip_hash = hash_client_ip(client_ip)

    # Validate image format
    if file.content_type not in ["image/png", "image/jpeg", "image/jpg", "image/webp"]:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported media type '{file.content_type}'. Must be PNG, JPEG, or WEBP."
        )

    image_bytes = await file.read()
    if len(image_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image size exceeds 10MB limit.")

    try:
        analysis = analyze_threat_with_gemini(
            content_text="Perform OCR extraction and visual forensics. Identify forged logos, fraudulent receipts, extortion messages, or fake login dialogs.",
            input_type="IMAGE",
            image_bytes=image_bytes,
            image_mime_type=file.content_type,
            language=language
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image Forensics error: {str(e)}")

    record = {
        "id": str(uuid.uuid4()),
        "sessionId": sessionId,
        "inputType": "IMAGE",
        "rawInputSnippet": f"Uploaded Image: {file.filename}",
        "sanitizedInput": f"Image screenshot analysis ({file.filename})",
        "riskScore": analysis.get("risk_score", 50),
        "riskLevel": analysis.get("risk_level", "MEDIUM"),
        "primaryCategory": analysis.get("primary_category", "PHISHING_CREDENTIAL_THEFT"),
        "confidenceScore": analysis.get("confidence_score", 0.90),
        "summary": analysis.get("summary", "Image forensic scan completed."),
        "isSafeToEngage": analysis.get("is_safe_to_engage", False),
        "psychologicalTriggers": analysis.get("psychological_triggers", []),
        "indicators": analysis.get("indicators", []),
        "technicalForensics": analysis.get("technical_forensics", {}),
        "recommendedActions": analysis.get("recommended_actions", []),
        "clientIpHash": ip_hash
    }

    saved = await save_analysis(record)
    if record["riskScore"] >= 70:
        await add_to_threat_feed(record)

    return saved

@app.get("/api/v1/reports/{report_id}")
async def get_report(report_id: str):
    record = await get_analysis_by_id(report_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis report not found.")
    return record

@app.get("/api/v1/feed")
async def get_feed(
    limit: int = 20,
    offset: int = 0,
    category: Optional[str] = "ALL",
    risk_level: Optional[str] = "ALL",
    search: Optional[str] = None
):
    return await get_threat_feed(limit, offset, category, risk_level, search)

@app.post("/api/v1/feed/vote")
async def vote_feed(payload: VoteRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    voter_hash = hash_client_ip(client_ip)
    return await vote_feed_item(payload.feedId, voter_hash, payload.voteType)

@app.get("/api/v1/threats/stats")
async def stats():
    return await get_threat_stats()

@app.get("/api/v1/academy")
async def academy():
    return [
        {
            "id": "pig-butchering",
            "title": "Pig Butchering (Sha Zhu Pan) & Fake Investment Fraud",
            "threat_level": "CRITICAL",
            "badge": "Financial Loss Vector",
            "description": "Scammers build romantic or mentor rapport over weeks on WhatsApp or LinkedIn before introducing a manipulated cryptocurrency trading platform that fakes massive gains.",
            "indicators": ["Encouragement to move conversation to WhatsApp or Telegram", "Unsolicited wrong-number introduction", "Promises of risk-free algorithmic returns", "Platform demands fee/taxes to withdraw own funds"],
            "prevention": "Never deposit money into exchanges not regulated by national securities boards. Once funds enter unregulated crypto addresses, recovery is near impossible."
        },
        {
            "id": "task-fraud",
            "title": "Remote Job 'Daily Wage Video Liking' Tasks",
            "threat_level": "HIGH",
            "badge": "Social Engineering",
            "description": "Victims are recruited via SMS to earn $200-$500/day by liking YouTube videos or reviewing hotels. Small initial payments are sent to build trust, followed by mandatory VIP deposit requirements.",
            "indicators": ["Unsolicited WhatsApp message from international country code", "Payment via crypto or non-reversal UPI handles", "Requirement to 'pre-fund' merchant accounts"],
            "prevention": "Legitimate employers never demand payment or deposits from employees before releasing salaries."
        },
        {
            "id": "package-smishing",
            "title": "USPS / FedEx / DHL Delivery Failure Alerts",
            "threat_level": "HIGH",
            "badge": "Credential & Card Phishing",
            "description": "Fraudulent SMS messages claiming an urgent package cannot be delivered due to an incorrect postal address, leading to a pixel-perfect replica of the postal carrier demanding a $0.30 - $2.00 fee.",
            "indicators": ["Sender number from personal mobile rather than official SMS shortcode", "Domain uses hyphenated or lookalike TLD (.xyz, .top, .cam)", "Requires credit card details for a trivial redelivery fee"],
            "prevention": "Never click SMS links. Open the official carrier website or app directly and paste the tracking number."
        },
        {
            "id": "tech-support",
            "title": "Browser Lockdown & Fake Windows/Apple Security Callouts",
            "threat_level": "CRITICAL",
            "badge": "Remote Access Trojan",
            "description": "A full-screen browser alert plays sirens claiming 'Zeus Virus Detected' and provides a toll-free number. The operator instructs the victim to download AnyDesk to 'clean the computer', then accesses online banking.",
            "indicators": ["Urgent robotic audio warning", "Toll-free number displayed in browser pop-up", "Request to install remote desktop control software"],
            "prevention": "Neither Apple nor Microsoft displays phone numbers in security pop-ups. Force-close the browser tab using Task Manager."
        }
    ]

# --- STATIC FILE SERVING & SPA ROUTING ---
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/assets", StaticFiles(directory=frontend_dir / "assets", check_dir=False), name="assets")

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    index_file = frontend_dir / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse(
        status_code=200,
        content={"message": "AI ScamShield API running. Please place index.html in frontend directory."}
    )
