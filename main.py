import re
import os
import sqlite3
import traceback
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

from phishing_detector.risk_calculator import analyze

# ---------------------------------------------------------------------------
# Database Logging setup
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "activity.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def log_activity(email: str, action: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO activity_logs (email, action, timestamp) VALUES (?, ?, ?)",
            (email, action, timestamp)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging activity: {e}")

app = FastAPI(title="PhishLens API", version="1.0.0")

# ---------------------------------------------------------------------------
# CORS — allow the Next.js frontend on localhost:3000 to reach this backend
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class TextScanRequest(BaseModel):
    text: str
    sender_domain: Optional[str] = None
    sender_email: Optional[str] = None
    attachments: Optional[List[str]] = None
    user_email: Optional[str] = None


class UrlScanRequest(BaseModel):
    url: str
    user_email: Optional[str] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def read_root():
    return {"message": "PhishLens backend is running"}


@app.post("/scan/text")
def scan_text(request: TextScanRequest):
    """
    Scan a text message (email body, SMS, etc.) for phishing signals.

    Body fields:
        text (str)                  — the message content to analyse
        sender_domain (str|null)    — optional sender domain for SPF/DMARC checks
        attachments (list[str]|null)— optional list of attachment filenames
    """
    try:
        user_email = request.user_email or "Anonymous"
        log_activity(user_email, "Single Text Scan")
        result = analyze(
            text=request.text,
            sender_domain=request.sender_domain,
            sender_email=request.sender_email,
            attachments=request.attachments,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/scan/url")
def scan_url(request: UrlScanRequest):
    """
    Scan a single URL for phishing signals.

    Body fields:
        url (str) — the URL to analyse
    """
    try:
        user_email = request.user_email or "Anonymous"
        log_activity(user_email, f"Single URL Scan ({request.url})")
        result = analyze(text=request.url)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Gmail request model
# ---------------------------------------------------------------------------
class GmailRequest(BaseModel):
    access_token: str
    max_results: int = 20
    user_email: Optional[str] = None


# ---------------------------------------------------------------------------
# Gmail routes
# ---------------------------------------------------------------------------
@app.post("/gmail/fetch")
def gmail_fetch(request: GmailRequest):
    """
    Fetch emails from the user's Gmail inbox.

    Body fields:
        access_token (str) — Google OAuth access token
        max_results  (int) — number of emails to fetch (20, 50, or 100)
    """
    try:
        from gmail.gmail_fetcher import fetch_emails

        user_email = request.user_email or "Anonymous"
        log_activity(user_email, f"Gmail Fetch Only (Max: {request.max_results})")
        emails = fetch_emails(
            access_token=request.access_token,
            max_results=request.max_results,
        )
        return {"emails": emails}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/gmail/scan")
def gmail_scan(request: GmailRequest):
    """
    Fetch emails and run phishing analysis on each one.

    Body fields:
        access_token (str) — Google OAuth access token
        max_results  (int) — number of emails to fetch (20, 50, or 100)

    Returns a list where each item contains the original email data
    plus the analysis result under the key "analysis".
    """
    try:
        from gmail.gmail_fetcher import fetch_emails

        user_email = request.user_email or "Anonymous"
        log_activity(user_email, f"Gmail Inbox Scan (Max: {request.max_results})")
        emails = fetch_emails(
            access_token=request.access_token,
            max_results=request.max_results,
        )

        results = []
        for email in emails:
            sender_str = email.get("sender", "")
            sender_domain = _extract_sender_domain(sender_str)
            analysis = analyze(
                text=email.get("body", ""),
                sender_domain=sender_domain,
                sender_email=sender_str,
                attachments=email.get("attachments", []),
            )
            results.append({**email, "analysis": analysis})

        return {"results": results}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(exc))


def _extract_sender_domain(sender: str) -> Optional[str]:
    """
    Extract the domain from a sender string.
    Example: "John Doe <john@gmail.com>" → "gmail.com"
             "john@gmail.com"             → "gmail.com"
    """
    if not sender:
        return None
    match = re.search(r"[\w.+-]+@([\w.-]+)", sender)
    return match.group(1) if match else None


class LogRequest(BaseModel):
    email: str
    action: str


@app.post("/admin/log-action")
def log_action(request: LogRequest):
    log_activity(request.email, request.action)
    return {"status": "success"}


@app.get("/admin/logs")
def get_admin_logs(email: str):
    if email != "yashhhwhat@gmail.com":
        raise HTTPException(status_code=403, detail="Access Denied: Unauthorized admin email")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, action, timestamp FROM activity_logs ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for r in rows:
            logs.append({
                "id": r[0],
                "email": r[1],
                "action": r[2],
                "timestamp": r[3]
            })
        return {"logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))