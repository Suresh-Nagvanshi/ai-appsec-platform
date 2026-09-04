"""
Website Security API
====================
Endpoints:
  POST /api/website-scans          — start a website URL scan (background task)
  GET  /api/website-scans          — list all website scans
  GET  /api/website-scans/{id}     — get single scan detail + live progress

Features:
  - URL validation and SSRF prevention (allowlist of public schemes/hosts)
  - Recursive crawling engine (BFS, configurable depth)
  - Client-side vulnerability analysis: detects inline scripts, dangerous sinks,
    insecure headers, mixed content, open redirects, and exposed secrets
  - Passive header analysis: CSP, HSTS, X-Frame-Options, etc.
  - All endpoints protected by API key (applied at router level in main.py)
"""

import asyncio
import copy
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from backend.api.website_scan_state import _website_scans, save_ws_state
from backend.services.website_scanner import run_website_scan

router = APIRouter()

_TIMELINE_STEPS = [
    {"id": "0", "name": "Validate & Init",      "status": "PENDING"},
    {"id": "1", "name": "Crawl Pages",           "status": "PENDING"},
    {"id": "2", "name": "Header Analysis",       "status": "PENDING"},
    {"id": "3", "name": "Client-Side Analysis",  "status": "PENDING"},
    {"id": "4", "name": "Persist Results",       "status": "PENDING"},
]


# ── Models ─────────────────────────────────────────────────────────────────────

class WebsiteScanRequest(BaseModel):
    url: str
    max_pages: Optional[int] = 20   # crawl depth limit (max URLs to visit)
    max_depth: Optional[int] = 3    # BFS depth limit


# ── SSRF guard ────────────────────────────────────────────────────────────────

_PRIVATE_PREFIXES = [
    "localhost", "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.", "::1", "fc00:", "fd",
]

def _validate_website_url(url: str) -> None:
    """
    Reject private/internal hosts and non-HTTP(S) schemes to prevent SSRF.
    Raises HTTPException(400) on any violation.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail="Only HTTP and HTTPS URLs are accepted",
        )

    host = (parsed.hostname or "").lower()

    if not host:
        raise HTTPException(status_code=400, detail="URL must contain a valid hostname")

    for prefix in _PRIVATE_PREFIXES:
        if host == prefix or host.startswith(prefix):
            raise HTTPException(
                status_code=400,
                detail="Scanning private/internal network addresses is not allowed",
            )

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        # Block raw IP addresses to prevent SSRF via DNS rebinding bypass
        raise HTTPException(
            status_code=400,
            detail="Scanning raw IP addresses is not allowed. Use a domain name.",
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _new_website_scan(url: str, max_pages: int, max_depth: int) -> dict:
    return {
        "id": str(uuid4()),
        "scanType": "website",
        "target": url,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "status": "QUEUED",
        "progress": 0,
        "startedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completedAt": None,
        "duration": None,
        "pagesScanned": 0,
        "findingsCount": 0,
        "criticalCount": 0,
        "summary": {},
        "logs": [],
        "timeline": copy.deepcopy(_TIMELINE_STEPS),
        "failureReason": None,
        "findings": [],
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", status_code=202)
async def start_website_scan(
    background_tasks: BackgroundTasks,
    payload: WebsiteScanRequest,
):
    """
    Start an async website security scan.

    Crawls the target URL up to `max_pages` pages at `max_depth` levels,
    performs passive header analysis, and runs client-side vulnerability checks.
    Returns scan_id immediately; poll GET /api/website-scans/{id} for progress.
    """
    _validate_website_url(payload.url)

    # Clamp values
    max_pages = min(max(1, payload.max_pages or 20), 100)
    max_depth = min(max(1, payload.max_depth or 3), 5)

    scan = _new_website_scan(payload.url, max_pages, max_depth)
    _website_scans[scan["id"]] = scan
    save_ws_state()

    background_tasks.add_task(
        run_website_scan, scan["id"], payload.url, max_pages, max_depth
    )

    return {"scan_id": scan["id"], "status": "QUEUED", "target": payload.url}


@router.get("")
def list_website_scans():
    """Return all website scans, newest first."""
    return sorted(
        _website_scans.values(),
        key=lambda s: s.get("startedAt", ""),
        reverse=True,
    )


@router.get("/{scan_id}")
def get_website_scan(scan_id: str):
    """Return live website scan state including progress, logs, and findings."""
    scan = _website_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Website scan not found")
    return scan
