"""
Scans API
=========
Endpoints:
  POST /api/scans/github    — start a GitHub URL scan (background task)
  POST /api/scans/zip       — start a ZIP upload scan  (background task)
  GET  /api/scans           — list all scans
  GET  /api/scans/{scan_id} — get single scan detail + live progress

Security measures applied here
  - GitHub URL: strict urlparse hostname check + owner/repo path depth guard
    (blocks subdomain spoofing and credential-injection SSRF bypasses)
  - ZIP filename: Path(...).name strips directory components
  - ZIP size: max 50 MB enforced at read time
  - ZIP magic bytes: PK header validated before accepting the file
  - ZIP member paths: validated in scan_orchestrator.run_zip_scan()
  - All endpoints protected by API key (applied at router level in main.py)
"""

import copy
from datetime import datetime
from pathlib import Path
from typing import List
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from pydantic import BaseModel

from backend.services.scan_orchestrator import run_github_scan, run_zip_scan
from backend.api.scan_state import _scans, save_state

router = APIRouter()

_TIMELINE_STEPS = [
    {"id": "0", "name": "Initialise",         "status": "PENDING"},
    {"id": "1", "name": "Static Analysis",     "status": "PENDING"},
    {"id": "2", "name": "Context Enrichment",  "status": "PENDING"},
    {"id": "3", "name": "AI Analysis",         "status": "PENDING"},
    {"id": "4", "name": "Persist Results",     "status": "PENDING"},
]

MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50 MB


# ── Request models ─────────────────────────────────────────────────────────────

class GithubScanRequest(BaseModel):
    """
    JSON body for POST /api/scans/github.

    Using a Pydantic model (instead of Form(...)) keeps all endpoints
    consistent — they all accept application/json — and matches axios's
    default Content-Type behaviour in the frontend, avoiding 400 errors
    caused by a missing form field when the client sends a JSON body.
    """
    repo_url: str


# ── SSRF guard ────────────────────────────────────────────────────────────────

def _validate_github_url(repo_url: str) -> None:
    """
    Strict GitHub URL validation.

    Accepts only:
      https://github.com/<owner>/<repo>
      https://github.com/<owner>/<repo>.git

    Rejects:
      https://github.com.evil.com/...   (subdomain spoofing)
      https://github.com@evil.com/...   (credential-injection)
      https://github.com/owner          (no repo segment — too shallow)
      http://github.com/...             (non-HTTPS)
      file:///etc/passwd                (local file)
      git://internal/repo               (internal network)

    Raises HTTPException(400) on any violation.
    """
    try:
        parsed = urlparse(repo_url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Must be HTTPS
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=400,
            detail="Only HTTPS URLs are accepted",
        )

    # Hostname must be exactly 'github.com' — no subdomains, no userinfo
    if parsed.hostname != "github.com":
        raise HTTPException(
            status_code=400,
            detail="Only public GitHub repositories are accepted (github.com)",
        )

    # Reject URLs with embedded credentials (https://user:pass@github.com/...)
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=400,
            detail="URLs with embedded credentials are not accepted",
        )

    # Path must have at least two non-empty segments: /owner/repo
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(path_parts) < 2:
        raise HTTPException(
            status_code=400,
            detail="URL must point to a specific repository: https://github.com/<owner>/<repo>",
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _new_scan(scan_type: str, target: str) -> dict:
    scan_id = str(uuid4())
    return {
        "id": scan_id,
        "scanType": scan_type,
        "target": target,
        "status": "QUEUED",
        "progress": 0,
        "startedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completedAt": None,
        "duration": None,
        "findingsCount": 0,
        "criticalCount": 0,
        "summary": {},
        "logs": [],
        "timeline": copy.deepcopy(_TIMELINE_STEPS),
        "failureReason": None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/github", status_code=202)
async def scan_github(
    background_tasks: BackgroundTasks,
    payload: GithubScanRequest,
):
    """
    Start an async GitHub repository scan.

    Accepts JSON body:  { "repo_url": "https://github.com/<owner>/<repo>" }

    Returns scan_id immediately; poll GET /api/scans/{scan_id} for progress.
    """
    _validate_github_url(payload.repo_url)

    scan = _new_scan("github", payload.repo_url)
    _scans[scan["id"]] = scan
    save_state()

    background_tasks.add_task(run_github_scan, scan["id"], payload.repo_url)

    return {"scan_id": scan["id"], "status": "QUEUED"}


@router.post("/zip", status_code=202)
async def scan_zip(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """
    Start an async ZIP upload scan.
    Returns scan_id immediately; poll GET /api/scans/{scan_id} for progress.
    """
    # Filename sanitisation — strips any directory path components
    safe_name = Path(file.filename or "upload.zip").name
    if not safe_name.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted")

    # Read entire upload with size cap
    zip_bytes = await file.read()
    if len(zip_bytes) > MAX_ZIP_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"ZIP file exceeds the {MAX_ZIP_SIZE // (1024 * 1024)} MB limit",
        )

    # Magic-bytes validation: ZIP files always start with PK (\x50\x4b)
    if zip_bytes[:2] != b"PK":
        raise HTTPException(
            status_code=400,
            detail="File does not appear to be a valid ZIP archive",
        )

    scan = _new_scan("zip", safe_name)
    _scans[scan["id"]] = scan
    save_state()

    background_tasks.add_task(run_zip_scan, scan["id"], zip_bytes, safe_name)

    return {"scan_id": scan["id"], "status": "QUEUED"}


@router.get("", response_model=List[dict])
def list_scans():
    """Return all scans, newest first."""
    return sorted(
        _scans.values(),
        key=lambda s: s.get("startedAt", ""),
        reverse=True,
    )


@router.get("/{scan_id}")
def get_scan(scan_id: str):
    """Return live scan state including progress, logs, and timeline."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
