"""
Scans API
=========
Endpoints:
  POST /api/scans/github    — start a GitHub URL scan (background task)
  POST /api/scans/zip       — start a ZIP upload scan  (background task)
  GET  /api/scans           — list all scans
  GET  /api/scans/{scan_id} — get single scan detail + live progress

Security measures applied here
  - GitHub URL: must start with https://github.com/ (SSRF guard)
  - ZIP filename: Path(...).name strips directory components
  - ZIP size: max 50 MB enforced at read time
  - ZIP member paths: validated in scan_orchestrator.run_zip_scan()
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile

from backend.services.scan_orchestrator import run_github_scan, run_zip_scan

router = APIRouter()

# ── In-memory scan store ─────────────────────────────────────────────────────
# Shared module to avoid circular imports with scan_orchestrator.
from backend.api.scan_state import _scans

_TIMELINE_STEPS = [
    {"id": "0", "name": "Initialise",         "status": "PENDING"},
    {"id": "1", "name": "Static Analysis",    "status": "PENDING"},
    {"id": "2", "name": "Context Enrichment", "status": "PENDING"},
    {"id": "3", "name": "AI Analysis",        "status": "PENDING"},
    {"id": "4", "name": "Persist Results",    "status": "PENDING"},
]

MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50 MB


def _new_scan(scan_type: str, target: str) -> dict:
    import copy
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
    repo_url: str = Form(...),
):
    """
    Start an async GitHub repository scan.
    Returns scan_id immediately; poll GET /api/scans/{scan_id} for progress.
    """
    # SSRF guard: only public GitHub HTTPS URLs
    if not repo_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=400,
            detail="Only public GitHub HTTPS URLs are accepted (https://github.com/...)",
        )

    scan = _new_scan("github", repo_url)
    _scans[scan["id"]] = scan

    background_tasks.add_task(run_github_scan, scan["id"], repo_url)

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
    # File name sanitisation — strips directory components
    safe_name = Path(file.filename or "upload.zip").name
    if not safe_name.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted")

    # Read with size limit
    zip_bytes = await file.read()
    if len(zip_bytes) > MAX_ZIP_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"ZIP file exceeds the {MAX_ZIP_SIZE // (1024*1024)} MB limit",
        )

    # ZIP magic-bytes validation (PK header)
    if not zip_bytes[:2] == b"PK":
        raise HTTPException(status_code=400, detail="File does not appear to be a valid ZIP archive")

    scan = _new_scan("zip", safe_name)
    _scans[scan["id"]] = scan

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
