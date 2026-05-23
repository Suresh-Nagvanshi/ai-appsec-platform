from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime
from typing import Optional, List

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────
# In-memory scan store (MVP).  Replace with DB in post-MVP.
# ─────────────────────────────────────────────────────────────────────────
_scans: dict = {}


# ─────────────────────────────────
# Request / Response Models
# ─────────────────────────────────

class ScanRequest(BaseModel):
    repository_url: str
    scan_type: Optional[str] = "Full Scan"


class ScanResponse(BaseModel):
    scan_id: str
    status: str


class TimelineStep(BaseModel):
    id: str
    title: str
    status: str  # PENDING | RUNNING | COMPLETED | FAILED


class ScanLog(BaseModel):
    id: str
    time: str
    level: str  # INFO | WARNING | ERROR
    message: str


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanDetail(BaseModel):
    id: str
    repositoryName: str
    scanType: str
    status: str
    progress: int
    findingsCount: Optional[int] = 0
    criticalCount: Optional[int] = 0
    startedAt: str
    duration: Optional[str] = "-"
    failureReason: Optional[str] = None
    summary: Optional[ScanSummary] = None
    timeline: Optional[List[TimelineStep]] = None
    logs: Optional[List[ScanLog]] = None


# ─────────────────────────────────
# Endpoints
# ─────────────────────────────────

@router.post("/start", response_model=ScanResponse)
async def start_scan(payload: ScanRequest):
    """
    Accepts repository_url + scan_type.
    Creates a scan record in the in-memory store.
    Returns scan_id for the frontend to poll.
    """
    scan_id = str(uuid4())
    repo_name = payload.repository_url.rstrip("/").split("/")[-1].replace(".git", "")

    _scans[scan_id] = {
        "id": scan_id,
        "repositoryName": repo_name,
        "scanType": payload.scan_type,
        "status": "QUEUED",
        "progress": 0,
        "findingsCount": 0,
        "criticalCount": 0,
        "startedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration": "-",
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "timeline": [
            {"id": "0", "title": "Repository Imported", "status": "PENDING"},
            {"id": "1", "title": "Static Analysis", "status": "PENDING"},
            {"id": "2", "title": "Dependency Scan", "status": "PENDING"},
            {"id": "3", "title": "AI Analysis", "status": "PENDING"},
            {"id": "4", "title": "Report Generation", "status": "PENDING"},
        ],
        "logs": [
            {
                "id": str(uuid4()),
                "time": datetime.utcnow().strftime("%H:%M:%S"),
                "level": "INFO",
                "message": f"Scan queued for {repo_name}"
            }
        ]
    }

    return ScanResponse(scan_id=scan_id, status="QUEUED")


@router.get("/", response_model=List[ScanDetail])
def get_scans():
    """Return all scans. Replaces localStorage in the frontend."""
    return list(_scans.values())


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan_by_id(scan_id: str):
    """Return a single scan by ID."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/status")
def get_scan_status(scan_id: str):
    """
    Polling endpoint for scan detail page.
    Returns full scan object including timeline, logs and summary.
    Frontend polls this every 3 seconds via useScanDetails hook.
    """
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
