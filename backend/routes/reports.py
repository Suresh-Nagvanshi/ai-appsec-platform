"""
Reports API
===========
Fix history:
  findings[:1]  →  findings  (removed truncation to 1 finding)
  Import path:  from ai_service →  from backend.ai_service
  Early-exit path now returns a consistent full response shape including
    findings:[], project_name, scan_type, summary, format  so the frontend
    never receives a response without a findings key (was crashing on .length).
  Removed redundant re-analysis loop: findings already carry ai_analysis
    from the scan pipeline stored in FindingsRepository — re-running
    analyze_vulnerability on every report generation wasted Groq tokens.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.storage.findings_repository import FindingsRepository

router = APIRouter()
_repo = FindingsRepository()


class ReportRequest(BaseModel):
    scan_id: str
    format: Optional[str] = "json"


@router.post("/generate")
def generate_report(payload: ReportRequest):
    """
    Generate a report for a completed scan.

    Returns a consistent response shape in ALL cases — including when there
    are zero findings — so the frontend never encounters an undefined
    `findings` key.

    Findings are returned as-is from FindingsRepository; they already carry
    ai_analysis from the scan pipeline, so there is no need to re-invoke
    the AI here.
    """
    scan = _repo.get_scan(payload.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.get("findings", [])

    # Always return the full consistent shape — findings:[] when empty.
    # The previous early-exit path omitted findings/project_name/etc which
    # caused TypeError: Cannot read properties of undefined ('length')
    # in the frontend ReportView component.
    return {
        "scan_id": payload.scan_id,
        "project_name": scan.get("project_name"),
        "scan_type": scan.get("scan_type"),
        "summary": scan.get("summary", {}),
        "finding_count": len(findings),
        "findings": findings,
        "format": payload.format,
    }
