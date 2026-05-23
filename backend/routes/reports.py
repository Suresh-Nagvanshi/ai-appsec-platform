"""
Reports API
===========
Fix applied vs original:
  findings[:1]  →  findings  (removed slice that truncated to 1 finding)
  Import path:  from ai_service →  from backend.ai_service
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.ai_service import analyze_vulnerability
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
    Processes ALL findings (no longer truncated to 1).
    """
    scan = _repo.get_scan(payload.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.get("findings", [])
    if not findings:
        return {
            "scan_id": payload.scan_id,
            "report": "No findings to report.",
            "finding_count": 0,
        }

    # Analyse ALL findings (original code had findings[:1])
    analysed = []
    for finding in findings:
        try:
            result = analyze_vulnerability(finding)
            analysed.append(result)
        except Exception as exc:
            analysed.append({"error": str(exc), "finding": finding})

    return {
        "scan_id": payload.scan_id,
        "project_name": scan.get("project_name"),
        "scan_type": scan.get("scan_type"),
        "summary": scan.get("summary", {}),
        "finding_count": len(analysed),
        "findings": analysed,
        "format": payload.format,
    }
