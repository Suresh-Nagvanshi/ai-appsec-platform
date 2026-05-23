"""
Findings API
============
Endpoints:
  GET  /findings                     — list all findings across all scans
  GET  /findings/{finding_id}        — get a single finding by its id
  PATCH /findings/{finding_id}/status — update finding status

All data comes from FindingsRepository (JSON files in database/).
The previous version returned 3 hardcoded mock findings — removed.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.storage.findings_repository import FindingsRepository

router = APIRouter()
_repo = FindingsRepository()


class StatusUpdate(BaseModel):
    status: str  # open | in_progress | resolved | false_positive


@router.get("")
def get_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """
    Return findings from FindingsRepository with optional filters.
    Supports scan_id, severity, and status query params.
    """
    try:
        all_findings = _repo.get_all_findings()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Storage read error: {exc}")

    # Filter
    if scan_id:
        all_findings = [f for f in all_findings if f.get("scan_id") == scan_id]
    if severity:
        all_findings = [
            f for f in all_findings
            if (f.get("severity") or "").upper() == severity.upper()
        ]
    if status:
        all_findings = [
            f for f in all_findings
            if (f.get("status") or "open").lower() == status.lower()
        ]

    total = len(all_findings)
    page = all_findings[offset : offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": page,
    }


@router.get("/{finding_id}")
def get_finding(finding_id: str):
    """Return a single finding by its id."""
    try:
        finding = _repo.get_finding_by_id(finding_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Storage read error: {exc}")

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding


@router.patch("/{finding_id}/status")
def update_finding_status(finding_id: str, payload: StatusUpdate):
    """
    Update the status of a finding (triage workflow).
    Valid statuses: open, in_progress, resolved, false_positive
    """
    valid = {"open", "in_progress", "resolved", "false_positive"}
    if payload.status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {sorted(valid)}",
        )

    try:
        updated = _repo.update_finding_status(finding_id, payload.status)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Storage write error: {exc}")

    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {"ok": True, "finding_id": finding_id, "status": payload.status}
