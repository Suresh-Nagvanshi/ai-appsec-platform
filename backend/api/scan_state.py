"""
Shared scan state with database persistence.
===========================================
The API and orchestrator still use the in-memory _scans dict, but it is now
backed by the SQLAlchemy Scan table so state survives restarts without
relying on a JSON file.
"""

import logging
from datetime import datetime

from sqlalchemy import select

from backend.db.models import Scan
from backend.db.session import SessionLocal, init_db

logger = logging.getLogger(__name__)

# ── Load from database on import (i.e. server start) ───────────────────────
_scans: dict = {}


def _load_from_db() -> dict:
    init_db()
    with SessionLocal() as session:
        rows = session.scalars(select(Scan).order_by(Scan.created_at.asc())).all()
    scans = {}
    for row in rows:
        scans[row.id] = {
            "id": row.id,
            "scanType": row.scan_type,
            "target": row.source_url or row.project_name,
            "status": row.status,
            "progress": row.progress,
            "startedAt": row.created_at.isoformat() if row.created_at else None,
            "completedAt": row.completed_at.isoformat() if row.completed_at else None,
            "duration": None,
            "findingsCount": 0,
            "criticalCount": (row.summary or {}).get("critical", 0),
            "summary": row.summary or {},
            "logs": row.logs or [],
            "timeline": row.timeline or [],
            "failureReason": None,
        }
    return scans


_scans = _load_from_db()


def _coerce_datetime(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return value


def save_state() -> None:
    """Persist the current _scans dict to the database."""
    try:
        init_db()
        with SessionLocal() as session:
            for scan_id, scan_data in _scans.items():
                scan = session.get(Scan, scan_id)
                if scan is None:
                    scan = Scan(
                        id=scan_id,
                        status=scan_data.get("status", "QUEUED"),
                        progress=scan_data.get("progress", 0),
                        scan_type=scan_data.get("scanType", "unknown"),
                        project_name=scan_data.get("target") or "unknown",
                        source_url=scan_data.get("target"),
                        summary=scan_data.get("summary", {}),
                        created_at=_coerce_datetime(scan_data.get("startedAt")),
                        completed_at=_coerce_datetime(scan_data.get("completedAt")),
                        timeline=scan_data.get("timeline", []),
                        logs=scan_data.get("logs", []),
                    )
                    session.add(scan)
                else:
                    scan.status = scan_data.get("status", scan.status)
                    scan.progress = scan_data.get("progress", scan.progress)
                    scan.scan_type = scan_data.get("scanType", scan.scan_type)
                    scan.project_name = scan_data.get("project_name") or scan.project_name
                    scan.source_url = scan_data.get("target") or scan.source_url
                    scan.summary = scan_data.get("summary", scan.summary)
                    scan.timeline = scan_data.get("timeline", scan.timeline)
                    scan.logs = scan_data.get("logs", scan.logs)
                    if scan_data.get("completedAt"):
                        scan.completed_at = _coerce_datetime(scan_data.get("completedAt"))
                    elif scan_data.get("status") == "COMPLETED":
                        scan.completed_at = scan.completed_at or scan.created_at
            session.commit()
    except Exception as exc:
        logger.warning("Could not persist scan state: %s", exc)
