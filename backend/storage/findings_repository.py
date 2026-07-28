"""
FindingsRepository
==================
Persists scan results in the database using SQLAlchemy.

The public interface remains compatible with the routes and orchestrator:
  save_scan()           — persist a completed scan + findings
  get_all_findings()    — flat list of all findings across all scans
  get_finding_by_id()   — single finding lookup
  update_finding_status() — triage status mutation
  get_scan()            — full scan record
"""

import json
from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select

from backend.db.models import Finding, Scan
from backend.db.session import SessionLocal, init_db


class FindingsRepository:
    def __init__(self) -> None:
        init_db()

    # ── Write ──────────────────────────────────────────────────────────────

    def save_scan(
        self,
        project_name: str,
        scan_results: dict,
    ) -> str:
        """Persist a completed scan and its findings."""
        scan_id = scan_results.get("scan_id") or str(uuid4())
        with SessionLocal() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                scan = Scan(
                    id=scan_id,
                    status="COMPLETED",
                    scan_type=scan_results.get("scan_type", "unknown"),
                    project_name=project_name,
                    source_url=scan_results.get("repository_url") or scan_results.get("filename"),
                    summary=scan_results.get("summary", {}),
                    created_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    timeline=[],
                    logs=[],
                )
                session.add(scan)
            else:
                scan.status = "COMPLETED"
                scan.scan_type = scan_results.get("scan_type", "unknown")
                scan.project_name = project_name
                scan.source_url = scan_results.get("repository_url") or scan_results.get("filename")
                scan.summary = scan_results.get("summary", {})
                scan.completed_at = datetime.utcnow()

            findings = scan_results.get("results", [])
            for finding in findings:
                finding_id = finding.get("id") or str(uuid4())
                if not session.get(Finding, finding_id):
                    session.add(
                        Finding(
                            id=finding_id,
                            scan_id=scan_id,
                            rule_id=finding.get("finding", {}).get("rule_id") or finding.get("rule_id"),
                            severity=(finding.get("severity") or finding.get("finding", {}).get("severity") or "").upper(),
                            status=finding.get("status", "open"),
                            path=(finding.get("path") or finding.get("finding", {}).get("path")),
                            line=finding.get("line") or finding.get("finding", {}).get("line"),
                            message=(finding.get("message") or finding.get("finding", {}).get("message")),
                            cwe=(finding.get("cwe") or finding.get("finding", {}).get("cwe")),
                            owasp=(finding.get("owasp") or finding.get("finding", {}).get("owasp")),
                            risk_score=(finding.get("risk", {}).get("risk_score") or finding.get("risk_score")),
                            exploitability=(finding.get("risk", {}).get("exploitability") or finding.get("exploitability")),
                            priority=(finding.get("risk", {}).get("priority") or finding.get("priority")),
                            total_occurrences=finding.get("total_occurrences", 1),
                            representative_finding=finding.get("representative_finding") or finding,
                            related_findings=finding.get("related_findings") or [],
                            ai_analysis=finding.get("ai_analysis"),
                            created_at=datetime.utcnow(),
                        )
                    )
            session.commit()
            return scan_id

    # ── Read ───────────────────────────────────────────────────────────────

    def get_all_findings(self) -> List[dict]:
        """Return a flat list of all findings from all scans."""
        with SessionLocal() as session:
            statement = select(Finding).order_by(Finding.created_at.desc())
            findings = session.scalars(statement).all()

        return [self._serialize_finding(f) for f in findings]

    def get_finding_by_id(self, finding_id: str) -> Optional[dict]:
        """Return a finding by its id."""
        with SessionLocal() as session:
            finding = session.get(Finding, finding_id)
        if finding is None:
            return None
        return self._serialize_finding(finding)

    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Return the full scan record (findings + summary) by scan_id."""
        with SessionLocal() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return None
            findings = [self._serialize_finding(f) for f in scan.findings]
            return {
                "scan_id": scan.id,
                "project_name": scan.project_name,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "scan_type": scan.scan_type,
                "summary": scan.summary or {},
                "findings": findings,
                "status": scan.status,
                "timeline": scan.timeline or [],
                "logs": scan.logs or [],
            }

    def list_scans(self) -> List[dict]:
        with SessionLocal() as session:
            scans = session.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
        return [
            {
                "id": scan.id,
                "scanType": scan.scan_type,
                "target": scan.source_url,
                "status": scan.status,
                "progress": 100 if scan.status == "COMPLETED" else 0,
                "startedAt": scan.created_at.isoformat() if scan.created_at else None,
                "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration": None,
                "findingsCount": len(scan.findings),
                "criticalCount": (scan.summary or {}).get("critical", 0),
                "summary": scan.summary or {},
                "logs": scan.logs or [],
                "timeline": scan.timeline or [],
                "failureReason": None,
            }
            for scan in scans
        ]

    # ── Mutate ─────────────────────────────────────────────────────────────

    def update_finding_status(self, finding_id: str, status: str) -> bool:
        """Update the status field of a single finding."""
        with SessionLocal() as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return False
            finding.status = status
            session.commit()
            return True

    def _serialize_finding(self, finding: Finding) -> dict:
        rep = finding.representative_finding or {}
        if isinstance(rep, str):
            rep = json.loads(rep)
        return {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "status": finding.status,
            "severity": finding.severity,
            "path": finding.path,
            "line": finding.line,
            "message": finding.message,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "risk_score": finding.risk_score,
            "exploitability": finding.exploitability,
            "priority": finding.priority,
            "total_occurrences": finding.total_occurrences,
            "representative_finding": rep,
            "related_findings": finding.related_findings or [],
            "ai_analysis": finding.ai_analysis,
            "rule_id": finding.rule_id,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }
