"""
FindingsRepository
==================
Persists scan results to JSON files under database/scans/.
Provides:
  save_scan()           — persist a completed scan + findings
  get_all_findings()    — flat list of all findings across all scans
  get_finding_by_id()   — single finding lookup
  update_finding_status() — triage status mutation

Scan IDs are UUID-based (no timestamp collision risk).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

import logging
from backend.db.session import init_db, SessionLocal
from backend.db.models import ScanModel, FindingModel

logger = logging.getLogger(__name__)

_BASE_DIR = Path(__file__).resolve().parent.parent.parent / "database" / "scans"
_BASE_DIR.mkdir(parents=True, exist_ok=True)


class FindingsRepository:

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = Path(base_dir) if base_dir else _BASE_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)
        try:
            init_db()
        except Exception as exc:
            logger.warning("Database init fallback to JSON-only mode: %s", exc)

    # ── Write ──────────────────────────────────────────────────────────────

    def save_scan(
        self,
        project_name: str,
        scan_results: dict | list,
    ) -> str:
        """
        Persist a completed scan.
        scan_results must contain at minimum:
          scan_id    (str)
          results    (list of enriched finding dicts)
          summary    (dict with severity counts)
        Returns the storage_id (== scan_id).
        """
        if isinstance(scan_results, list):
            scan_results = {"results": scan_results}

        scan_id = scan_results.get("scan_id") or str(uuid4())

        # Stamp every finding with scan_id + default status
        findings = scan_results.get("results", [])
        for i, finding in enumerate(findings):
            finding.setdefault("id", str(uuid4()))
            finding.setdefault("scan_id", scan_id)
            finding.setdefault("status", "open")
            finding.setdefault("created_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

        record = {
            "scan_id": scan_id,
            "project_name": project_name,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scan_type": scan_results.get("scan_type", "unknown"),
            "summary": scan_results.get("summary", {}),
            "findings": findings,
        }

        # 1. JSON file persistence
        scan_file = self.base_dir / f"{scan_id}.json"
        scan_file.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

        # 2. Database ORM persistence
        try:
            db = SessionLocal()
            existing = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if not existing:
                scan_orm = ScanModel(
                    id=scan_id,
                    project_name=project_name,
                    scan_type=scan_results.get("scan_type", "static"),
                    status="COMPLETED",
                    progress=100,
                    summary_json=scan_results.get("summary", {})
                )
                db.add(scan_orm)
                for f in findings:
                    rep = f.get("representative_finding") or {}
                    raw_f = rep.get("finding") or f.get("finding") or f
                    risk = rep.get("risk") or f.get("risk") or {}
                    finding_orm = FindingModel(
                        id=f.get("id"),
                        scan_id=scan_id,
                        rule_id=raw_f.get("rule_id", "security-finding"),
                        severity=raw_f.get("severity") or risk.get("severity") or "INFO",
                        file_path=raw_f.get("path", ""),
                        line_number=raw_f.get("line"),
                        message=raw_f.get("message", ""),
                        cwe=raw_f.get("cwe", [None])[0] if isinstance(raw_f.get("cwe"), list) else raw_f.get("cwe"),
                        owasp=raw_f.get("owasp", [None])[0] if isinstance(raw_f.get("owasp"), list) else raw_f.get("owasp"),
                        status=f.get("status", "open"),
                        risk_score=float(risk.get("risk_score", 0.0)),
                        exploitability=risk.get("exploitability"),
                        priority=risk.get("priority"),
                        raw_payload_json=f
                    )
                    db.add(finding_orm)
                db.commit()
            db.close()
        except Exception as exc:
            logger.warning("Failed to persist scan to DB ORM: %s", exc)

        return scan_id

    # ── Read ───────────────────────────────────────────────────────────────

    def get_all_findings(self) -> List[dict]:
        """
        Return a flat list of all findings from all scan files,
        newest scans first.
        """
        findings: List[dict] = []
        for scan_file in sorted(self.base_dir.glob("*.json"), reverse=True):
            try:
                record = json.loads(scan_file.read_text(encoding="utf-8"))
                findings.extend(record.get("findings", []))
            except Exception:
                continue
        return findings

    def get_finding_by_id(self, finding_id: str) -> Optional[dict]:
        """Search all scan files for a finding by its id field."""
        for scan_file in self.base_dir.glob("*.json"):
            try:
                record = json.loads(scan_file.read_text(encoding="utf-8"))
                for finding in record.get("findings", []):
                    if finding.get("id") == finding_id:
                        return finding
            except Exception:
                continue
        return None

    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Return the full scan record (findings + summary) by scan_id."""
        scan_file = self.base_dir / f"{scan_id}.json"
        if not scan_file.exists():
            return None
        try:
            return json.loads(scan_file.read_text(encoding="utf-8"))
        except Exception:
            return None

    def list_scans(self) -> List[dict]:
        """Return persisted scan records, newest first."""
        scans: List[dict] = []
        for scan_file in sorted(self.base_dir.glob("*.json"), reverse=True):
            try:
                scans.append(json.loads(scan_file.read_text(encoding="utf-8")))
            except Exception:
                continue
        return scans

    # ── Mutate ─────────────────────────────────────────────────────────────

    def update_finding_status(self, finding_id: str, status: str) -> bool:
        """
        Update the status field of a single finding in-place.
        Returns True if found and updated, False if not found.
        """
        for scan_file in self.base_dir.glob("*.json"):

            try:
                record = json.loads(scan_file.read_text(encoding="utf-8"))
                for finding in record.get("findings", []):
                    if finding.get("id") == finding_id:
                        finding["status"] = status
                        scan_file.write_text(
                            json.dumps(record, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )
                        return True
            except Exception:
                continue
        return False
