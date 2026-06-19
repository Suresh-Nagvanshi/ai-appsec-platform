"""
Reports API
===========
Fix history:
  findings[:1]  →  findings  (removed truncation to 1 finding)
  Import path:  from ai_service  →  from backend.ai_service
  Early-exit path now returns a consistent full response shape including
    findings:[], project_name, scan_type, summary, format  so the frontend
    never receives a response without a findings key.
  Removed redundant re-analysis loop: findings already carry ai_analysis
    from the scan pipeline stored in FindingsRepository.
  Flatten deduplicated group objects: FindingsRepository stores each
    finding as a deduplicated group  { representative_finding: { finding:
    {...}, risk: {...}, ai_analysis: {...} }, ... }. The report endpoint
    now extracts and flattens these into the flat ReportFinding shape the
    frontend expects (rule_id, severity, path, line, risk_score, etc.)
  Severity normalisation: Semgrep emits ERROR / WARNING / NOTE / INFO.
    The frontend SEV_STYLES map only handles CRITICAL / HIGH / MEDIUM /
    LOW / INFO.  _flatten_finding() now maps Semgrep levels → standard
    security labels so badges render with the correct colour.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from backend.storage.findings_repository import FindingsRepository

router = APIRouter()
_repo = FindingsRepository()

# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------
# Semgrep native levels  →  security-standard labels used by the frontend
# SEV_STYLES map (CRITICAL / HIGH / MEDIUM / LOW / INFO).
#
# Priority order inside _flatten_finding:
#   1. risk.severity   — already normalised by RiskScorer; prefer this.
#   2. _SEMGREP_SEV_MAP translation of finding.severity.
#   3. finding.severity as-is (pass-through for unknown values).
# ---------------------------------------------------------------------------
_SEMGREP_SEV_MAP: dict[str, str] = {
    "ERROR":   "CRITICAL",
    "WARNING": "HIGH",
    "NOTE":    "MEDIUM",
    "INFO":    "INFO",
}


def _normalise_severity(raw: Optional[str], risk_sev: Optional[str]) -> Optional[str]:
    """
    Return the best severity label for display.

    - If the risk scorer has already produced a standard label, use it.
    - Otherwise translate the raw Semgrep level via _SEMGREP_SEV_MAP.
    - Unknown values pass through unchanged.
    """
    if risk_sev:
        upper = risk_sev.upper()
        if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            return upper
    if raw:
        return _SEMGREP_SEV_MAP.get(raw.upper(), raw.upper())
    return raw


class ReportRequest(BaseModel):
    scan_id: str
    format: Optional[str] = "json"


def _flatten_finding(group: dict) -> dict:
    """
    Convert a deduplicated FindingsRepository group object into the flat
    ReportFinding shape expected by the frontend.

    Storage shape (per group):
      {
        "id": "...",
        "scan_id": "...",
        "status": "open",
        "total_occurrences": 3,
        "representative_finding": {
          "finding": {
            "rule_id": "...", "severity": "ERROR",
            "path": "...",   "line": 12,
            "message": "...", "cwe": "...", "owasp": "..."
          },
          "risk":        { "risk_score": 10, "severity": "CRITICAL", "exploitability": "Very High", "priority": "P1" },
          "ai_analysis": { ... } | { "error": "..." }
        },
        "related_findings": [...]
      }

    Target shape (flat, matches frontend ReportFinding interface):
      {
        "id": "...",
        "scan_id": "...",
        "status": "open",
        "rule_id":   "...",
        "severity":  "CRITICAL",   ← normalised from ERROR
        "path":      "...",
        "line":      12,
        "message":   "...",
        "cwe":       "...",
        "owasp":     "...",
        "risk_score": 10,
        "exploitability": "Very High",
        "priority": "P1",
        "ai_analysis": { ... },
        "total_occurrences": 3
      }

    If the group is already flat (does not have representative_finding),
    severity is still normalised before returning so legacy data gets the
    same treatment.
    """
    rep = group.get("representative_finding")
    if not rep:
        # Already flat — legacy or manually-created finding.
        # Still normalise the severity field in-place.
        raw_sev = group.get("severity")
        return {
            **group,
            "severity": _normalise_severity(raw_sev, group.get("risk", {}).get("severity")),
        }

    finding   = rep.get("finding")     or {}
    risk      = rep.get("risk")        or {}
    ai        = rep.get("ai_analysis") or {}
    snippet   = rep.get("snippet")     or finding.get("snippet")   or {}
    framework = rep.get("framework")   or finding.get("framework") or {}
    metadata  = rep.get("metadata")    or finding.get("metadata")  or {}

    return {
        # Identity
        "id":                group.get("id"),
        "scan_id":           group.get("scan_id"),
        "status":            group.get("status", "open"),
        "total_occurrences": group.get("total_occurrences", 1),
        # Core finding fields
        "rule_id":  finding.get("rule_id"),
        "title":    finding.get("rule_id"),  # title alias for display
        "severity": _normalise_severity(
            finding.get("severity"),
            risk.get("severity"),
        ),
        "message":  finding.get("message"),
        "path":     finding.get("path"),
        "line":     finding.get("line"),
        "scanner":  finding.get("scanner"),
        # Taxonomy
        "cwe":      finding.get("cwe"),
        "owasp":    finding.get("owasp"),
        "mitre":    finding.get("mitre"),
        "framework": framework,
        # Risk
        "risk_score":     risk.get("risk_score"),
        "exploitability": risk.get("exploitability"),
        "priority":       risk.get("priority"),
        "confidence":     risk.get("confidence"),
        # Code snippet
        "snippet":  snippet,
        # Metadata
        "metadata": metadata,
        # AI analysis — may be a result dict or { "error": "..." }
        "ai_analysis": ai if not ai.get("error") else None,
        # Surface AI errors separately so the frontend can show them
        "error":    ai.get("error"),
    }


@router.post("/generate")
def generate_report(payload: ReportRequest):
    """
    Generate a report for a completed scan.

    Returns a consistent response shape in ALL cases — including when
    there are zero findings — so the frontend never encounters an
    undefined `findings` key.

    Each deduplicated group from FindingsRepository is flattened and
    severity-normalised before returning so the frontend SEV_STYLES map
    renders the correct badge colour for every finding.
    """
    scan = _repo.get_scan(payload.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    raw_findings = scan.get("findings", [])
    findings = [_flatten_finding(f) for f in raw_findings]

    return {
        "scan_id":        payload.scan_id,
        "project_name":  scan.get("project_name"),
        "scan_type":     scan.get("scan_type"),
        "summary":       scan.get("summary", {}),
        "finding_count": len(findings),
        "findings":      findings,
        "format":        payload.format,
    }
