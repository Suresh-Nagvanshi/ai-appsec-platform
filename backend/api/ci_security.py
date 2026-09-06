"""CI and developer-tool integration endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.routes.reports import _flatten_finding
from backend.storage.findings_repository import FindingsRepository

router = APIRouter()
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "ERROR": 4}


class SecurityGateRequest(BaseModel):
    scan_id: str
    minimum_severity: str = "HIGH"
    fail_on_status: list[str] = ["open", "in_progress"]


def build_sarif(scan_id: str, findings: list[dict], project_name: str | None = None) -> dict:
    results = []
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        level = "error" if severity in {"CRITICAL", "HIGH", "ERROR"} else "warning" if severity in {"MEDIUM", "LOW"} else "note"
        result = {
            "ruleId": finding.get("rule_id") or "security-finding",
            "level": level,
            "message": {"text": finding.get("message") or finding.get("title") or "Security finding"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.get("path") or "unknown"}, "region": {"startLine": finding.get("line") or 1}}}],
            "properties": {"severity": severity, "status": finding.get("status", "open"), "risk_score": finding.get("risk_score")},
        }
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "AI AppSec Platform", "informationUri": "https://github.com/Suresh-Nagvanshi/ai-appsec-platform", "version": "0.3.0"}}, "automationDetails": {"id": f"ai-appsec/{scan_id}"}, "results": results}],
        "properties": {"project": project_name, "scan_id": scan_id},
    }


def evaluate_security_gate(findings: list[dict], minimum_severity: str, fail_on_status: list[str]) -> dict:
    threshold = _SEVERITY_RANK.get(minimum_severity.upper())
    if threshold is None:
        raise ValueError("minimum_severity must be INFO, LOW, MEDIUM, HIGH, or CRITICAL")
    violations = [
        {"id": finding.get("id"), "severity": finding.get("severity"), "message": finding.get("message"), "path": finding.get("path")}
        for finding in findings
        if _SEVERITY_RANK.get(str(finding.get("severity") or "INFO").upper(), 0) >= threshold
        and str(finding.get("status", "open")).lower() in {status.lower() for status in fail_on_status}
    ]
    return {"passed": not violations, "minimum_severity": minimum_severity.upper(), "violations": violations, "violation_count": len(violations)}


def _load_flat_findings(scan_id: str) -> tuple[dict, list[dict]]:
    scan = FindingsRepository().get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan, [_flatten_finding(finding) for finding in scan.get("findings", [])]


@router.get("/sarif/{scan_id}")
def sarif_export(scan_id: str):
    scan, findings = _load_flat_findings(scan_id)
    return build_sarif(scan_id, findings, scan.get("project_name"))


@router.post("/gate")
def security_gate(payload: SecurityGateRequest):
    scan, findings = _load_flat_findings(payload.scan_id)
    gate = evaluate_security_gate(findings, payload.minimum_severity, payload.fail_on_status)
    return {"scan_id": payload.scan_id, "project_name": scan.get("project_name"), **gate}
