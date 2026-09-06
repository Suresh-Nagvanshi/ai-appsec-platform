"""Security regression-test registry and evaluation API."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.storage.diff_analyzer import DiffAnalyzer
from backend.storage.findings_repository import FindingsRepository

router = APIRouter()
_BASE_DIR = Path(__file__).resolve().parent.parent.parent / "database"
_REGRESSION_FILE = _BASE_DIR / "regression_tests.json"
_ANALYZER = DiffAnalyzer()


class RegressionGenerateRequest(BaseModel):
    scan_id: str = Field(min_length=1)
    finding_ids: list[str] | None = None


class RegressionEvaluateRequest(BaseModel):
    scan_id: str = Field(min_length=1)
    test_ids: list[str] | None = None


def _load_tests() -> list[dict]:
    if not _REGRESSION_FILE.exists():
        return []
    try:
        return json.loads(_REGRESSION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _save_tests(tests: list[dict]) -> None:
    _BASE_DIR.mkdir(parents=True, exist_ok=True)
    _REGRESSION_FILE.write_text(json.dumps(tests, indent=2), encoding="utf-8")


def create_regression_specs(scan_id: str, findings: list[dict], finding_ids: set[str] | None = None) -> list[dict]:
    """Convert persisted findings into stable regression-test specifications."""
    specifications = []
    for finding in findings:
        finding_id = str(finding.get("id", ""))
        if not finding_id or (finding_ids and finding_id not in finding_ids):
            continue
        if finding.get("status") == "false_positive":
            continue
        raw = finding.get("representative_finding", {}).get("finding") or finding.get("finding") or finding
        specifications.append({
            "id": str(uuid4()),
            "scan_id": scan_id,
            "finding_id": finding_id,
            "fingerprint": _ANALYZER._generate_fingerprint(finding),
            "rule_id": raw.get("rule_id", "security-finding"),
            "path": raw.get("path", ""),
            "expected": "finding_absent",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
    return specifications


def evaluate_regression_specs(specifications: list[dict], current_findings: list[dict]) -> dict:
    """Check whether previously fixed findings have reappeared."""
    current_by_fingerprint = {
        _ANALYZER._generate_fingerprint(finding): finding
        for finding in current_findings
    }
    results = []
    for specification in specifications:
        reappeared = specification["fingerprint"] in current_by_fingerprint
        results.append({
            "test_id": specification["id"],
            "finding_id": specification["finding_id"],
            "status": "FAIL" if reappeared else "PASS",
            "expected": specification["expected"],
            "current_finding": current_by_fingerprint.get(specification["fingerprint"]),
        })
    failed = sum(result["status"] == "FAIL" for result in results)
    return {"status": "FAIL" if failed else "PASS", "tested": len(results), "failed": failed, "results": results}


@router.post("/generate")
def generate_regression_tests(payload: RegressionGenerateRequest):
    repository = FindingsRepository()
    scan = repository.get_scan(payload.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    specifications = create_regression_specs(
        payload.scan_id,
        scan.get("findings", scan.get("results", [])),
        set(payload.finding_ids) if payload.finding_ids else None,
    )
    tests = [test for test in _load_tests() if test.get("scan_id") != payload.scan_id]
    tests.extend(specifications)
    _save_tests(tests)
    return {"scan_id": payload.scan_id, "created": len(specifications), "tests": specifications}


@router.get("")
def list_regression_tests():
    return {"total": len(_load_tests()), "tests": _load_tests()}


@router.post("/evaluate")
def evaluate_regression_tests(payload: RegressionEvaluateRequest):
    repository = FindingsRepository()
    current_scan = repository.get_scan(payload.scan_id)
    if not current_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    tests = _load_tests()
    if payload.test_ids:
        tests = [test for test in tests if test.get("id") in payload.test_ids]
    return {"scan_id": payload.scan_id, **evaluate_regression_specs(tests, current_scan.get("findings", current_scan.get("results", [])))}
