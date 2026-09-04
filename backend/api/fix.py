"""
Fix Suggestion API
==================
Provides on-demand, language-specific secure code fix suggestions
for a specific finding within a completed scan.

Endpoints:
  GET  /api/fix/{scan_id}/{finding_index}
       Returns a structured fix with before/after code, explanation,
       and testing guidance — powered by FixSuggestionChain (RAG + Groq).

Authentication: X-API-Key header (via require_api_key dependency in main.py)
"""

import difflib
import logging
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.storage.findings_repository import FindingsRepository

logger = logging.getLogger(__name__)

router = APIRouter()

class DirectFixRequest(BaseModel):
    language: Optional[str] = "python"
    path: Optional[str] = "app.py"
    vulnerable_code: str
    rule_id: Optional[str] = "security-finding"
    message: Optional[str] = "Potential security vulnerability"

def generate_unified_diff(vulnerable_code: str, secure_code: str, file_path: str = "vulnerable_file") -> str:
    if not vulnerable_code or not secure_code:
        return ""
    vuln_lines = [l + "\n" for l in vulnerable_code.splitlines()]
    secure_lines = [l + "\n" for l in secure_code.splitlines()]
    diff = difflib.unified_diff(
        vuln_lines,
        secure_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(diff)

@router.post(
    "/generate",
    summary="Generate fix for custom finding payload",
    description="Generates secure remediation code and unified diff for raw finding input.",
)
async def generate_direct_fix(payload: DirectFixRequest) -> Dict[str, Any]:
    finding = {
        "finding": {
            "rule_id": payload.rule_id,
            "message": payload.message,
            "path": payload.path,
            "extra": {"lines": payload.vulnerable_code, "message": payload.message},
            "metadata": {"language": payload.language},
        }
    }
    
    if os.getenv("GROQ_API_KEY"):
        try:
            from backend.ai.chains.fix_suggestion_chain import FixSuggestionChain
            fix = FixSuggestionChain().generate_fix(finding)
        except Exception as exc:
            logger.warning("AI fix generation failed: %s; using fallback", exc)
            fix = _local_fix(finding)
    else:
        fix = _local_fix(finding)
        
    fix["diff_patch"] = generate_unified_diff(
        fix.get("vulnerable_code", payload.vulnerable_code),
        fix.get("secure_code", ""),
        payload.path or "source_file"
    )
    return {"fix": fix}

@router.get(
    "/{scan_id}/{finding_index}",
    summary="Generate secure fix for a finding",
    description=(
        "Retrieves the finding at *finding_index* from the scan result, "
        "then uses the RAG-augmented FixSuggestionChain to generate a "
        "language-specific secure code fix with before/after snippets."
    ),
)
async def get_fix_suggestion(
    scan_id: str,
    finding_index: int,
) -> Dict[str, Any]:
    # 1. Load scan from findings repository
    findings_repo = FindingsRepository()
    scan = findings_repo.get_scan(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan '{scan_id}' not found.",
        )

    results = scan.get("findings", [])
    if finding_index < 0 or finding_index >= len(results):
        raise HTTPException(
            status_code=404,
            detail=(
                f"Finding index {finding_index} out of range. "
                f"Scan has {len(results)} findings."
            ),
        )

    finding = results[finding_index]

    # 2. Extract the representative finding if deduplicated group format
    if "representative_finding" in finding:
        finding = finding["representative_finding"]

    # 3. Generate a local fallback unless the optional AI provider is ready.
    try:
        if not os.getenv("GROQ_API_KEY"):
            fix = _local_fix(finding)
        else:
            try:
                from backend.ai.chains.fix_suggestion_chain import FixSuggestionChain

                fix = FixSuggestionChain().generate_fix(finding)
            except Exception as exc:
                logger.warning("AI fix unavailable; returning local guidance: %s", exc)
                fix = _local_fix(finding)
                
        vuln_code = fix.get("vulnerable_code", "")
        sec_code = fix.get("secure_code", "")
        filePath = finding.get("finding", {}).get("path", "file")
        fix["diff_patch"] = generate_unified_diff(vuln_code, sec_code, filePath)

        return {
            "scan_id": scan_id,
            "finding_index": finding_index,
            "fix": fix,
        }
    except Exception as exc:
        logger.error("FixSuggestionChain failed for scan=%s index=%d: %s",
                     scan_id, finding_index, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Fix generation failed: {exc}",
        )


def _local_fix(finding: dict) -> Dict[str, Any]:
    """Return useful deterministic guidance when AI is not configured."""
    raw = finding.get("finding", finding)
    vulnerable_code = raw.get("extra", {}).get("lines") or raw.get("snippet", {}).get("vulnerable_line", "")
    secure_code = f"# Secure Fix:\n# {raw.get('extra', {}).get('message', 'Apply parameterized input validation')}"
    
    return {
        "language": raw.get("metadata", {}).get("language", "unknown"),
        "vulnerable_code": vulnerable_code,
        "secure_code": secure_code,
        "explanation": raw.get("extra", {}).get("message", "Review and remediate this finding."),
        "security_libraries": [],
        "additional_hardening": [
            "Use parameterized input queries and sanitize untrusted input.",
            "Enforce strict input length and type validation."
        ],
        "testing_guidance": "Re-run the static analysis scan and add a unit test for vulnerable inputs.",
        "ai_unavailable": True,
    }

