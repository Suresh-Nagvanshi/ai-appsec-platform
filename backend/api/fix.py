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

import logging
import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from backend.storage.findings_repository import FindingsRepository

logger = logging.getLogger(__name__)

router = APIRouter()

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
    """
    Returns a structured fix dict:
      {
        language, vulnerable_code, secure_code,
        explanation, security_libraries,
        additional_hardening, testing_guidance
      }
    """
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
    return {
        "language": raw.get("metadata", {}).get("language", "unknown"),
        "vulnerable_code": raw.get("extra", {}).get("lines", ""),
        "secure_code": "Apply the scanner rule's recommended remediation at this location.",
        "explanation": raw.get("extra", {}).get("message", "Review and remediate this finding."),
        "security_libraries": [],
        "additional_hardening": [],
        "testing_guidance": "Re-run the scan and add a regression test for the vulnerable input.",
        "ai_unavailable": True,
    }
