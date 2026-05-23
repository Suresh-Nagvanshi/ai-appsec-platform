"""
Scan Orchestrator
=================
Wires the full scanning pipeline:

  clone_or_extract()
       │
       v
  run_semgrep()
       │
       v
  context_builder.build()  ← per-finding enrichment
       │
       v
  risk_scorer.calculate()   ← per-finding risk score
       │
       v
  model_router.route()       ← choose fast vs deep LLM
       │
       v
  analysis_engine.analyze()  ← AI analysis per finding
       │
       v
  deduplicator.deduplicate() ← group duplicates
       │
       v
  findings_repository.save_scan()  ← persist all results
       │
       v
  update_scan_status(COMPLETED)

All scan-state mutations go through _update_scan() which
writes directly into the _scans dict imported from
backend.api.scans so the polling endpoint sees live state.
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from git import Repo

# ── Internal modules ───────────────────────────────────────────────────────────────────
from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.ai.model_router import ModelRouter
from backend.ai.analysis_engine import AnalysisEngine
from backend.deduplication.finding_deduplicator import FindingDeduplicator
from backend.storage.findings_repository import FindingsRepository

# Live scan-state dict shared with the API polling endpoint
from backend.api.scan_state import _scans

logger = logging.getLogger(__name__)

# ── Directory layout (mirrors main.py) ──────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
EXTRACT_DIR = BASE_DIR / "extracted"
RESULT_DIR = BASE_DIR / "results"
REPO_DIR = BASE_DIR / "repos"

for _d in (UPLOAD_DIR, EXTRACT_DIR, RESULT_DIR, REPO_DIR):
    _d.mkdir(exist_ok=True)


# ── Tiny helpers ────────────────────────────────────────────────────────────────────────

def _now_str() -> str:
    return datetime.utcnow().strftime("%H:%M:%S")


def _iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_entry(level: str, message: str) -> dict:
    return {"id": str(uuid4()), "time": _now_str(), "level": level, "message": message}


def _update_scan(
    scan_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    log_message: Optional[str] = None,
    log_level: str = "INFO",
    timeline_step_id: Optional[str] = None,
    timeline_status: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """Mutate the live scan record in-place so the polling endpoint sees it."""
    scan = _scans.get(scan_id)
    if not scan:
        return
    if status:
        scan["status"] = status
    if progress is not None:
        scan["progress"] = progress
    if log_message:
        scan.setdefault("logs", []).append(_log_entry(log_level, log_message))
    if timeline_step_id is not None and timeline_status:
        for step in scan.get("timeline", []):
            if step["id"] == timeline_step_id:
                step["status"] = timeline_status
                break
    if extra:
        scan.update(extra)


# ── Semgrep runner (sync, called via asyncio.to_thread) ──────────────────────────────

def _run_semgrep(scan_path: Path, result_file: Path) -> dict:
    """
    Execute Semgrep on *scan_path*, write JSON to *result_file*.
    Returns the parsed Semgrep results dict.
    Raises RuntimeError on failure.
    """
    env = os.environ.copy()
    env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "LANG": "en_US.UTF-8"})

    cmd = [
        sys.executable, "-m", "semgrep",
        "--config=auto",
        str(scan_path),
        "--json",
        "--output", str(result_file),
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        env=env,
        timeout=600,
    )

    if not result_file.exists():
        raise RuntimeError(
            f"Semgrep produced no output file. stderr: {result.stderr[:500]}"
        )

    with open(result_file, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ── AI analysis (sync, called via asyncio.to_thread) ─────────────────────────────────

def _analyze_findings(
    raw_findings: List[dict],
    project_path: str,
    project_name: str,
) -> List[dict]:
    """
    Runs the full per-finding pipeline:
      context_builder → risk_scorer → model_router → analysis_engine

    Returns a list of fully-enriched finding dicts ready for
    deduplication and persistence.
    """
    context_builder = ContextBuilder()
    risk_scorer = RiskScorer()
    model_router = ModelRouter()

    results: List[dict] = []

    for raw in raw_findings:
        try:
            # 1. Context enrichment (normalises + adds snippet/framework/endpoint)
            enriched = context_builder.build(
                finding=raw,
                project_path=project_path,
            )
            if "error" in enriched:
                logger.warning("context_builder error: %s", enriched["error"])

            # 2. Risk scoring
            risk = risk_scorer.calculate(enriched)
            enriched["risk"] = risk

            # 3. Model routing (select fast vs deep LLM)
            routing = model_router.route(enriched)
            selected_model = routing["selected_model"]["model_name"]

            # 4. AI analysis with the routed model
            engine = AnalysisEngine(model_name=selected_model)
            ai_result = engine.analyze(enriched)
            enriched["ai_analysis"] = ai_result
            enriched["model_routing"] = routing

            results.append(enriched)

        except Exception as exc:
            logger.error("Per-finding analysis failed: %s", exc)
            # Still include the raw finding so nothing is silently lost
            results.append({
                "finding": raw,
                "risk": {},
                "ai_analysis": {"error": str(exc)},
            })

    return results


# ── Main orchestrator ──────────────────────────────────────────────────────────────────────

async def run_github_scan(scan_id: str, repo_url: str) -> None:
    """
    Full GitHub repository scan pipeline.
    Runs as a FastAPI BackgroundTask so the HTTP response returns immediately.
    """
    repo_path: Optional[Path] = None
    result_file: Optional[Path] = None

    try:
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        repo_path = REPO_DIR / repo_name
        result_file = RESULT_DIR / f"{repo_name}_github_{scan_id}.json"

        # ── STEP 0: RUNNING ──────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            status="RUNNING",
            progress=5,
            log_message=f"Starting GitHub scan for {repo_url}",
            timeline_step_id="0",
            timeline_status="RUNNING",
        )

        # ── STEP 1: Clone ────────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=10,
            log_message=f"Cloning repository: {repo_name}",
        )

        if repo_path.exists():
            shutil.rmtree(repo_path, ignore_errors=True)

        await asyncio.to_thread(Repo.clone_from, repo_url, repo_path)

        _update_scan(
            scan_id,
            progress=20,
            log_message="Repository cloned successfully",
            timeline_step_id="0",
            timeline_status="COMPLETED",
        )

        # ── STEP 2: Semgrep ──────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=25,
            log_message="Running Semgrep static analysis",
            timeline_step_id="1",
            timeline_status="RUNNING",
        )

        semgrep_data = await asyncio.to_thread(
            _run_semgrep, repo_path, result_file
        )
        raw_findings: List[dict] = semgrep_data.get("results", [])

        _update_scan(
            scan_id,
            progress=45,
            log_message=f"Semgrep complete — {len(raw_findings)} raw findings",
            timeline_step_id="1",
            timeline_status="COMPLETED",
        )

        # ── STEP 3: Context + Risk + AI ─────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=50,
            log_message="Running AI analysis pipeline",
            timeline_step_id="3",
            timeline_status="RUNNING",
        )

        enriched_findings = await asyncio.to_thread(
            _analyze_findings,
            raw_findings,
            str(repo_path),
            repo_name,
        )

        _update_scan(
            scan_id,
            progress=75,
            log_message=f"AI analysis complete — {len(enriched_findings)} findings analysed",
            timeline_step_id="3",
            timeline_status="COMPLETED",
        )

        # ── STEP 4: Deduplication ────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=80,
            log_message="Deduplicating findings",
        )

        deduplicator = FindingDeduplicator()
        deduplicated = deduplicator.deduplicate(enriched_findings)

        _update_scan(
            scan_id,
            progress=85,
            log_message=f"Deduplication complete — {len(deduplicated)} unique findings",
        )

        # ── STEP 5: Persist ────────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=90,
            log_message="Saving findings to repository",
            timeline_step_id="4",
            timeline_status="RUNNING",
        )

        summary = _build_summary(enriched_findings)

        findings_repo = FindingsRepository()
        storage_id = findings_repo.save_scan(
            project_name=repo_name,
            scan_results={
                "scan_id": scan_id,
                "scan_type": "github",
                "repository_url": repo_url,
                "results": deduplicated,
                "summary": summary,
            },
        )

        # ── STEP 6: COMPLETED ───────────────────────────────────────────────────
        _update_scan(
            scan_id,
            status="COMPLETED",
            progress=100,
            log_message="Scan completed successfully",
            timeline_step_id="4",
            timeline_status="COMPLETED",
            extra={
                "findingsCount": len(deduplicated),
                "criticalCount": summary.get("critical", 0),
                "summary": summary,
                "storage_id": storage_id,
                "duration": _calculate_duration(_scans[scan_id]["startedAt"]),
            },
        )

        logger.info("Scan %s completed. %d findings persisted.", scan_id, len(deduplicated))

    except subprocess.TimeoutExpired:
        _update_scan(
            scan_id,
            status="FAILED",
            progress=0,
            log_message="Scan timed out after 600 seconds",
            log_level="ERROR",
            extra={"failureReason": "Semgrep timed out"},
        )
    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        _update_scan(
            scan_id,
            status="FAILED",
            progress=0,
            log_message=f"Scan failed: {exc}",
            log_level="ERROR",
            extra={"failureReason": str(exc)},
        )
    finally:
        if repo_path and repo_path.exists():
            shutil.rmtree(repo_path, ignore_errors=True)


async def run_zip_scan(scan_id: str, zip_bytes: bytes, filename: str) -> None:
    """
    Full ZIP upload scan pipeline.
    Runs as a FastAPI BackgroundTask so the HTTP response returns immediately.
    """
    safe_name = Path(filename).name
    project_name = safe_name.replace(".zip", "")
    zip_path = UPLOAD_DIR / safe_name
    extract_path = EXTRACT_DIR / project_name
    result_file = RESULT_DIR / f"{project_name}_zip_{scan_id}.json"

    try:
        # ── STEP 0: RUNNING ──────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            status="RUNNING",
            progress=5,
            log_message=f"Starting ZIP scan for {safe_name}",
            timeline_step_id="0",
            timeline_status="RUNNING",
        )

        # ── STEP 1: Extract ───────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=10,
            log_message=f"Extracting ZIP: {safe_name}",
        )

        import zipfile

        zip_path.write_bytes(zip_bytes)
        extract_path.mkdir(exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                member_path = (extract_path / member).resolve()
                if not str(member_path).startswith(str(extract_path.resolve())):
                    raise ValueError(f"Unsafe ZIP entry detected: {member}")
            zf.extractall(extract_path)

        _update_scan(
            scan_id,
            progress=20,
            log_message="ZIP extracted successfully",
            timeline_step_id="0",
            timeline_status="COMPLETED",
        )

        # ── STEP 2: Semgrep ──────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=25,
            log_message="Running Semgrep static analysis",
            timeline_step_id="1",
            timeline_status="RUNNING",
        )

        semgrep_data = await asyncio.to_thread(
            _run_semgrep, extract_path, result_file
        )
        raw_findings: List[dict] = semgrep_data.get("results", [])

        _update_scan(
            scan_id,
            progress=45,
            log_message=f"Semgrep complete — {len(raw_findings)} raw findings",
            timeline_step_id="1",
            timeline_status="COMPLETED",
        )

        # ── STEP 3: Context + Risk + AI ─────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=50,
            log_message="Running AI analysis pipeline",
            timeline_step_id="3",
            timeline_status="RUNNING",
        )

        enriched_findings = await asyncio.to_thread(
            _analyze_findings,
            raw_findings,
            str(extract_path),
            project_name,
        )

        _update_scan(
            scan_id,
            progress=75,
            log_message=f"AI analysis complete — {len(enriched_findings)} findings analysed",
            timeline_step_id="3",
            timeline_status="COMPLETED",
        )

        # ── STEP 4: Deduplication ────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=80,
            log_message="Deduplicating findings",
        )

        deduplicator = FindingDeduplicator()
        deduplicated = deduplicator.deduplicate(enriched_findings)

        _update_scan(
            scan_id,
            progress=85,
            log_message=f"Deduplication complete — {len(deduplicated)} unique findings",
        )

        # ── STEP 5: Persist ────────────────────────────────────────────────────────
        _update_scan(
            scan_id,
            progress=90,
            log_message="Saving findings to repository",
            timeline_step_id="4",
            timeline_status="RUNNING",
        )

        summary = _build_summary(enriched_findings)

        findings_repo = FindingsRepository()
        storage_id = findings_repo.save_scan(
            project_name=project_name,
            scan_results={
                "scan_id": scan_id,
                "scan_type": "zip",
                "filename": safe_name,
                "results": deduplicated,
                "summary": summary,
            },
        )

        # ── STEP 6: COMPLETED ───────────────────────────────────────────────────
        _update_scan(
            scan_id,
            status="COMPLETED",
            progress=100,
            log_message="Scan completed successfully",
            timeline_step_id="4",
            timeline_status="COMPLETED",
            extra={
                "findingsCount": len(deduplicated),
                "criticalCount": summary.get("critical", 0),
                "summary": summary,
                "storage_id": storage_id,
                "duration": _calculate_duration(_scans[scan_id]["startedAt"]),
            },
        )

        logger.info("ZIP scan %s completed. %d findings persisted.", scan_id, len(deduplicated))

    except subprocess.TimeoutExpired:
        _update_scan(
            scan_id,
            status="FAILED",
            progress=0,
            log_message="Scan timed out after 600 seconds",
            log_level="ERROR",
            extra={"failureReason": "Semgrep timed out"},
        )
    except Exception as exc:
        logger.exception("ZIP scan %s failed: %s", scan_id, exc)
        _update_scan(
            scan_id,
            status="FAILED",
            progress=0,
            log_message=f"Scan failed: {exc}",
            log_level="ERROR",
            extra={"failureReason": str(exc)},
        )
    finally:
        if extract_path.exists():
            shutil.rmtree(extract_path, ignore_errors=True)
        if zip_path.exists():
            zip_path.unlink(missing_ok=True)


# ── Utility helpers ──────────────────────────────────────────────────────────────────────

def _build_summary(enriched_findings: List[dict]) -> dict:
    """Build severity count summary from enriched findings."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for ef in enriched_findings:
        sev = (
            ef.get("finding", {}).get("severity", "")
            or ef.get("risk", {}).get("severity", "")
        ).upper()
        if sev in ("CRITICAL", "ERROR"):
            counts["critical"] += 1
        elif sev in ("HIGH",):
            counts["high"] += 1
        elif sev in ("MEDIUM", "WARNING"):
            counts["medium"] += 1
        else:
            counts["low"] += 1
    return counts


def _calculate_duration(started_at: str) -> str:
    """Calculate human-readable duration from ISO start timestamp."""
    try:
        start = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ")
        delta = datetime.utcnow() - start
        minutes, seconds = divmod(int(delta.total_seconds()), 60)
        return f"{minutes}m {seconds}s"
    except Exception:
        return "-"
