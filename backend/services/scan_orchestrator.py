"""
Scan Orchestrator
=================
Wires the full scanning pipeline:

  clone_or_extract()
       │
       v
  [if branch specified] checkout_branch()
       │
       v
  [if base_scan_id] compute_git_diff() ← incremental scan: only changed files
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
  VulnAnalysisChain.analyze()  ← RAG-augmented AI analysis (LangChain + ChromaDB + Groq)
       │                          Falls back to legacy AnalysisEngine on failure
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
import sys
import shutil
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

# ── Internal modules ──────────────────────────────────────────────────────────
from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.ai.model_router import ModelRouter
from backend.deduplication.finding_deduplicator import FindingDeduplicator
from backend.storage.findings_repository import FindingsRepository
from backend.scanning.multi_engine import run_multi_engine_scan

# Live scan-state dict shared with the API polling endpoint
from backend.api.scan_state import _scans, save_state

logger = logging.getLogger(__name__)

# ── Directory layout ──────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
EXTRACT_DIR = BASE_DIR / "extracted"
RESULT_DIR = BASE_DIR / "results"
REPO_DIR = BASE_DIR / "repos"

for _d in (UPLOAD_DIR, EXTRACT_DIR, RESULT_DIR, REPO_DIR):
    _d.mkdir(exist_ok=True)


# ── Tiny helpers ──────────────────────────────────────────────────────────────

def _force_rmtree(path: Path) -> None:
    """Recursively remove directory, clearing read-only attributes on Windows git files."""
    if not path.exists():
        return
    import stat

    def _remove_readonly(func, p):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    try:
        shutil.rmtree(path, onexc=lambda func, p, exc: _remove_readonly(func, p))
    except TypeError:
        shutil.rmtree(path, onerror=lambda func, p, exc_info: _remove_readonly(func, p))
    except Exception:
        pass


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
        if status == "COMPLETED":
            scan["completedAt"] = _iso()
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
    save_state()


def _build_semgrep_cmd(result_file: Path, scan_target: str, include_paths: Optional[List[str]] = None) -> List[str]:
    """
    Build the semgrep command list.

    Strategy (cross-platform, works in Docker Linux containers):
      1. Find the semgrep script via shutil.which / common paths.
      2. ALWAYS invoke it as [sys.executable, semgrep_script, ...] — this
         bypasses all OS shebang resolution issues that cause [Errno 2] on
         Linux containers where the shebang interpreter path may not match.
      3. If no semgrep file can be found at all, raise RuntimeError immediately.
    """
    # Build candidate directories to search
    py_dir = Path(sys.executable).parent
    home = Path(os.path.expanduser("~"))
    python_ver = f"Python{sys.version_info.major}{sys.version_info.minor}"

    # Augment PATH so shutil.which covers user site-packages scripts
    extra_dirs = [
        str(py_dir),
        str(py_dir / "Scripts"),
        str(home / "AppData" / "Roaming" / "Python" / python_ver / "Scripts"),
        str(home / ".local" / "bin"),
        "/usr/local/bin",
        "/usr/bin",
    ]
    current_path = os.environ.get("PATH", "")
    os.environ["PATH"] = os.pathsep.join(extra_dirs) + os.pathsep + current_path

    # --- Find the semgrep script file ---
    semgrep_script: Optional[str] = None

    # 1. shutil.which searches the (now-augmented) PATH
    for name in ("semgrep", "semgrep.exe", "semgrep.EXE"):
        found = shutil.which(name)
        if found and Path(found).exists():
            semgrep_script = found
            break

    # 2. Hard-coded fallback paths (covers all common install locations)
    if not semgrep_script:
        for cand in [
            py_dir / "semgrep",
            py_dir / "semgrep.exe",
            py_dir / "Scripts" / "semgrep",
            py_dir / "Scripts" / "semgrep.exe",
            home / "AppData" / "Roaming" / "Python" / python_ver / "Scripts" / "semgrep.exe",
            home / "AppData" / "Roaming" / "Python" / python_ver / "Scripts" / "semgrep",
            home / ".local" / "bin" / "semgrep",
            Path("/usr/local/bin/semgrep"),
            Path("/usr/bin/semgrep"),
        ]:
            if cand.exists():
                semgrep_script = str(cand)
                break

    if not semgrep_script:
        raise RuntimeError(
            "Semgrep not found. Ensure 'semgrep' is listed in requirements.txt "
            "and the Docker image was rebuilt after adding it."
        )

    # ALWAYS run via sys.executable — avoids [Errno 2] on Linux shebang scripts.
    # On Windows this also works because .exe files just ignore the leading interpreter arg.
    cmd = [sys.executable, semgrep_script, "scan", "--config=auto", "--json", "--json-output", str(result_file)]

    if include_paths:
        for rel_path in include_paths:
            cmd.append(rel_path)
    else:
        cmd.append(scan_target)

    return cmd



def _run_semgrep(
    scan_path: Path,
    result_file: Path,
    include_paths: Optional[List[str]] = None,
) -> dict:
    """
    Execute Semgrep on *scan_path*, write JSON to *result_file*.
    If *include_paths* is provided (incremental mode), Semgrep is run only
    on those specific relative file paths, dramatically reducing scan time.
    Returns the parsed Semgrep results dict.
    Raises RuntimeError on failure.
    """
    env = os.environ.copy()
    env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "LANG": "en_US.UTF-8"})

    cmd = _build_semgrep_cmd(
        result_file=result_file,
        scan_target=str(scan_path),
        include_paths=include_paths,
    )
    logger.warning("Semgrep command: %r", cmd)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        env=env,
        timeout=600,
    )

    if result_file.exists():
        with open(result_file, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                pass

    if result.stdout and result.stdout.strip().startswith("{"):
        try:
            parsed = json.loads(result.stdout)
            result_file.write_text(result.stdout, encoding="utf-8")
            return parsed
        except json.JSONDecodeError:
            pass

    raise RuntimeError(
        f"Semgrep failed. returncode={result.returncode}, stderr: {result.stderr or result.stdout}"
    )



# ── Branch helpers ─────────────────────────────────────────────────────────────

def _checkout_branch(repo_obj, branch: str) -> None:
    """
    Checkout a specific branch in the already-cloned repository.
    Tries remote tracking branch first (origin/<branch>) to avoid
    ambiguity when branch name matches a tag.
    """
    try:
        repo_obj.git.checkout(branch)
    except Exception:
        # Fallback: create a local tracking branch from the remote
        repo_obj.git.checkout("-b", branch, f"origin/{branch}")


# ── Incremental diff helpers ────────────────────────────────────────────────────

def _compute_git_diff(repo_obj, base_commit: str, current_commit: str) -> dict:
    """
    Compute the set of source-code files changed between *base_commit* and
    *current_commit* using GitPython's diff API.

    Returns a dict with:
      - changed_files: list of relative paths to changed/added files
      - base_commit:   hex SHA of the base
      - current_commit: hex SHA of HEAD
      - added: count of added files
      - modified: count of modified files
      - deleted: count of deleted files
    """
    # Extensions recognised as source code for security scanning
    _SRC_EXTS = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb",
        ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".kt", ".swift",
        ".scala", ".sh", ".yaml", ".yml", ".json", ".tf",
    }

    base = repo_obj.commit(base_commit)
    current = repo_obj.commit(current_commit)
    diffs = base.diff(current)

    changed_files: List[str] = []
    added = modified = deleted = 0

    for diff in diffs:
        if diff.change_type == "D":
            deleted += 1
            continue  # deleted files have no content to scan
        path = diff.b_path or diff.a_path
        ext = Path(path).suffix.lower()
        if ext in _SRC_EXTS:
            changed_files.append(path)
            if diff.change_type == "A":
                added += 1
            else:
                modified += 1

    return {
        "changed_files": changed_files,
        "base_commit": base_commit,
        "current_commit": current_commit,
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "total_changed": len(changed_files),
    }


# ── AI analysis (sync, called via asyncio.to_thread) ──────────────────────────

def _analyze_findings(
    raw_findings: List[dict],
    project_path: str,
    project_name: str,
) -> List[dict]:
    """
    Runs the full per-finding pipeline:
      context_builder → risk_scorer → model_router → VulnAnalysisChain (RAG)

    VulnAnalysisChain is RAG-augmented: it retrieves relevant CWE/OWASP/MITRE
    context from ChromaDB before calling Groq, producing richer analysis with
    authoritative references and CVSS estimates.

    Falls back to legacy AnalysisEngine automatically on any RAG failure.
    """
    context_builder = ContextBuilder()
    risk_scorer = RiskScorer()
    model_router = ModelRouter()

    # AI is optional for local/static scans. Import and initialize it only when
    # a key is configured so missing AI packages or model downloads cannot stop
    # Semgrep results from being persisted.
    rag_chain = None
    if os.getenv("GROQ_API_KEY"):
        try:
            from backend.ai.chains.vuln_analysis_chain import VulnAnalysisChain

            rag_chain = VulnAnalysisChain()
        except Exception as exc:
            logger.warning("AI analysis unavailable; continuing without it: %s", exc)

    results: List[dict] = []

    for raw in raw_findings:
        try:
            # 1. Context enrichment
            enriched = context_builder.build(
                finding=raw,
                project_path=project_path,
            )
            if "error" in enriched:
                logger.warning("context_builder error: %s", enriched["error"])

            # 2. Risk scoring
            risk = risk_scorer.calculate(enriched)
            enriched["risk"] = risk

            # 3. Model routing and optional RAG-augmented AI analysis
            if rag_chain is not None:
                routing = model_router.route(enriched)
                selected_model = routing["selected_model"]["model_name"]
                rag_chain.model_name = selected_model
                enriched["ai_analysis"] = rag_chain.analyze(enriched)
                enriched["model_routing"] = routing
            else:
                enriched["ai_analysis"] = _local_analysis(enriched)

            results.append(enriched)

        except Exception as exc:
            logger.error("Per-finding analysis failed: %s", exc)
            results.append({
                "finding": raw,
                "risk": {},
                "ai_analysis": {"error": str(exc)},
            })

    return results


def _local_analysis(finding: dict) -> dict:
    """Return deterministic metadata when external AI is not configured."""
    raw = finding.get("finding", {})
    return {
        "summary": raw.get("message", "Static analysis finding"),
        "secure_fix": "Review the finding and apply the scanner's remediation guidance.",
        "developer_remediation_steps": [
            "Confirm the finding against the reported source location.",
            "Apply the recommended secure coding pattern.",
            "Re-run the scan to verify the issue is resolved.",
        ],
        "model": "local-static-analysis",
        "rag_enhanced": False,
        "ai_unavailable": True,
    }


# ── GitHub scan ───────────────────────────────────────────────────────────────

async def run_github_scan(
    scan_id: str,
    repo_url: str,
    branch: Optional[str] = None,
    base_scan_id: Optional[str] = None,
) -> None:
    """
    Full GitHub repository scan pipeline.
    Runs as a FastAPI BackgroundTask so the HTTP response returns immediately.

    Args:
        scan_id:      UUID of the current scan record.
        repo_url:     Target GitHub HTTPS URL.
        branch:       Branch to checkout after clone; None → default branch.
        base_scan_id: If set, performs an INCREMENTAL scan — only files changed
                      since the commit recorded in the base scan are re-scanned;
                      existing findings for unchanged files are preserved.
    """
    # Keep GitPython out of API startup so ZIP scans remain available when Git
    # is not installed on the host. GitPython also needs an explicit path on
    # Windows when Git is installed but not present on PATH.
    git_executable = shutil.which("git")
    if not git_executable:
        for candidate in (
            r"C:\Program Files\Git\cmd\git.exe",
            r"C:\Program Files\Git\bin\git.exe",
            r"C:\Program Files (x86)\Git\cmd\git.exe",
        ):
            if Path(candidate).exists():
                git_executable = candidate
                break
    if not git_executable:
        raise RuntimeError("Git executable not found; install Git and add it to PATH")
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = git_executable
    from git import Repo

    repo_path: Optional[Path] = None
    result_file: Optional[Path] = None

    try:
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        repo_path = REPO_DIR / repo_name
        result_file = RESULT_DIR / f"{repo_name}_github_{scan_id}.json"

        _update_scan(scan_id, status="RUNNING", progress=5,
                     log_message=f"Starting GitHub scan for {repo_url}" +
                                 (f" (branch: {branch})" if branch else ""),
                     timeline_step_id="0", timeline_status="RUNNING")

        _update_scan(scan_id, progress=10,
                     log_message=f"Cloning repository: {repo_name}")

        if repo_path.exists():
            _force_rmtree(repo_path)

        repo_obj = await asyncio.to_thread(Repo.clone_from, repo_url, repo_path)

        # ── Branch checkout ─────────────────────────────────────────────────────────────────
        if branch:
            try:
                await asyncio.to_thread(_checkout_branch, repo_obj, branch)
                _update_scan(scan_id, progress=18,
                             log_message=f"Checked out branch: {branch}")
            except Exception as exc:
                raise RuntimeError(f"Branch '{branch}' not found in repository: {exc}")
        else:
            active = repo_obj.active_branch.name if not repo_obj.head.is_detached else "HEAD"
            _update_scan(scan_id, progress=18,
                         log_message=f"Using default branch: {active}")

        current_commit = repo_obj.head.commit.hexsha

        _update_scan(scan_id, progress=20,
                     log_message="Repository cloned successfully",
                     timeline_step_id="0", timeline_status="COMPLETED",
                     extra={"commit": current_commit})

        # ── Incremental diff scan ───────────────────────────────────────────────────────────
        changed_files: Optional[List[str]] = None
        base_commit: Optional[str] = None

        if base_scan_id:
            base_scan = _scans.get(base_scan_id)
            base_commit = (base_scan or {}).get("commit")
            if base_commit:
                try:
                    diff_result = await asyncio.to_thread(
                        _compute_git_diff, repo_obj, base_commit, current_commit
                    )
                    changed_files = diff_result["changed_files"]
                    _update_scan(scan_id, progress=22,
                                 log_message=(
                                     f"Incremental scan: {len(changed_files)} files changed "
                                     f"since {base_commit[:8]}"
                                 ),
                                 extra={"diff_info": diff_result})
                except Exception as exc:
                    logger.warning("Diff computation failed; falling back to full scan: %s", exc)
            else:
                logger.warning("Base scan %s has no commit hash; running full scan.", base_scan_id)

        _update_scan(scan_id, progress=25,
                     log_message="Running Semgrep static analysis" +
                                 (" (incremental — changed files only)" if changed_files is not None else ""),
                     timeline_step_id="1", timeline_status="RUNNING")

        semgrep_data = await asyncio.to_thread(
            _run_semgrep, repo_path, result_file, include_paths=changed_files
        )
        engine_results = await asyncio.to_thread(
            run_multi_engine_scan,
            repo_path,
            semgrep_data,
            RESULT_DIR / f"{scan_id}_engines",
        )
        raw_findings: List[dict] = engine_results["findings"]

        _update_scan(scan_id, progress=45,
                     log_message=(
                         f"Multi-engine analysis complete — {engine_results['raw_finding_count']} raw findings, "
                         f"{engine_results['correlated_finding_count']} correlated findings "
                         f"({', '.join(engine_results['engines_used']) or 'semgrep'})"
                     ),
                     extra={"engine_status": engine_results["engine_status"]},
                     timeline_step_id="1", timeline_status="COMPLETED")

        _update_scan(scan_id, progress=50,
                 log_message="Running context enrichment",
                 timeline_step_id="2", timeline_status="RUNNING")
        _update_scan(scan_id, progress=50,
                 log_message="Running RAG-augmented AI analysis pipeline",
                 timeline_step_id="3", timeline_status="RUNNING")

        enriched_findings = await asyncio.to_thread(
            _analyze_findings, raw_findings, str(repo_path), repo_name
        )

        rag_count = sum(1 for f in enriched_findings
                        if f.get("ai_analysis", {}).get("rag_enhanced"))
        _update_scan(scan_id, progress=75,
                     log_message=(
                         f"AI analysis complete — {len(enriched_findings)} findings analysed "
                         f"({rag_count} RAG-enhanced)"
                     ),
                     timeline_step_id="2", timeline_status="COMPLETED")
        _update_scan(scan_id, progress=75,
                     log_message="Context enrichment complete",
                     timeline_step_id="3", timeline_status="COMPLETED")

        _update_scan(scan_id, progress=80, log_message="Deduplicating findings")

        deduplicator = FindingDeduplicator()
        deduplicated = deduplicator.deduplicate(enriched_findings)

        _update_scan(scan_id, progress=85,
                     log_message=f"Deduplication complete — {len(deduplicated)} unique findings")

        _update_scan(scan_id, progress=90,
                     log_message="Saving findings to repository",
                     timeline_step_id="4", timeline_status="RUNNING")

        summary = _build_summary(enriched_findings)

        findings_repo = FindingsRepository()
        storage_id = findings_repo.save_scan(
            project_name=repo_name,
            scan_results={
                "scan_id": scan_id,
                "scan_type": "github",
                "repository_url": repo_url,
                "branch": branch,
                "commit": current_commit,
                "results": deduplicated,
                "summary": summary,
                "engine_status": engine_results["engine_status"],
                "engines_used": engine_results["engines_used"],
                "raw_finding_count": engine_results["raw_finding_count"],
                "correlated_finding_count": engine_results["correlated_finding_count"],
            },
        )

        _update_scan(
            scan_id, status="COMPLETED", progress=100,
            log_message="Scan completed successfully",
            timeline_step_id="4", timeline_status="COMPLETED",
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
        _update_scan(scan_id, status="FAILED", progress=0,
                     log_message="Scan timed out after 600 seconds",
                     log_level="ERROR",
                     extra={"failureReason": "Semgrep timed out"})
    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        _update_scan(scan_id, status="FAILED", progress=0,
                     log_message=f"Scan failed: {exc}",
                     log_level="ERROR",
                     extra={"failureReason": str(exc)})
    finally:
        if repo_path and repo_path.exists():
            shutil.rmtree(repo_path, ignore_errors=True)


# ── ZIP scan ──────────────────────────────────────────────────────────────────

async def run_zip_scan(scan_id: str, zip_bytes: bytes, filename: str) -> None:
    """
    Full ZIP upload scan pipeline.
    Runs as a FastAPI BackgroundTask so the HTTP response returns immediately.
    """
    import zipfile

    safe_name = Path(filename).name
    project_name = safe_name.replace(".zip", "")
    zip_path = UPLOAD_DIR / safe_name
    extract_path = EXTRACT_DIR / project_name
    result_file = RESULT_DIR / f"{project_name}_zip_{scan_id}.json"

    try:
        _update_scan(scan_id, status="RUNNING", progress=5,
                     log_message=f"Starting ZIP scan for {safe_name}",
                     timeline_step_id="0", timeline_status="RUNNING")

        _update_scan(scan_id, progress=10, log_message=f"Extracting ZIP: {safe_name}")

        zip_path.write_bytes(zip_bytes)
        extract_path.mkdir(exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            extract_root = extract_path.resolve()
            total_size = 0
            member_count = 0
            for member in zf.namelist():
                member_count += 1
                info = zf.getinfo(member)
                total_size += info.file_size

                # Basic path traversal check: ensure the resolved path is still within extract_root
                resolved_path = (extract_root / member).resolve()
                if not resolved_path.is_relative_to(extract_root):
                    raise ValueError(f"Unsafe ZIP entry detected (path traversal): {member}")

                # More robust checks against symbolic links and other special files
                # Note: zipfile.extractall does not follow symlinks by default in Python 3.6+
                # but it's good to be explicit for defense-in-depth.
                if info.is_sym() or info.external_attr >> 16 == 0o120000:  # S_IFLNK
                    raise ValueError(f"Unsafe ZIP entry detected (symbolic link): {member}")

                if member_count > 10_000 or total_size > 500 * 1024 * 1024:
                    raise ValueError("ZIP extraction exceeds the safety limits")
            zf.extractall(extract_path)

        _update_scan(scan_id, progress=20,
                     log_message="ZIP extracted successfully",
                     timeline_step_id="0", timeline_status="COMPLETED")

        _update_scan(scan_id, progress=25,
                     log_message="Running Semgrep static analysis",
                     timeline_step_id="1", timeline_status="RUNNING")

        semgrep_data = await asyncio.to_thread(_run_semgrep, extract_path, result_file)
        engine_results = await asyncio.to_thread(
            run_multi_engine_scan,
            extract_path,
            semgrep_data,
            RESULT_DIR / f"{scan_id}_engines",
        )
        raw_findings: List[dict] = engine_results["findings"]

        _update_scan(scan_id, progress=45,
                     log_message=(
                         f"Multi-engine analysis complete — {engine_results['raw_finding_count']} raw findings, "
                         f"{engine_results['correlated_finding_count']} correlated findings "
                         f"({', '.join(engine_results['engines_used']) or 'semgrep'})"
                     ),
                     extra={"engine_status": engine_results["engine_status"]},
                     timeline_step_id="1", timeline_status="COMPLETED")

        _update_scan(scan_id, progress=50,
                     log_message="Running RAG-augmented AI analysis pipeline",
                     timeline_step_id="3", timeline_status="RUNNING")

        enriched_findings = await asyncio.to_thread(
            _analyze_findings, raw_findings, str(extract_path), project_name
        )

        rag_count = sum(1 for f in enriched_findings
                        if f.get("ai_analysis", {}).get("rag_enhanced"))
        _update_scan(scan_id, progress=75,
                     log_message=(
                         f"AI analysis complete — {len(enriched_findings)} findings analysed "
                         f"({rag_count} RAG-enhanced)"
                     ),
                     timeline_step_id="3", timeline_status="COMPLETED")

        _update_scan(scan_id, progress=80, log_message="Deduplicating findings")

        deduplicator = FindingDeduplicator()
        deduplicated = deduplicator.deduplicate(enriched_findings)

        _update_scan(scan_id, progress=85,
                     log_message=f"Deduplication complete — {len(deduplicated)} unique findings")

        _update_scan(scan_id, progress=90,
                     log_message="Saving findings to repository",
                     timeline_step_id="4", timeline_status="RUNNING")

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
                "engine_status": engine_results["engine_status"],
                "engines_used": engine_results["engines_used"],
                "raw_finding_count": engine_results["raw_finding_count"],
                "correlated_finding_count": engine_results["correlated_finding_count"],
            },
        )

        _update_scan(
            scan_id, status="COMPLETED", progress=100,
            log_message="Scan completed successfully",
            timeline_step_id="4", timeline_status="COMPLETED",
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
        _update_scan(scan_id, status="FAILED", progress=0,
                     log_message="Scan timed out after 600 seconds",
                     log_level="ERROR",
                     extra={"failureReason": "Semgrep timed out"})
    except Exception as exc:
        logger.exception("ZIP scan %s failed: %s", scan_id, exc)
        _update_scan(scan_id, status="FAILED", progress=0,
                     log_message=f"Scan failed: {exc}",
                     log_level="ERROR",
                     extra={"failureReason": str(exc)})
    finally:
        if extract_path.exists():
            shutil.rmtree(extract_path, ignore_errors=True)
        if zip_path.exists():
            zip_path.unlink(missing_ok=True)


# ── Utility helpers ───────────────────────────────────────────────────────────

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
