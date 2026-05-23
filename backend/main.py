from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from backend.api.scans import router as scans_router
from backend.ai_service import analyze_vulnerability
from backend.routes.findings import router as findings_router

import shutil
import zipfile
import subprocess
import json
import os
import sys

from pathlib import Path
from git import Repo

# UTF-8 Fix
os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"

app = FastAPI(
    title="AI Security Agent Backend",
    version="1.0.0"
)

app.include_router(
    scans_router,
    prefix="/api/scans",
    tags=["Scans"]
)

app.include_router(findings_router)

# CORS
# allow_origins=["*"] + allow_credentials=True is spec-invalid and rejected
# by browsers. Use explicit origins and credentials=False for MVP.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
EXTRACT_DIR = BASE_DIR / "extracted"
RESULT_DIR = BASE_DIR / "results"

UPLOAD_DIR.mkdir(exist_ok=True)
EXTRACT_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(exist_ok=True)
REPO_DIR = BASE_DIR / "repos"
REPO_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB


@app.get("/")
def home():
    return {
        "status": "success",
        "message": "AI Security Agent Backend Running"
    }


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    # ── File size guard (read first chunk to estimate) ──────────────────
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds maximum allowed size of {MAX_UPLOAD_BYTES // (1024*1024)} MB"
        )

    # ── Safe filename (strip directory components) ───────────────────────
    safe_name = Path(file.filename).name
    if not safe_name.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted")

    zip_path = UPLOAD_DIR / safe_name
    project_name = safe_name.replace(".zip", "")
    extract_path = EXTRACT_DIR / project_name

    try:
        # Write bytes already read into memory
        zip_path.write_bytes(content)

        # ── ZIP path traversal guard (Zip Slip) ─────────────────────────
        extract_path.mkdir(exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            for member in zip_ref.namelist():
                member_path = (extract_path / member).resolve()
                if not str(member_path).startswith(str(extract_path.resolve())):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Unsafe ZIP entry detected: {member}"
                    )
            zip_ref.extractall(extract_path)

        result_file = RESULT_DIR / f"{project_name}_results.json"

        command = [
            sys.executable, "-m", "semgrep",
            "--config=auto",
            str(extract_path),
            "--json",
            "--output", str(result_file)
        ]

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["LANG"] = "en_US.UTF-8"

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            timeout=600
        )

        if not result_file.exists():
            return {
                "status": "error",
                "message": "Semgrep result file not generated",
                "stderr": result.stderr
            }

        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        findings_count = len(semgrep_results.get("results", []))

        return {
            "status": "success",
            "project": project_name,
            "findings": findings_count,
            "results_file": str(result_file),
            "results": semgrep_results.get("results", [])
        }

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Semgrep scan timed out after 600 seconds"}
    except zipfile.BadZipFile:
        return {"status": "error", "message": "Invalid ZIP file"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        # Clean up extracted files after scan to prevent disk accumulation
        if extract_path.exists():
            shutil.rmtree(extract_path, ignore_errors=True)
        if zip_path.exists():
            zip_path.unlink(missing_ok=True)


@app.post("/scan/analyze")
async def analyze_scan_results(project_name: str):
    try:
        result_file = RESULT_DIR / f"{project_name}_results.json"

        if not result_file.exists():
            return {"status": "error", "message": "Result file not found"}

        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        findings = semgrep_results.get("results", [])

        if not findings:
            return {"status": "success", "message": "No vulnerabilities found", "analysis": []}

        analyzed_results = []

        for finding in findings:
            vulnerability_data = {
                "rule_id": finding.get("check_id"),
                "path": finding.get("path"),
                "message": finding.get("extra", {}).get("message"),
                "severity": finding.get("extra", {}).get("severity"),
                "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe"),
                "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp"),
            }

            ai_response = analyze_vulnerability(vulnerability_data)
            analyzed_results.append({"finding": vulnerability_data, "ai_analysis": ai_response})

        return {
            "status": "success",
            "project": project_name,
            "total_findings": len(analyzed_results),
            "analysis": analyzed_results
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/scan/github")
async def scan_github_repo(repo_url: str):
    # ── SSRF guard: only allow public GitHub HTTPS URLs ──────────────────
    if not repo_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=400,
            detail="Only public GitHub HTTPS repository URLs are accepted (https://github.com/...)"
        )

    try:
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        if not repo_name:
            raise HTTPException(status_code=400, detail="Could not derive repository name from URL")

        repo_path = REPO_DIR / repo_name
        result_file = RESULT_DIR / f"{repo_name}_github_results.json"

        if repo_path.exists():
            try:
                shutil.rmtree(repo_path)
            except PermissionError:
                return {
                    "status": "error",
                    "message": "Repository folder is locked. Restart server and try again."
                }

        Repo.clone_from(repo_url, repo_path)

        command = [
            sys.executable, "-m", "semgrep",
            "--config=auto",
            str(repo_path),
            "--json",
            "--output", str(result_file)
        ]

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["LANG"] = "en_US.UTF-8"

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            env=env,
            timeout=600
        )

        if not result_file.exists():
            return {
                "status": "error",
                "message": "Semgrep result file not generated",
                "stderr": result.stderr
            }

        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        findings_count = len(semgrep_results.get("results", []))

        return {
            "status": "success",
            "repository": repo_name,
            "findings": findings_count,
            "results_file": str(result_file),
            "results": semgrep_results.get("results", [])
        }

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Semgrep scan timed out after 600 seconds"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/report/generate")
async def generate_report(project_name: str):
    try:
        result_file = RESULT_DIR / f"{project_name}_results.json"

        if not result_file.exists():
            result_file = RESULT_DIR / f"{project_name}_github_results.json"

        if not result_file.exists():
            return {"status": "error", "message": "Result file not found"}

        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        findings = semgrep_results.get("results", [])[:5]

        if not findings:
            return {"status": "success", "message": "No vulnerabilities found", "report": []}

        report = []

        for finding in findings:
            vulnerability_data = {
                "rule_id": finding.get("check_id"),
                "path": finding.get("path"),
                "message": finding.get("extra", {}).get("message"),
                "severity": finding.get("extra", {}).get("severity"),
                "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe"),
                "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp"),
            }

            ai_analysis = analyze_vulnerability(vulnerability_data)
            report.append({"finding": vulnerability_data, "ai_report": ai_analysis})

        report_file = RESULT_DIR / f"{project_name}_ai_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        return {
            "status": "success",
            "project": project_name,
            "total_findings": len(report),
            "report_file": str(report_file),
            "report": report
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}
