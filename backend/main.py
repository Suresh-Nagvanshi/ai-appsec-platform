from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from backend.api.scans import router as scans_router
from backend.ai_service import analyze_vulnerability
from backend.routes.findings import (
router as findings_router
)

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

# Register Routers

app.include_router(findings_router)

# CORS

app.add_middleware(
CORSMiddleware,
allow_origins=["*"],
allow_credentials=True,
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


@app.get("/")
def home():
    return {
        "status": "success",
        "message": "AI Security Agent Backend Running"
    }


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    try:
        # =========================
        # Save ZIP File
        # =========================
        zip_path = UPLOAD_DIR / file.filename
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # =========================
        # Extract ZIP
        # =========================
        project_name = file.filename.replace(".zip", "")
        extract_path = EXTRACT_DIR / project_name
        extract_path.mkdir(exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)

        # =========================
        # Result File
        # =========================
        result_file = RESULT_DIR / f"{project_name}_results.json"

        # =========================
        # Semgrep Command
        # =========================
        command = [
            sys.executable,
            "-m",
            "semgrep",
            "--config=auto",
            str(extract_path),
            "--json",
            "--output",
            str(result_file)
        ]

        print("\nRunning Semgrep...")
        print(" ".join(command))

        # =========================
        # Run Semgrep
        # =========================
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

        print("\n===== STDOUT =====")
        print(result.stdout)
        print("\n===== STDERR =====")
        print(result.stderr)

        # =========================
        # Verify Result File
        # =========================
        if not result_file.exists():
            return {
                "status": "error",
                "message": "Semgrep result file not generated",
                "stderr": result.stderr
            }

        # =========================
        # Load Results
        # =========================
        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        findings = len(semgrep_results.get("results", []))

        return {
            "status": "success",
            "project": project_name,
            "findings": findings,
            "results_file": str(result_file),
            "results": semgrep_results.get("results", [])
        }

    except subprocess.TimeoutExpired as e:
        return {
            "status": "error",
            "message": "Semgrep scan timed out after 600 seconds",
            "stderr": str(e)
        }

    except zipfile.BadZipFile:
        return {"status": "error", "message": "Invalid ZIP file"}

    except Exception as e:
        return {"status": "error", "message": str(e)}
    
    
@app.post("/scan/analyze")
async def analyze_scan_results(project_name: str):
    try:
        # =========================
        # Locate Semgrep Results
        # =========================
        result_file = RESULT_DIR / f"{project_name}_results.json"

        if not result_file.exists():
            return {
                "status": "error",
                "message": "Result file not found"
            }

        # =========================
        # Load Semgrep JSON
        # =========================
        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        findings = semgrep_results.get("results", [])

        if not findings:
            return {
                "status": "success",
                "message": "No vulnerabilities found",
                "analysis": []
            }

        analyzed_results = []

        # =========================
        # AI Analysis Loop
        # =========================
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

            analyzed_results.append({
                "finding": vulnerability_data,
                "ai_analysis": ai_response
            })

        return {
            "status": "success",
            "project": project_name,
            "total_findings": len(analyzed_results),
            "analysis": analyzed_results
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.post("/scan/github")
async def scan_github_repo(repo_url: str):
    try:
        # =========================
        # Extract Repo Name
        # =========================
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_path = REPO_DIR / repo_name
        result_file = RESULT_DIR / f"{repo_name}_github_results.json"

        # =========================
        # Delete Old Repo If Exists
        # =========================
        if repo_path.exists():
            try:
                shutil.rmtree(repo_path)
            except PermissionError:
                return {
                    "status": "error",
                    "message": "Repository folder is currently locked. Close any open files/folders or restart server and try again."
                }

        # =========================
        # Clone Repository
        # =========================
        print(f"\nCloning repository: {repo_url}")
        Repo.clone_from(repo_url, repo_path)
        print("Repository cloned successfully.")

        # =========================
        # Semgrep Command
        # =========================
        command = [
            sys.executable,
            "-m",
            "semgrep",
            "--config=auto",
            str(repo_path),
            "--json",
            "--output",
            str(result_file)
        ]

        print("\nRunning Semgrep on GitHub repo...")
        print(" ".join(command))

        # =========================
        # Run Semgrep
        # =========================
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

        print("\n===== STDOUT =====")
        print(result.stdout)
        print("\n===== STDERR =====")
        print(result.stderr)

        # =========================
        # Verify Results
        # =========================
        if not result_file.exists():
            return {
                "status": "error",
                "message": "Semgrep result file not generated",
                "stderr": result.stderr
            }

        # =========================
        # Load Results
        # =========================
        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        findings = len(semgrep_results.get("results", []))

        return {
            "status": "success",
            "repository": repo_name,
            "findings": findings,
            "results_file": str(result_file),
            "results": semgrep_results.get("results", [])
        }

    except subprocess.TimeoutExpired as e:
        return {
            "status": "error",
            "message": "Semgrep scan timed out after 600 seconds",
            "stderr": str(e)
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.post("/report/generate")
async def generate_report(project_name: str):
    try:
        # =========================
        # Locate Semgrep Result File
        # =========================
        result_file = RESULT_DIR / f"{project_name}_results.json"

        # GitHub fallback
        if not result_file.exists():
            result_file = RESULT_DIR / f"{project_name}_github_results.json"

        if not result_file.exists():
            return {
                "status": "error",
                "message": "Result file not found"
            }

        # =========================
        # Load Results
        # =========================
        with open(result_file, "r", encoding="utf-8") as f:
            semgrep_results = json.load(f)

        # Process the first five findings for the AI report to provide richer output.
        findings = semgrep_results.get("results", [])[:5]

        if not findings:
            return {
                "status": "success",
                "message": "No vulnerabilities found",
                "report": []
            }

        report = []

        # =========================
        # Generate AI Report
        # =========================
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

            report.append({
                "finding": vulnerability_data,
                "ai_report": ai_analysis
            })

        # =========================
        # Save Report
        # =========================
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
        return {
            "status": "error",
            "message": str(e)
        }

