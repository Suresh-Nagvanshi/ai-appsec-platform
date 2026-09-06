"""Static infrastructure-as-code and container security checks."""

import re
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from backend.api.api_security import _allowed_project_path

router = APIRouter()


class InfrastructureRequest(BaseModel):
    project_path: str


def _finding(file: Path, project_path: Path, severity: str, rule: str, message: str, line: int | None = None) -> dict:
    return {
        "severity": severity,
        "rule": rule,
        "file": file.relative_to(project_path).as_posix(),
        "line": line,
        "message": message,
    }


def analyze_infrastructure(project_path: Path) -> dict:
    findings = []
    files_scanned = 0
    for path in project_path.rglob("*"):
        if not path.is_file() or any(part in {".git", "node_modules", ".venv", "venv", "target"} for part in path.parts):
            continue
        name = path.name.lower()
        suffix = path.suffix.lower()
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        lines = content.splitlines()

        if name.startswith("dockerfile"):
            has_user = any(line.strip().upper().startswith("USER ") for line in lines)
            for line_number, line in enumerate(lines, 1):
                upper = line.upper().strip()
                if upper.startswith("FROM ") and (":LATEST" in upper or "@" not in upper and ":" not in upper):
                    findings.append(_finding(path, project_path, "MEDIUM", "docker-unpinned-base", "Container base image is not pinned to a version or digest.", line_number))
                if upper.startswith("ADD "):
                    findings.append(_finding(path, project_path, "LOW", "docker-use-copy", "Use COPY instead of ADD unless archive extraction or URL retrieval is required.", line_number))
                if "--PRIVILEGED" in upper:
                    findings.append(_finding(path, project_path, "CRITICAL", "docker-privileged", "Privileged container execution defeats isolation controls.", line_number))
            if not has_user:
                findings.append(_finding(path, project_path, "MEDIUM", "docker-root-user", "Container does not declare a non-root USER."))

        if suffix in {".tf", ".tfvars"}:
            for line_number, line in enumerate(lines, 1):
                if re.search(r"0\.0\.0\.0/0", line):
                    findings.append(_finding(path, project_path, "HIGH", "iac-public-network", "Infrastructure rule exposes a resource to the entire IPv4 internet.", line_number))
                if re.search(r"acl\s*=\s*['\"]public-(read|read-write)", line, re.I):
                    findings.append(_finding(path, project_path, "HIGH", "iac-public-storage", "Storage resource uses a public ACL.", line_number))

        if suffix in {".yaml", ".yml"}:
            for line_number, line in enumerate(lines, 1):
                if re.search(r"\bprivileged:\s*true\b", line, re.I):
                    findings.append(_finding(path, project_path, "CRITICAL", "k8s-privileged", "Workload requests privileged container execution.", line_number))
                if re.search(r"\bhostNetwork:\s*true\b", line, re.I):
                    findings.append(_finding(path, project_path, "HIGH", "k8s-host-network", "Workload shares the host network namespace.", line_number))
                if re.search(r"image:\s*[^\s]+:latest\s*$", line, re.I):
                    findings.append(_finding(path, project_path, "MEDIUM", "k8s-latest-image", "Container image uses the mutable latest tag.", line_number))
                if "pull_request_target:" in line:
                    findings.append(_finding(path, project_path, "HIGH", "ci-pull-request-target", "Workflow runs privileged repository context for pull requests and requires careful trust-boundary review.", line_number))
                if re.search(r"permissions:\s*write-all", line, re.I):
                    findings.append(_finding(path, project_path, "HIGH", "ci-write-all", "Workflow grants write-all permissions.", line_number))

    return {
        "project_path": str(project_path),
        "files_scanned": files_scanned,
        "findings": findings,
        "summary": {
            "critical": sum(item["severity"] == "CRITICAL" for item in findings),
            "high": sum(item["severity"] == "HIGH" for item in findings),
            "medium": sum(item["severity"] == "MEDIUM" for item in findings),
            "low": sum(item["severity"] == "LOW" for item in findings),
        },
    }


@router.post("/analyze")
def infrastructure_analysis(payload: InfrastructureRequest):
    project_path = _allowed_project_path(payload.project_path)
    return analyze_infrastructure(project_path)
