"""Supply-chain inventory, dependency posture, and secret detection API."""

import json
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.api.api_security import _allowed_project_path

router = APIRouter()
_MAX_FILES = 5_000
_MAX_FILE_BYTES = 1_000_000
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "target"}
_SECRET_PATTERNS = [
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("database_url", re.compile(r"(?i)(postgres|mysql|mongodb)://[^\s\"']+")),
]


class SupplyChainRequest(BaseModel):
    project_path: str
    include_secrets: bool = True


def _component(name: str, version: str, ecosystem: str, source: str) -> dict:
    return {
        "type": "library",
        "name": name,
        "version": version or "UNKNOWN",
        "purl": f"pkg:{ecosystem}/{name}@{version or 'UNKNOWN'}",
        "evidence": source,
    }


def _parse_requirements(path: Path) -> tuple[list[dict], list[dict]]:
    components, findings = [], []
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$", line)
        if not match:
            continue
        name, version = match.groups()
        version = (version or "").strip("=<>!~ ")
        components.append(_component(name, version, "pypi", path.name))
        if not version:
            findings.append({"type": "unbounded_dependency", "severity": "MEDIUM", "file": path.name, "line": line_number, "message": f"Dependency '{name}' is not pinned."})
    return components, findings


def _parse_package_json(path: Path) -> tuple[list[dict], list[dict]]:
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], [{"type": "invalid_manifest", "severity": "MEDIUM", "file": path.name, "message": "package.json is not valid JSON."}]
    components, findings = [], []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version in (package.get(section) or {}).items():
            version = str(version)
            components.append(_component(name, version, "npm", path.name))
            if version in {"latest", "*"} or version.startswith(("^", "~")):
                findings.append({"type": "loose_dependency", "severity": "LOW", "file": path.name, "dependency": name, "message": f"Dependency '{name}' uses a non-exact version '{version}'."})
    return components, findings


def _parse_manifests(project_path: Path) -> tuple[list[dict], list[dict]]:
    components, findings = [], []
    for path in project_path.rglob("*"):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name in {"requirements.txt", "requirements-dev.txt"}:
            found_components, found_findings = _parse_requirements(path)
        elif path.name == "package.json":
            found_components, found_findings = _parse_package_json(path)
        else:
            continue
        components.extend(found_components)
        findings.extend(found_findings)
    return components, findings


def _find_secrets(project_path: Path) -> list[dict]:
    findings = []
    scanned = 0
    for path in project_path.rglob("*"):
        if scanned >= _MAX_FILES:
            break
        if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES or any(part in _SKIP_DIRS for part in path.parts):
            continue
        scanned += 1
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_number, line in enumerate(content.splitlines(), 1):
            for secret_type, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    evidence = line[:120]
                    if match.groups():
                        evidence = evidence.replace(match.group(match.lastindex), "[REDACTED]")
                    findings.append({"type": "secret_exposure", "secret_type": secret_type, "severity": "HIGH", "file": path.relative_to(project_path).as_posix(), "line": line_number, "evidence": evidence})
                    break
    return findings


def analyze_supply_chain(project_path: Path, include_secrets: bool = True) -> dict:
    components, findings = _parse_manifests(project_path)
    if include_secrets:
        findings.extend(_find_secrets(project_path))
    return {
        "format": "CycloneDX-compatible inventory",
        "project_path": str(project_path),
        "components": components,
        "findings": findings,
        "summary": {
            "components": len(components),
            "secret_findings": sum(item["type"] == "secret_exposure" for item in findings),
            "dependency_findings": sum(item["type"] != "secret_exposure" for item in findings),
        },
        "disclaimer": "This inventory does not query a CVE database. Use the component list with an authoritative vulnerability feed for CVE matching.",
    }


@router.post("/analyze")
def supply_chain_analysis(payload: SupplyChainRequest):
    try:
        project_path = _allowed_project_path(payload.project_path)
    except HTTPException:
        raise
    return analyze_supply_chain(project_path, payload.include_secrets)
