"""Supply-chain inventory, dependency posture, and secret detection API."""

import json
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

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


class SbomRequest(BaseModel):
    project_path: str
    format: str = "cyclonedx"
    include_secrets: bool = False


def _component(name: str, version: str, ecosystem: str, source: str, scope: str | None = None) -> dict:
    component = {
        "type": "library",
        "name": name,
        "version": version or "UNKNOWN",
        "purl": f"pkg:{ecosystem}/{name}@{version or 'UNKNOWN'}",
        "evidence": source,
    }
    if scope:
        component["scope"] = scope
    return component


def _component_key(component: dict) -> str:
    return str(component.get("purl") or f"{component.get('name')}@{component.get('version')}")


def _parse_package_lock(path: Path) -> tuple[list[dict], list[dict], list[dict]]:
    """Parse npm lockfile v2/v3 packages and direct dependency relationships."""
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], [{"type": "invalid_manifest", "severity": "MEDIUM", "file": path.name, "message": "package-lock.json is not valid JSON."}], []

    components: list[dict] = []
    dependencies: list[dict] = []
    packages = lock.get("packages") or {}
    if packages:
        for package_path, package in packages.items():
            if not package_path or package_path == "":
                continue
            name = package_path.rsplit("node_modules/", 1)[-1]
            if name.startswith("@") and "/" in name:
                name = "@" + name[1:].replace("/node_modules/", "/", 1)
            version = str(package.get("version") or "UNKNOWN")
            component = _component(name, version, "npm", path.name, "optional" if package.get("optional") else None)
            components.append(component)
            source_ref = _component_key(component)
            for dependency_name, dependency_spec in (package.get("dependencies") or {}).items():
                dependency_version = str(dependency_spec) if isinstance(dependency_spec, str) else "UNKNOWN"
                dependency_component = _component(dependency_name, dependency_version, "npm", path.name)
                dependencies.append({"from": source_ref, "to": _component_key(dependency_component)})
    else:
        # npm lockfile v1 stores the dependency tree under `dependencies`.
        def walk(items: dict, parent: str | None = None) -> None:
            for name, package in items.items():
                component = _component(name, str(package.get("version") or "UNKNOWN"), "npm", path.name)
                components.append(component)
                current = _component_key(component)
                if parent:
                    dependencies.append({"from": parent, "to": current})
                walk(package.get("dependencies") or {}, current)

        walk(lock.get("dependencies") or {})
    return components, [], dependencies


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


def _parse_manifests(project_path: Path) -> tuple[list[dict], list[dict], list[dict]]:
    components, findings, dependencies = [], [], []
    for path in project_path.rglob("*"):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name in {"requirements.txt", "requirements-dev.txt"}:
            found_components, found_findings = _parse_requirements(path)
            found_dependencies = []
        elif path.name == "package.json":
            found_components, found_findings = _parse_package_json(path)
            found_dependencies = []
        elif path.name == "package-lock.json":
            found_components, found_findings, found_dependencies = _parse_package_lock(path)
        else:
            continue
        components.extend(found_components)
        findings.extend(found_findings)
        dependencies.extend(found_dependencies)
    return components, findings, dependencies


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
    components, findings, dependencies = _parse_manifests(project_path)
    if include_secrets:
        findings.extend(_find_secrets(project_path))
    return {
        "format": "normalized dependency inventory",
        "project_path": str(project_path),
        "components": components,
        "dependencies": dependencies,
        "findings": findings,
        "summary": {
            "components": len(components),
            "dependency_edges": len(dependencies),
            "secret_findings": sum(item["type"] == "secret_exposure" for item in findings),
            "dependency_findings": sum(item["type"] != "secret_exposure" for item in findings),
        },
        "disclaimer": "This inventory does not query a CVE database. Use the component list with an authoritative vulnerability feed for CVE matching.",
    }


def _bom_ref(component: dict) -> str:
    digest = sha256(_component_key(component).encode("utf-8")).hexdigest()[:16]
    return f"pkg-{digest}"


def _unique_components(components: list[dict]) -> list[dict]:
    unique: dict[str, dict] = {}
    for component in components:
        unique.setdefault(_component_key(component), component)
    return list(unique.values())


def _cyclonedx_bom(report: dict) -> dict:
    components = _unique_components(report["components"])
    ref_by_key = {_component_key(component): _bom_ref(component) for component in components}
    dependencies = []
    for edge in report.get("dependencies", []):
        source_ref = ref_by_key.get(edge.get("from")) or f"pkg-{sha256(str(edge.get('from')).encode()).hexdigest()[:16]}"
        target_ref = ref_by_key.get(edge.get("to")) or f"pkg-{sha256(str(edge.get('to')).encode()).hexdigest()[:16]}"
        dependencies.append({"ref": source_ref, "dependsOn": [target_ref]})
    grouped: dict[str, set[str]] = {}
    for item in dependencies:
        grouped.setdefault(item["ref"], set()).update(item["dependsOn"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": Path(report["project_path"]).name or "application", "version": "unknown"},
        },
        "components": [
            {"type": item["type"], "bom-ref": ref_by_key[_component_key(item)], "name": item["name"], "version": item["version"], "purl": item["purl"]}
            for item in components
        ],
        "dependencies": [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in grouped.items()],
    }


def _spdx_document(report: dict) -> dict:
    components = _unique_components(report["components"])
    package_by_key = {_component_key(component): f"SPDXRef-{_bom_ref(component)}" for component in components}
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": package_id} for package_id in package_by_key.values()]
    for edge in report.get("dependencies", []):
        source = package_by_key.get(edge.get("from"))
        target = package_by_key.get(edge.get("to"))
        if source and target:
            relationships.append({"spdxElementId": source, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": target})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": Path(report["project_path"]).name or "application",
        "documentNamespace": f"https://ai-appsec.local/spdx/{uuid4()}",
        "creationInfo": {"created": datetime.now(timezone.utc).isoformat(), "creators": ["Tool: AI AppSec Platform"]},
        "packages": [
            {
                "SPDXID": package_by_key[_component_key(item)],
                "name": item["name"],
                "versionInfo": item["version"],
                "downloadLocation": "NOASSERTION",
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": item["purl"]}],
            }
            for item in components
        ],
        "relationships": relationships,
    }


def generate_sbom(project_path: Path, output_format: str = "cyclonedx", include_secrets: bool = False) -> dict:
    normalized_format = output_format.lower().replace("-", "")
    report = analyze_supply_chain(project_path, include_secrets=include_secrets)
    if normalized_format in {"cyclonedx", "cdx"}:
        return _cyclonedx_bom(report)
    if normalized_format in {"spdx", "spdx23"}:
        return _spdx_document(report)
    raise ValueError("format must be 'cyclonedx' or 'spdx'")


@router.post("/analyze")
def supply_chain_analysis(payload: SupplyChainRequest):
    try:
        project_path = _allowed_project_path(payload.project_path)
    except HTTPException:
        raise
    return analyze_supply_chain(project_path, payload.include_secrets)


@router.post("/sbom")
def supply_chain_sbom(payload: SbomRequest):
    try:
        project_path = _allowed_project_path(payload.project_path)
        return generate_sbom(project_path, payload.format, payload.include_secrets)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
