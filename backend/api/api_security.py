"""
API security discovery endpoints.

The first API-security capability is passive endpoint inventory. It reuses the
source scanners used by context enrichment and only permits managed project
roots so callers cannot use this endpoint as an arbitrary filesystem reader.
"""

from pathlib import Path
from typing import List
from ipaddress import ip_address
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.enrichment.endpoint_extractor import EndpointExtractor

router = APIRouter()

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_ALLOWED_ROOTS = tuple(
    (_BASE_DIR / directory).resolve()
    for directory in ("repos", "uploads", "extracted")
)
_MAX_ENDPOINTS = 10_000

OWASP_API_TOP10 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}


class EndpointDiscoveryRequest(BaseModel):
    project_path: str = Field(min_length=1)


class AuthzTestRequest(BaseModel):
    base_url: str = Field(min_length=1)
    endpoints: List[dict] = Field(min_length=1, max_length=100)
    headers: dict[str, str] = Field(default_factory=dict)


class APIContractRequest(BaseModel):
    spec: dict
    baseline: dict | None = None


def _allowed_project_path(project_path: str) -> Path:
    candidate = Path(project_path).expanduser().resolve()
    if not candidate.is_dir():
        raise HTTPException(status_code=404, detail="Project directory not found")

    if not any(candidate == root or root in candidate.parents for root in _ALLOWED_ROOTS):
        raise HTTPException(
            status_code=400,
            detail="Project path must be inside repos, uploads, or extracted",
        )
    return candidate


def discover_endpoints(project_path: Path) -> List[dict]:
    """Return a deterministic, normalized endpoint inventory for a project."""
    extractor = EndpointExtractor()
    discovered = extractor.extract(str(project_path))
    endpoints = []
    seen = set()

    for endpoint in discovered:
        file_path = Path(endpoint["file"])
        try:
            relative_file = file_path.resolve().relative_to(project_path).as_posix()
        except ValueError:
            relative_file = file_path.name

        normalized = {
            "framework": endpoint.get("framework", "unknown"),
            "method": endpoint.get("method", "REQUEST").upper(),
            "path": endpoint.get("endpoint", ""),
            "file": relative_file,
        }
        key = tuple(normalized.values())
        if normalized["path"] and key not in seen:
            seen.add(key)
            endpoints.append(normalized)

        if len(endpoints) >= _MAX_ENDPOINTS:
            break

    return sorted(endpoints, key=lambda item: (item["file"], item["path"], item["method"]))


def map_api_top10(endpoints: List[dict]) -> List[dict]:
    """Map endpoint characteristics to review areas in OWASP API Top 10."""
    mapped = []
    for endpoint in endpoints:
        path = endpoint["path"].lower()
        method = endpoint["method"]
        concerns = []

        if any(token in path for token in ("{", ":", "<", "id", "user", "account", "order")):
            concerns.append(("API1:2023", "Object identifiers or user-owned resources require object-level authorization."))
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            concerns.append(("API5:2023", "State-changing functions require function-level authorization."))
        if any(token in path for token in ("login", "auth", "token", "password", "session")):
            concerns.append(("API2:2023", "Authentication-related endpoint requires token and credential controls."))
        if any(token in path for token in ("search", "export", "report", "download", "upload")):
            concerns.append(("API4:2023", "Potentially expensive or bulk operation requires rate and resource limits."))
        if path in {"/", "/health", "/status", "/metrics", "/debug"}:
            concerns.append(("API8:2023", "Operational endpoint should expose only intended information and configuration."))

        mapped.append({
            **endpoint,
            "owasp_api": [
                {
                    "id": category_id,
                    "name": OWASP_API_TOP10[category_id],
                    "confidence": "REVIEW",
                    "rationale": rationale,
                }
                for category_id, rationale in concerns
            ],
        })
    return mapped


def analyze_api_contract(spec: dict) -> dict:
    """Analyze an OpenAPI/Swagger document without making network requests."""
    version = str(spec.get("openapi") or spec.get("swagger") or "")
    findings = []
    paths = spec.get("paths") or {}
    global_security = spec.get("security")
    operations = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"} or not isinstance(operation, dict):
                continue
            operations.append((method.upper(), path, operation))
            location = f"{method.upper()} {path}"
            if operation.get("deprecated"):
                findings.append({"category": "lifecycle", "severity": "LOW", "location": location, "message": "Deprecated operation remains in the contract."})
            if not operation.get("operationId"):
                findings.append({"category": "contract_quality", "severity": "LOW", "location": location, "message": "Operation is missing operationId."})
            if operation.get("security") is None and global_security is None and method.lower() not in {"options", "head"}:
                findings.append({"category": "authentication", "severity": "HIGH", "location": location, "message": "Operation has no declared authentication requirement."})
            if method.upper() in {"POST", "PUT", "PATCH"} and "requestBody" not in operation:
                findings.append({"category": "contract_quality", "severity": "MEDIUM", "location": location, "message": "State-changing operation has no requestBody schema."})
            parameters = operation.get("parameters", [])
            declared_path_params = {parameter.get("name") for parameter in parameters if parameter.get("in") == "path"}
            required_path_params = {part[1:-1] for part in path.split("/") if part.startswith("{") and part.endswith("}")}
            for missing in sorted(required_path_params - declared_path_params):
                findings.append({"category": "contract_quality", "severity": "HIGH", "location": location, "message": f"Path parameter '{missing}' is not declared."})

    return {
        "format": "OpenAPI" if spec.get("openapi") else "Swagger" if spec.get("swagger") else "unknown",
        "version": version,
        "endpoint_count": len(operations),
        "findings": findings,
        "summary": {
            "high": sum(item["severity"] == "HIGH" for item in findings),
            "medium": sum(item["severity"] == "MEDIUM" for item in findings),
            "low": sum(item["severity"] == "LOW" for item in findings),
        },
    }


def compare_api_contracts(baseline: dict, current: dict) -> dict:
    """Report route-level API contract drift between two OpenAPI documents."""
    def routes(spec: dict) -> set[str]:
        return {
            f"{method.upper()} {path}"
            for path, path_item in (spec.get("paths") or {}).items()
            if isinstance(path_item, dict)
            for method in path_item
            if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}
        }

    before = routes(baseline)
    after = routes(current)
    return {
        "added": sorted(after - before),
        "removed": sorted(before - after),
        "unchanged": sorted(before & after),
        "breaking_changes": sorted(before - after),
    }


def _validate_probe_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="base_url must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="base_url must not contain credentials")
    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "localhost.localdomain"}:
        raise HTTPException(status_code=400, detail="Private and local probe targets are not allowed")
    try:
        address = ip_address(hostname)
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            raise HTTPException(status_code=400, detail="Private and local probe targets are not allowed")
    except ValueError:
        if hostname.endswith((".local", ".internal")):
            raise HTTPException(status_code=400, detail="Private and local probe targets are not allowed")
    return base_url.rstrip("/") + "/"


def _probe_endpoint(client: httpx.Client, base_url: str, endpoint: dict, headers: dict[str, str]) -> dict:
    path = str(endpoint.get("path", ""))
    if any(token in path for token in ("{", ":", "<")):
        return {**endpoint, "status": "SKIPPED", "reason": "Templated path requires concrete object identifiers"}

    url = urljoin(base_url, path.lstrip("/"))
    try:
        response = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return {**endpoint, "status": "ERROR", "reason": str(exc)}

    status = response.status_code
    if status in {401, 403}:
        classification = "AUTH_REQUIRED"
    elif status < 400:
        classification = "PUBLIC_OR_UNPROTECTED"
    else:
        classification = "INCONCLUSIVE"

    return {
        **endpoint,
        "url": url,
        "http_status": status,
        "classification": classification,
        "response_size": len(response.content),
    }


def run_authentication_authorization(
    base_url: str,
    endpoints: List[dict],
    headers: dict[str, str] | None = None,
) -> List[dict]:
    """Passively probe GET endpoints and classify observable access controls."""
    target = _validate_probe_url(base_url)
    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        return [_probe_endpoint(client, target, endpoint, headers or {}) for endpoint in endpoints]


@router.post("/endpoints")
def endpoint_inventory(payload: EndpointDiscoveryRequest):
    """Discover HTTP endpoints in a managed local repository or extraction."""
    project_path = _allowed_project_path(payload.project_path)
    endpoints = discover_endpoints(project_path)
    return {
        "project_path": str(project_path),
        "total": len(endpoints),
        "endpoints": endpoints,
    }


@router.post("/mapping")
def api_top10_mapping(payload: EndpointDiscoveryRequest):
    """Return endpoint inventory annotated with OWASP API Top 10 review areas."""
    project_path = _allowed_project_path(payload.project_path)
    endpoints = map_api_top10(discover_endpoints(project_path))
    category_counts = {
        category_id: sum(
            any(item["id"] == category_id for item in endpoint["owasp_api"])
            for endpoint in endpoints
        )
        for category_id in OWASP_API_TOP10
    }
    return {
        "project_path": str(project_path),
        "total": len(endpoints),
        "category_counts": category_counts,
        "endpoints": endpoints,
        "disclaimer": "Mappings identify review areas from static route characteristics; they are not proof of exploitable vulnerabilities.",
    }


@router.post("/authz-test")
def authz_test(payload: AuthzTestRequest):
    """Run non-destructive GET probes for authentication/authorization signals."""
    results = run_authentication_authorization(
        payload.base_url,
        payload.endpoints,
        payload.headers,
    )
    return {
        "base_url": payload.base_url.rstrip("/"),
        "tested": len(results),
        "results": results,
        "disclaimer": "This performs non-destructive GET requests only. A successful response is a review signal, not proof of missing authorization; meaningful authorization testing requires separate identities and concrete object IDs.",
    }


@router.post("/contract")
def api_contract_analysis(payload: APIContractRequest):
    """Analyze an OpenAPI/Swagger contract and optionally compare a baseline."""
    analysis = analyze_api_contract(payload.spec)
    if payload.baseline is not None:
        analysis["drift"] = compare_api_contracts(payload.baseline, payload.spec)
    return analysis
