"""
API security discovery endpoints.

The first API-security capability is passive endpoint inventory. It reuses the
source scanners used by context enrichment and only permits managed project
roots so callers cannot use this endpoint as an arbitrary filesystem reader.
"""

from pathlib import Path
from typing import List

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
