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
