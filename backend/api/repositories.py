from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from uuid import uuid4
from datetime import datetime
import json
import os
from pathlib import Path

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# Storage path  (same base_dir pattern used by FindingsRepository)
# ─────────────────────────────────────────────────────────────────────────────
_BASE_DIR = Path(__file__).resolve().parent.parent.parent / "database" / "repositories"
_BASE_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Models
# ─────────────────────────────────────────────────────────────────────────────

class RepositoryCreate(BaseModel):
    name: str
    url: str
    provider: Optional[str] = "github"


class Repository(BaseModel):
    id: str
    name: str
    url: str
    provider: str
    status: str          # active | inactive
    last_scan: Optional[str] = None
    created_at: str


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _repo_file(repo_id: str) -> Path:
    return _BASE_DIR / f"{repo_id}.json"


def _load_all() -> List[dict]:
    repos: List[dict] = []
    for f in sorted(_BASE_DIR.glob("*.json"), reverse=True):
        try:
            repos.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return repos


def _save(repo: dict) -> None:
    _repo_file(repo["id"]).write_text(
        json.dumps(repo, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[Repository])
def list_repositories():
    """Return all saved repositories, newest first."""
    return _load_all()


@router.post("", response_model=Repository, status_code=201)
def create_repository(payload: RepositoryCreate):
    """
    Register a repository for scanning.
    Validates that a GitHub URL starts with https://github.com/
    to re-use the same SSRF guard applied in the scan endpoints.
    """
    if payload.provider == "github" and not payload.url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=400,
            detail="Only public GitHub HTTPS URLs are accepted (https://github.com/...)",
        )

    repo: dict = {
        "id": str(uuid4()),
        "name": payload.name,
        "url": payload.url,
        "provider": payload.provider,
        "status": "active",
        "last_scan": None,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    _save(repo)
    return repo


@router.get("/{repo_id}", response_model=Repository)
def get_repository(repo_id: str):
    """Return a single repository record."""
    path = _repo_file(repo_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Repository not found")
    return json.loads(path.read_text(encoding="utf-8"))


@router.patch("/{repo_id}/last-scan")
def update_last_scan(repo_id: str, scan_id: str):
    """
    Internal helper called by the scan orchestrator after a successful scan
    to record the most-recent scan_id on the repository.
    """
    path = _repo_file(repo_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Repository not found")
    repo = json.loads(path.read_text(encoding="utf-8"))
    repo["last_scan"] = scan_id
    _save(repo)
    return {"ok": True, "last_scan": scan_id}
