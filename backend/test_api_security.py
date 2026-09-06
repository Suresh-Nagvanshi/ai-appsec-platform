from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.api.api_security import _allowed_project_path, discover_endpoints, map_api_top10


def test_discover_endpoints_normalizes_supported_frameworks(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        '@app.get("/health")\ndef health(): pass\n', encoding="utf-8"
    )
    (project / "routes.js").write_text(
        'router.post("/users", handler)\n', encoding="utf-8"
    )

    monkeypatch.setattr(
        "backend.api.api_security._ALLOWED_ROOTS", (tmp_path.resolve(),)
    )

    endpoints = discover_endpoints(project)

    assert endpoints == [
        {"framework": "FastAPI", "method": "GET", "path": "/health", "file": "app.py"},
        {"framework": "Express.js", "method": "POST", "path": "/users", "file": "routes.js"},
    ]


def test_endpoint_discovery_rejects_unmanaged_paths(tmp_path, monkeypatch):
    managed = tmp_path / "repos"
    managed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(
        "backend.api.api_security._ALLOWED_ROOTS", (managed.resolve(),)
    )

    with pytest.raises(HTTPException) as exc:
        _allowed_project_path(str(outside))

    assert exc.value.status_code == 400


def test_map_api_top10_marks_object_and_function_authorization_reviews():
    mapped = map_api_top10([
        {"framework": "FastAPI", "method": "POST", "path": "/users/{user_id}", "file": "app.py"}
    ])

    categories = {item["id"] for item in mapped[0]["owasp_api"]}
    assert categories == {"API1:2023", "API5:2023"}
    assert all(item["confidence"] == "REVIEW" for item in mapped[0]["owasp_api"])
