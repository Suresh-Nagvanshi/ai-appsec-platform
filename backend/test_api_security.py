from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.api.api_security import (
    _allowed_project_path,
    _validate_probe_url,
    discover_endpoints,
    map_api_top10,
    analyze_api_contract,
    compare_api_contracts,
    run_authentication_authorization,
)
from backend.api.ai_security import (
    AISecurityTestRequest,
    _validate_target_url,
    run_ai_security_tests,
    ModelEvaluationCase,
    ModelEvaluationRequest,
    run_model_evaluation,
)


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


def test_authz_probe_classifies_authentication_signals(monkeypatch):
    class FakeResponse:
        status_code = 401
        content = b"unauthorized"

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, headers):
            assert url == "https://example.com/users"
            return FakeResponse()

    monkeypatch.setattr("backend.api.api_security.httpx.Client", lambda **kwargs: FakeClient())
    results = run_authentication_authorization(
        "https://example.com",
        [{"method": "GET", "path": "/users", "framework": "FastAPI", "file": "app.py"}],
    )

    assert results[0]["classification"] == "AUTH_REQUIRED"
    assert results[0]["http_status"] == 401


def test_probe_rejects_private_targets():
    with pytest.raises(HTTPException) as exc:
        _validate_probe_url("http://127.0.0.1:8000")

    assert exc.value.status_code == 400


def test_ai_security_suite_reports_prompt_injection_and_safety(monkeypatch):
    class FakeResponse:
        status_code = 200
        content = b"safe"

        def json(self):
            return {"response": "I cannot help with that unsafe request."}

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json, headers):
            return FakeResponse()

    monkeypatch.setattr("backend.api.ai_security._validate_target_url", lambda url: url)
    monkeypatch.setattr("backend.api.ai_security.httpx.Client", lambda **kwargs: FakeClient())
    request = AISecurityTestRequest(
        target_url="https://example.com/model",
        probe_ids=["prompt-injection-instruction-override", "safety-harmful-request-refusal"],
    )

    report = run_ai_security_tests(request)

    assert report["tested"] == 2
    assert report["categories"]["safety_assessment"]["status"] == "PASS"
    assert report["categories"]["prompt_injection"]["status"] == "PASS"


def test_ai_security_suite_detects_canary_leak(monkeypatch):
    class FakeResponse:
        status_code = 200
        content = b"leak"

        def json(self):
            return {"response": "APPSEC_TEST_CANARY_7F3A"}

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json, headers):
            return FakeResponse()

    monkeypatch.setattr("backend.api.ai_security._validate_target_url", lambda url: url)
    monkeypatch.setattr("backend.api.ai_security.httpx.Client", lambda **kwargs: FakeClient())
    request = AISecurityTestRequest(
        target_url="https://example.com/model",
        probe_ids=["prompt-injection-instruction-override"],
    )

    report = run_ai_security_tests(request)

    assert report["overall_status"] == "FAIL"
    assert report["results"][0]["matched_failure_markers"] == ["APPSEC_TEST_CANARY_7F3A"]


def test_openapi_contract_analysis_detects_auth_and_path_parameter_gaps():
    analysis = analyze_api_contract({
        "openapi": "3.0.0",
        "paths": {"/users/{user_id}": {"get": {}}},
    })

    messages = {finding["message"] for finding in analysis["findings"]}
    assert "Operation has no declared authentication requirement." in messages
    assert "Path parameter 'user_id' is not declared." in messages


def test_openapi_contract_comparison_reports_route_drift():
    drift = compare_api_contracts(
        {"paths": {"/old": {"get": {}}, "/stable": {"get": {}}}},
        {"paths": {"/new": {"post": {}}, "/stable": {"get": {}}}},
    )

    assert drift["added"] == ["POST /new"]
    assert drift["breaking_changes"] == ["GET /old"]


def test_model_evaluation_reports_accuracy_and_latency(monkeypatch):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {"response": "expected answer"}

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json, headers):
            return FakeResponse()

    monkeypatch.setattr("backend.api.ai_security._validate_target_url", lambda url: url)
    monkeypatch.setattr("backend.api.ai_security.httpx.Client", lambda **kwargs: FakeClient())
    report = run_model_evaluation(ModelEvaluationRequest(
        target_url="https://example.com/model",
        cases=[ModelEvaluationCase(id="case-1", prompt="hello", expected_markers=["expected"])],
    ))

    assert report["status"] == "PASS"
    assert report["accuracy"] == 1.0
    assert report["average_latency_ms"] >= 0
