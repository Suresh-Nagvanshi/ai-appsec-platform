import importlib
import os


def _reload_persistence_modules(monkeypatch, db_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    for module_name in [
        "backend.db.session",
        "backend.db.models",
        "backend.storage.findings_repository",
        "backend.api.scan_state",
    ]:
        if module_name in importlib.sys.modules:
            del importlib.sys.modules[module_name]
    import backend.db.session as db_session
    import backend.storage.findings_repository as findings_repository_module
    import backend.api.scan_state as scan_state_module

    importlib.reload(db_session)
    importlib.reload(findings_repository_module)
    importlib.reload(scan_state_module)
    return findings_repository_module, scan_state_module


def test_findings_repository_round_trip(monkeypatch, tmp_path):
    db_path = tmp_path / "findings.sqlite"
    repo_module, _ = _reload_persistence_modules(monkeypatch, db_path)

    repo = repo_module.FindingsRepository()
    scan_id = repo.save_scan(
        project_name="demo",
        scan_results={
            "scan_id": "scan-1",
            "scan_type": "github",
            "results": [
                {
                    "id": "finding-1",
                    "severity": "HIGH",
                    "message": "SQL injection",
                    "path": "app.py",
                    "line": 10,
                    "status": "open",
                }
            ],
            "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        },
    )

    assert scan_id == "scan-1"
    findings = repo.get_all_findings()
    assert len(findings) == 1
    assert findings[0]["scan_id"] == scan_id

    updated = repo.update_finding_status("finding-1", "resolved")
    assert updated is True
    assert repo.get_finding_by_id("finding-1")["status"] == "resolved"

    scan = repo.get_scan("scan-1")
    assert scan is not None
    assert scan["project_name"] == "demo"


def test_scan_state_persists_across_reloads(monkeypatch, tmp_path):
    db_path = tmp_path / "scan_state.sqlite"
    _, scan_state_module = _reload_persistence_modules(monkeypatch, db_path)

    scan_state_module._scans.clear()
    scan_state_module._scans["scan-2"] = {
        "id": "scan-2",
        "status": "RUNNING",
        "progress": 42,
        "summary": {"high": 2},
        "logs": [],
        "timeline": [],
    }
    scan_state_module.save_state()

    reloaded_module = importlib.reload(scan_state_module)
    assert reloaded_module._scans["scan-2"]["status"] == "RUNNING"
    assert reloaded_module._scans["scan-2"]["progress"] == 42
