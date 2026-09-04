import tempfile
from pathlib import Path
from backend.storage.findings_repository import FindingsRepository

def test_findings_repository(tmp_path):
    repo = FindingsRepository(base_dir=tmp_path)
    sample_finding = {
        "id": "f_1001",
        "rule_id": "test.rule",
        "severity": "HIGH",
        "status": "open"
    }
    scan_id = repo.save_scan(
        project_name="TestProject",
        scan_results=[sample_finding]
    )
    assert scan_id is not None
    scan = repo.get_scan(scan_id)
    assert scan is not None
    assert scan["project_name"] == "TestProject"