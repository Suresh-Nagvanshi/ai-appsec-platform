from backend.scanning.multi_engine import correlate_findings, normalize_finding


def test_normalize_finding_preserves_engine_provenance():
    result = normalize_finding(
        "bandit",
        {"test_id": "B602", "issue_text": "subprocess call", "filename": "app.py", "line_number": 12, "issue_severity": "HIGH"},
    )

    assert result["finding"]["engine"] == "bandit"
    assert result["finding"]["path"] == "app.py"
    assert result["finding"]["scanner"] == "bandit"


def test_correlate_findings_merges_multi_engine_evidence():
    semgrep = normalize_finding("semgrep", {"check_id": "python.sql", "path": "app.py", "start": {"line": 12}, "extra": {"message": "SQL injection"}})
    bandit = normalize_finding("bandit", {"test_id": "python.sql", "filename": "app.py", "line_number": 12, "issue_text": "SQL injection"})

    result = correlate_findings([semgrep, bandit])

    assert len(result) == 1
    assert result[0]["detected_by"] == ["bandit", "semgrep"]
    assert result[0]["engine_count"] == 2
    assert result[0]["confidence_score"] == 75
    assert set(result[0]["engine_evidence"]) == {"bandit", "semgrep"}

