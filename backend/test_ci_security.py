from backend.api.ci_security import build_sarif, evaluate_security_gate


def test_sarif_export_has_valid_core_shape():
    sarif = build_sarif("scan-1", [{
        "rule_id": "xss",
        "severity": "HIGH",
        "message": "Unsafe output",
        "path": "app.py",
        "line": 4,
    }], "demo")

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"


def test_security_gate_fails_on_open_high_finding():
    result = evaluate_security_gate(
        [{"id": "f-1", "severity": "HIGH", "status": "open", "message": "issue", "path": "app.py"}],
        "HIGH",
        ["open"],
    )

    assert result["passed"] is False
    assert result["violation_count"] == 1


def test_security_gate_ignores_resolved_findings():
    result = evaluate_security_gate(
        [{"id": "f-1", "severity": "CRITICAL", "status": "resolved"}],
        "HIGH",
        ["open", "in_progress"],
    )

    assert result["passed"] is True
