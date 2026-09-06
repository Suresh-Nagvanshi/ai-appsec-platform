from backend.api.regression_tests import create_regression_specs, evaluate_regression_specs


def _finding(finding_id="f-1", code="execute(user_input)"):
    return {
        "id": finding_id,
        "scan_id": "scan-1",
        "status": "open",
        "finding": {
            "rule_id": "python.security.injection",
            "cwe": ["CWE-78"],
            "path": "app.py",
        },
        "snippet": {"vulnerable_line": code},
    }


def test_confirmed_finding_becomes_regression_spec():
    specs = create_regression_specs("scan-1", [_finding()])

    assert len(specs) == 1
    assert specs[0]["expected"] == "finding_absent"
    assert specs[0]["fingerprint"]


def test_regression_evaluation_fails_when_finding_reappears():
    specs = create_regression_specs("scan-1", [_finding()])

    report = evaluate_regression_specs(specs, [_finding("f-2")])

    assert report["status"] == "FAIL"
    assert report["failed"] == 1


def test_regression_evaluation_passes_after_finding_disappears():
    specs = create_regression_specs("scan-1", [_finding()])

    report = evaluate_regression_specs(specs, [])

    assert report["status"] == "PASS"
    assert report["failed"] == 0
