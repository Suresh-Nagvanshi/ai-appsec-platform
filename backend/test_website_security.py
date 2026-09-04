import pytest

from fastapi import HTTPException

from backend.api.website_scans import _validate_website_url, _new_website_scan
from backend.api.website_scan_state import _website_scans
from backend.services.website_scanner import _build_summary


def test_validate_website_url_rejects_private_hosts():
    with pytest.raises(HTTPException) as exc:
        _validate_website_url("http://localhost:3000")

    assert exc.value.status_code == 400


def test_validate_website_url_rejects_raw_ip():
    with pytest.raises(HTTPException) as exc:
        _validate_website_url("https://127.0.0.1")

    assert exc.value.status_code == 400


def test_new_website_scan_defaults():
    scan = _new_website_scan("https://example.com", 10, 2)

    assert scan["scanType"] == "website"
    assert scan["target"] == "https://example.com"
    assert scan["status"] == "QUEUED"
    assert scan["timeline"]
    assert scan["findings"] == []


def test_build_summary_counts_severities():
    findings = [
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
        {"severity": "unknown"},
    ]

    summary = _build_summary(findings)

    assert summary == {"critical": 1, "high": 2, "medium": 1, "low": 2}


def test_website_scan_state_is_mutable():
    _website_scans.clear()
    _website_scans["scan-1"] = {"id": "scan-1"}
    assert _website_scans["scan-1"]["id"] == "scan-1"
