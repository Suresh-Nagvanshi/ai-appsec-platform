from backend.api.runtime_security import RuntimeAsset, analyze_runtime_posture


def test_runtime_posture_correlates_exposure_and_vulnerabilities():
    report = analyze_runtime_posture([
        RuntimeAsset(
            asset_id="cluster-api",
            name="api",
            asset_type="kubernetes-service",
            environment="production",
            internet_exposed=True,
            encrypted=False,
            vulnerabilities=[{"cve": "CVE-2026-0001", "severity": "CRITICAL"}],
        )
    ])

    assert report["summary"] == {"assets": 1, "internet_exposed": 1, "critical": 1, "high": 2}
    assert report["findings"][0]["severity"] == "CRITICAL"


def test_runtime_posture_is_clean_for_private_asset():
    report = analyze_runtime_posture([
        RuntimeAsset(
            asset_id="worker",
            name="worker",
            asset_type="container",
            environment="staging",
            internet_exposed=False,
            encrypted=True,
        )
    ])

    assert report["findings"] == []
