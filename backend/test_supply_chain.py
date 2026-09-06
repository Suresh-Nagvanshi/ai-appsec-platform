from backend.api.supply_chain import analyze_supply_chain


def test_supply_chain_inventory_and_secret_detection(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests\nhttpx==0.27.2\n", encoding="utf-8")
    (project / "package.json").write_text(
        '{"dependencies":{"react":"^19.0.0","safe-lib":"1.2.3"}}', encoding="utf-8"
    )
    (project / "config.py").write_text(
        'API_KEY = "1234567890abcdef1234"\n', encoding="utf-8"
    )

    report = analyze_supply_chain(project)

    names = {component["name"] for component in report["components"]}
    assert {"requests", "httpx", "react", "safe-lib"}.issubset(names)
    assert report["summary"]["secret_findings"] == 1
    assert report["summary"]["dependency_findings"] == 2


def test_supply_chain_can_skip_secret_scanning(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "config.py").write_text(
        'API_KEY = "1234567890abcdef1234"\n', encoding="utf-8"
    )

    report = analyze_supply_chain(project, include_secrets=False)

    assert report["summary"]["secret_findings"] == 0
