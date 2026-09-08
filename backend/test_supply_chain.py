from backend.api.supply_chain import analyze_supply_chain, generate_sbom


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


def test_supply_chain_parses_lockfile_edges_and_generates_cyclonedx(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{"express":"4.18.3"}},"node_modules/express":{"version":"4.18.3","dependencies":{"body-parser":"1.20.2"}},"node_modules/body-parser":{"version":"1.20.2"}}}',
        encoding="utf-8",
    )

    report = analyze_supply_chain(project, include_secrets=False)
    bom = generate_sbom(project, "cyclonedx")

    assert report["summary"]["components"] == 2
    assert report["summary"]["dependency_edges"] == 1
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert len(bom["components"]) == 2
    assert bom["dependencies"]


def test_supply_chain_generates_spdx(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")

    document = generate_sbom(project, "spdx")

    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["packages"][0]["name"] == "requests"
    assert document["relationships"][0]["relationshipType"] == "DESCRIBES"
