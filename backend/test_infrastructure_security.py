from backend.api.infrastructure_security import analyze_infrastructure


def test_infrastructure_analysis_detects_container_and_iac_risks(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "Dockerfile").write_text("FROM python:latest\nADD . /app\n", encoding="utf-8")
    (project / "network.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n', encoding="utf-8")
    (project / "deployment.yaml").write_text("securityContext:\n  privileged: true\n", encoding="utf-8")

    report = analyze_infrastructure(project)
    rules = {finding["rule"] for finding in report["findings"]}

    assert {"docker-unpinned-base", "docker-use-copy", "iac-public-network", "k8s-privileged"}.issubset(rules)
    assert report["summary"]["critical"] == 1
    assert report["summary"]["high"] == 1


def test_infrastructure_analysis_has_no_findings_for_safe_baseline(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "Dockerfile").write_text("FROM python:3.12-slim\nUSER app\nCOPY . /app\n", encoding="utf-8")

    report = analyze_infrastructure(project)

    assert report["findings"] == []
