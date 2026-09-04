from backend.reporting.report_generator import ReportGenerator

def test_report_generator():
    generator = ReportGenerator()
    findings = [{
        "id": "f_1",
        "representative_finding": {
            "finding": {"rule_id": "test.rule", "path": "src/App.java", "line": 10},
            "risk": {"risk_score": 8, "severity": "HIGH"},
            "ai_analysis": {"summary": "High risk vulnerability"}
        }
    }]
    report = generator.generate(project_name="TestApp", findings=findings)
    assert report is not None