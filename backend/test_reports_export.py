from backend.reporting.report_generator import ReportGenerator

def test_markdown_and_html_reports():
    generator = ReportGenerator()
    scan_data = {
        "scan_id": "test_scan_100",
        "project_name": "WebGoat",
        "summary": {"top_risk_score": 9.2, "critical": 1, "high": 2},
        "findings": [
            {
                "rule_id": "java.lang.sqli",
                "severity": "CRITICAL",
                "path": "src/Sql.java",
                "line": 42,
                "message": "Potential SQL injection vulnerability",
                "ai_analysis": {
                    "summary": "High severity SQL injection",
                    "secure_fix": "Use prepared statements"
                }
            }
        ]
    }
    
    md = generator.generate_markdown_report(scan_data)
    assert "# Executive Security Report — WebGoat" in md
    assert "java.lang.sqli" in md
    assert "Use prepared statements" in md
    
    html = generator.generate_html_report(scan_data)
    assert "<title>Security Report - WebGoat</title>" in html
    assert "CRITICAL" in html
    assert "src/Sql.java:42" in html
