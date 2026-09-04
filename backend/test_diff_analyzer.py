from backend.storage.diff_analyzer import DiffAnalyzer

def test_diff_analyzer():
    analyzer = DiffAnalyzer()
    old_scan = {
        "scan_id": "scan_1",
        "findings": [{"id": "f1", "rule_id": "rule_a"}]
    }
    new_scan = {
        "scan_id": "scan_2",
        "findings": [{"id": "f1", "rule_id": "rule_a"}, {"id": "f2", "rule_id": "rule_b"}]
    }
    diff = analyzer.compare_scans(old_scan=old_scan, new_scan=new_scan)
    assert diff is not None
    assert "new_findings" in diff
    assert "summary" in diff