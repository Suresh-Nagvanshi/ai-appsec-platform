from backend.db.session import init_db, SessionLocal
from backend.db.models import ScanModel, FindingModel
from backend.storage.findings_repository import FindingsRepository

def test_database_orm():
    init_db()
    db = SessionLocal()
    
    scan = ScanModel(
        id="test_db_scan_1",
        project_name="TestORMProject",
        scan_type="static",
        status="COMPLETED",
        summary_json={"critical": 1}
    )
    db.add(scan)
    
    finding = FindingModel(
        id="test_db_finding_1",
        scan_id="test_db_scan_1",
        rule_id="java.lang.security.sqli",
        severity="CRITICAL",
        file_path="src/Sql.java",
        message="SQL injection",
        risk_score=9.5
    )
    db.add(finding)
    db.commit()
    
    queried_scan = db.query(ScanModel).filter(ScanModel.id == "test_db_scan_1").first()
    assert queried_scan is not None
    assert queried_scan.project_name == "TestORMProject"
    assert len(queried_scan.findings) == 1
    assert queried_scan.findings[0].severity == "CRITICAL"
    
    db.delete(scan)
    db.commit()
    db.close()
