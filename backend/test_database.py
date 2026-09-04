import importlib
import sys

def test_database_orm(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path.as_posix()}/appsec.sqlite")
    for module_name in [
        "backend.db",
        "backend.db.base",
        "backend.db.session",
        "backend.db.models",
    ]:
        sys.modules.pop(module_name, None)

    db_session = importlib.import_module("backend.db.session")
    models = importlib.import_module("backend.db.models")
    init_db = db_session.init_db
    SessionLocal = db_session.SessionLocal
    ScanModel = models.ScanModel
    FindingModel = models.FindingModel

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
