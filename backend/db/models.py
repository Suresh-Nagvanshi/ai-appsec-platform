from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.db.base import Base

class ScanModel(Base):
    __tablename__ = "scans"
    __table_args__ = {"extend_existing": True}

    id = Column(String(64), primary_key=True, index=True)
    project_name = Column(String(255), index=True)
    scan_type = Column(String(50), default="static")
    status = Column(String(50), default="COMPLETED")
    progress = Column(Integer, default=100)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    summary_json = Column(JSON, nullable=True)
    source_url = Column(Text, nullable=True)
    timeline = Column(JSON, nullable=True)
    logs = Column(JSON, nullable=True)

    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = {"extend_existing": True}

    id = Column(String(64), primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id"), index=True)
    rule_id = Column(String(255), index=True)
    severity = Column(String(50), index=True)
    file_path = Column(Text)
    line_number = Column(Integer, nullable=True)
    message = Column(Text)
    cwe = Column(String(100), nullable=True)
    owasp = Column(String(100), nullable=True)
    mitre = Column(String(100), nullable=True)
    status = Column(String(50), default="open", index=True)
    risk_score = Column(Float, default=0.0)
    exploitability = Column(String(50), nullable=True)
    priority = Column(String(50), nullable=True)
    raw_payload_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("ScanModel", back_populates="findings")

Scan = ScanModel
Finding = FindingModel


@property
def _scan_summary(self):
    return self.summary_json


@_scan_summary.setter
def _scan_summary(self, value):
    self.summary_json = value


ScanModel.summary = _scan_summary
