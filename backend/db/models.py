"""
ORM Models
==========
Defines the two core tables:

  scans    — one row per scan job (GitHub URL or ZIP upload)
  findings — one row per deduplicated finding group from a scan

Design notes
------------
- PostgreSQL JSONB is used for semi-structured fields (summary, timeline,
  logs, ai_analysis, representative_finding, related_findings, snippet,
  framework, metadata) so they can be queried/indexed later without an
  additional schema migration.
- findings.scan_id has a FK back to scans.id with ON DELETE CASCADE so
  that deleting a scan automatically removes all its findings.
- Indexes are placed on the columns used by the existing API filter params
  (scan_id, severity, status, created_at) to keep queries fast once the
  JSON file storage is replaced.
- All datetime columns are stored as UTC; the application layer is
  responsible for tz-aware handling.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class Scan(Base):
    """
    Represents a single scan job.

    Columns
    -------
    id           UUID string — matches the scan_id used in scan_state.json
    status       pending | running | completed | failed
    scan_type    github | zip
    project_name human-readable repo/file name
    source_url   GitHub URL (null for ZIP uploads)
    summary      JSONB — { critical:N, high:N, medium:N, low:N, info:N }
    timeline     JSONB — list of pipeline step objects
    logs         JSONB — list of log-message strings
    created_at   UTC timestamp, set by DB default
    completed_at UTC timestamp, null until the scan finishes
    """

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    scan_type: Mapped[str] = mapped_column(String(16), nullable=False)  # github | zip
    project_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Semi-structured fields stored as JSONB for flexibility
    summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    timeline: Mapped[Optional[List[Any]]] = mapped_column(JSONB, nullable=True)
    logs: Mapped[Optional[List[str]]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False), nullable=True
    )

    # Relationship — cascade delete removes findings when scan is deleted
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    # Indexes
    __table_args__ = (
        Index("ix_scans_status", "status"),
        Index("ix_scans_scan_type", "scan_type"),
        Index("ix_scans_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id!r} status={self.status!r} project={self.project_name!r}>"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(Base):
    """
    Represents a single deduplicated finding group from a scan.

    The representative_finding column mirrors the nested structure that
    FindingsRepository currently stores in JSON:

        {
          "finding":    { rule_id, severity, path, line, message, cwe, owasp },
          "risk":       { risk_score, severity, exploitability, priority },
          "ai_analysis": { ... },
          "snippet":    { ... },
          "framework":  { ... },
          "metadata":   { ... },
        }

    Scalar fields (severity, status, path, line, risk_score, etc.) are
    promoted to top-level columns so that filtering and sorting are cheap
    SQL operations rather than JSONB path queries.
    """

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ── Triage ──────────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="open"
    )  # open | in_progress | resolved | false_positive

    # ── Core finding fields (promoted scalars) ────────────────────────────
    rule_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True
    )  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanner: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # ── Taxonomy ─────────────────────────────────────────────────────────
    cwe: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    owasp: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mitre: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # ── Risk ─────────────────────────────────────────────────────────────
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    exploitability: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    priority: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)  # P1‥P4
    confidence: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # ── Deduplication ─────────────────────────────────────────────────────
    total_occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # ── Full nested payload (JSONB) ───────────────────────────────────────
    representative_finding: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB, nullable=True
    )
    related_findings: Mapped[Optional[List[Any]]] = mapped_column(
        JSONB, nullable=True, default=list
    )
    ai_analysis: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB, nullable=True
    )
    snippet: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    framework: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    extra_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB, nullable=True, name="metadata"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False,
    )

    # Back-reference to Scan
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    # Indexes for the common API filter params
    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_created_at", "created_at"),
        Index("ix_findings_rule_id", "rule_id"),
        Index("ix_findings_priority", "priority"),
    )

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id!r} rule={self.rule_id!r} "
            f"sev={self.severity!r} scan={self.scan_id!r}>"
        )
