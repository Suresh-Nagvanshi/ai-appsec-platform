"""Initial schema: scans + findings tables

Revision ID: 0001
Revises: 
Create Date: 2026-08-11

Creates:
  - scans    table with JSONB summary / timeline / logs columns
  - findings table with JSONB representative_finding / ai_analysis / snippet /
              framework / metadata columns and FK to scans
  - All indexes defined in the ORM models
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── scans ────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("scan_type", sa.String(16), nullable=False),
        sa.Column("project_name", sa.String(255), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("timeline", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("logs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=False), nullable=True),
    )
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_scan_type", "scans", ["scan_type"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])

    # ── findings ─────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        # Core finding scalars
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("scanner", sa.String(64), nullable=True),
        # Taxonomy
        sa.Column("cwe", sa.String(64), nullable=True),
        sa.Column("owasp", sa.String(64), nullable=True),
        sa.Column("mitre", sa.String(128), nullable=True),
        # Risk
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("exploitability", sa.String(32), nullable=True),
        sa.Column("priority", sa.String(8), nullable=True),
        sa.Column("confidence", sa.String(32), nullable=True),
        # Deduplication
        sa.Column("total_occurrences", sa.Integer(), nullable=False, server_default="1"),
        # Full nested JSONB payloads
        sa.Column(
            "representative_finding",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "related_findings",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "ai_analysis",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("snippet", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("framework", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=False),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_created_at", "findings", ["created_at"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_priority", "findings", ["priority"])


def downgrade() -> None:
    # Drop findings first (FK dependency)
    op.drop_index("ix_findings_priority", table_name="findings")
    op.drop_index("ix_findings_rule_id", table_name="findings")
    op.drop_index("ix_findings_created_at", table_name="findings")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_index("ix_scans_scan_type", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_table("scans")
