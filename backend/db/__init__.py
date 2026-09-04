"""
backend.db
==========
Database package — exposes the ORM models, session factory, and Base
metadata so that the rest of the application only needs to import from
this package.
"""

from backend.db.base import Base
from backend.db.models import Finding, Scan
from backend.db.session import SessionLocal, engine

__all__ = ["Base", "Scan", "Finding", "SessionLocal", "engine"]
