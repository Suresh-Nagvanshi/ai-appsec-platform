"""
DeclarativeBase
===============
Single source of truth for SQLAlchemy's ORM metadata.
All models import Base from here so that Alembic env.py can reach
target_metadata = Base.metadata.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Project-wide declarative base."""
    pass
