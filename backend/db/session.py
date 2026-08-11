"""
Database Session Factory
========================
Creates a SQLAlchemy engine and a session factory from DATABASE_URL.

Usage
-----
In a FastAPI route / dependency:

    from backend.db.session import SessionLocal

    def get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    @router.get("/example")
    def example(db: Session = Depends(get_db)):
        ...

Environment variables
---------------------
DATABASE_URL — PostgreSQL connection string in SQLAlchemy format.
               Example:
                 postgresql+psycopg://user:password@localhost:5432/appsec
               If DATABASE_URL is not set, the engine is created with a
               placeholder URL that will raise an error on first connection
               attempt — this allows the backend to start in JSON-only mode
               without crashing.
"""

import logging
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

load_dotenv()

logger = logging.getLogger(__name__)

DATABASE_URL: str | None = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    logger.warning(
        "DATABASE_URL is not set — PostgreSQL features are disabled. "
        "Set DATABASE_URL in .env to enable the database layer."
    )
    # Use a placeholder URL so SQLAlchemy doesn't crash at import time.
    # Any actual DB call will raise OperationalError, which is caught
    # by the repository layer.
    DATABASE_URL = "postgresql+psycopg://placeholder:placeholder@localhost/placeholder"

engine = create_engine(
    DATABASE_URL,
    # Keep a small pool — this is a dev server, not a production cluster.
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,   # Detect stale connections before handing them out.
    echo=False,           # Set to True to log all SQL — helpful when debugging.
)

SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,  # Avoid lazy-load errors after commit.
)


def get_db():
    """
    FastAPI dependency that yields a database session and guarantees
    the session is closed when the request finishes.

    Usage:
        from fastapi import Depends
        from sqlalchemy.orm import Session
        from backend.db.session import get_db

        @router.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_connection() -> bool:
    """
    Ping the database.  Returns True if reachable, False otherwise.
    Useful for a /health endpoint or startup check.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("Database connection check failed: %s", exc)
        return False
