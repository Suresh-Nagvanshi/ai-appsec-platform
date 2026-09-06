import os
from pathlib import Path
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from backend.db.base import Base

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_DIR = BASE_DIR / "database"
DB_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_SQLITE_URL = f"sqlite:///{DB_DIR / 'appsec.db'}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)

engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
def init_db():
    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_scan_columns()


def _ensure_sqlite_scan_columns() -> None:
    """Backfill missing columns for older SQLite databases.

    create_all() creates missing tables, but it does not alter existing ones.
    Older local databases can therefore miss newer optional columns and crash
    during ORM loads. We only patch the minimal drift we know about here.
    """

    if not DATABASE_URL.startswith("sqlite"):
        return

    inspector = inspect(engine)
    if "scans" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("scans")}
    desired_columns = {
        "source_url": "TEXT",
        "timeline": "JSON",
        "logs": "JSON",
        "summary_json": "JSON",
        "progress": "INTEGER",
    }

    missing_columns = {
        name: ddl for name, ddl in desired_columns.items() if name not in existing_columns
    }
    if not missing_columns:
        return

    with engine.begin() as connection:
        for column_name, column_ddl in missing_columns.items():
            connection.execute(
                text(f"ALTER TABLE scans ADD COLUMN {column_name} {column_ddl}")
            )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
