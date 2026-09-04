"""
Alembic environment script
==========================
This file is executed by Alembic when running any migration command.

Key behaviours
--------------
1. Loads DATABASE_URL from the project .env file via python-dotenv so
   developers don't need to hard-code credentials in alembic.ini.
2. Imports Base.metadata from backend.db.base so that --autogenerate
   detects all model changes automatically.
3. Supports both offline (SQL script) and online (direct DB) migration modes.
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so that `backend` is importable
# when Alembic is invoked from any working directory.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load .env so DATABASE_URL is available
load_dotenv(PROJECT_ROOT / ".env")

# Import models to populate Base.metadata (must come after sys.path fix)
from backend.db.base import Base  # noqa: E402
import backend.db.models  # noqa: F401, E402 — registers all models with Base

# ---------------------------------------------------------------------------
# Alembic Config object — gives access to alembic.ini values
# ---------------------------------------------------------------------------
config = context.config

# Override sqlalchemy.url with DATABASE_URL from environment
_db_url = os.getenv("DATABASE_URL")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

# Configure Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata object for --autogenerate support
target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Offline migration mode  (alembic upgrade head --sql)
# Emits SQL to stdout without connecting to the DB.
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migration mode  (alembic upgrade head)
# Connects to the DB and applies migrations directly.
# ---------------------------------------------------------------------------
def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,     # detect column type changes
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
