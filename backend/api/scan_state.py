"""
Shared scan state with disk persistence.
==========================================
Extracted from api/scans.py to break the circular import between
api/scans.py ↔ services/scan_orchestrator.py.

State is held in-memory for fast access but flushed to disk after
every mutation so that uvicorn --reload restarts don't lose it.
For a multi-worker deployment, replace with Redis or a database.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Persistence file ──────────────────────────────────────────────────────────
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_DATA_DIR = _BASE_DIR / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = _DATA_DIR / "scan_state.json"

# ── Load from disk on import (i.e. server start) ─────────────────────────────
_scans: dict = {}

if STATE_FILE.exists():
    try:
        _scans = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        logger.info("Loaded %d scan(s) from %s", len(_scans), STATE_FILE)
    except Exception as exc:
        logger.warning("Could not load scan state from %s: %s", STATE_FILE, exc)
        _scans = {}


def save_state() -> None:
    """Flush the current _scans dict to disk as JSON."""
    try:
        STATE_FILE.write_text(
            json.dumps(_scans, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("Could not persist scan state: %s", exc)
