"""
Website scan state — mirrors the pattern used by scan_state.py for GitHub scans.
Persists in-memory state to JSON so scans survive process restarts.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_STATE_FILE = Path(__file__).resolve().parent.parent.parent / "database" / "website_scan_state.json"
_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

_website_scans: dict = {}


def _load_state() -> None:
    """Load persisted scan state from disk on startup."""
    if _STATE_FILE.exists():
        try:
            data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
            _website_scans.update(data)
            logger.info("Loaded %d website scan(s) from state file.", len(data))
        except Exception as exc:
            logger.warning("Could not load website scan state: %s", exc)


def save_ws_state() -> None:
    """Persist current website scan state to disk."""
    try:
        _STATE_FILE.write_text(
            json.dumps(_website_scans, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("Could not save website scan state: %s", exc)


_load_state()
