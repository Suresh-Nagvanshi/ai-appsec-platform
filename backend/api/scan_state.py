"""
Shared in-memory scan state.
=============================
Extracted from api/scans.py to break the circular import between
api/scans.py ↔ services/scan_orchestrator.py.

For a multi-worker deployment, replace with Redis or a database.
"""

_scans: dict = {}
