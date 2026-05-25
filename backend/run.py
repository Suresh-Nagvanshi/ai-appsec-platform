"""
Development server launcher.
==============================
Usage:
    python -m backend.run

Configures uvicorn with:
  - reload=True for development hot-reload
  - reload_excludes for directories written to during scans (repos/, extracted/,
    uploads/, results/, database/, data/) so that file writes during a scan
    don't trigger a server restart and kill the running scan mid-execution
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["backend"],
    )
