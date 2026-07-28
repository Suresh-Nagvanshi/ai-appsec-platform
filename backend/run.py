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

import os
import sys
from pathlib import Path
import uvicorn

if __name__ == "__main__":
    # Ensure the project root is in PYTHONPATH so that uvicorn worker processes
    # spawned during hot-reloads can successfully find the 'backend' package.
    project_root = str(Path(__file__).resolve().parent.parent)
    existing_pythonpath = os.environ.get("PYTHONPATH", "")
    sep = os.pathsep  # ':' on Unix, ';' on Windows — OS-aware
    os.environ["PYTHONPATH"] = f"{project_root}{sep}{existing_pythonpath}" if existing_pythonpath else project_root
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["backend"],
        reload_excludes=["repos", "extracted", "uploads", "results", "database", "data"],
    )

