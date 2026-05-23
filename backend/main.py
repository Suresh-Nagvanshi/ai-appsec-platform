"""
AI AppSec Platform — FastAPI entry point
========================================
Changes from original:
  1. CORS: allow_origins set to env-configurable list; allow_credentials
     removed from wildcard-origin config (browsers reject that combination).
  2. All routers use backend.* import paths (consistent module resolution).
  3. Old /scan/github and /scan/file endpoints removed — replaced by
     /api/scans/github and /api/scans/zip in backend/api/scans.py.
  4. Old /findings route still exists via backend/routes/findings.py
     (now reads from FindingsRepository, no mock data).
  5. New /api/scans router mounted.
  6. New /api/repositories router mounted.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes.findings import router as findings_router
from backend.routes.reports import router as reports_router
from backend.api.scans import router as scans_router
from backend.api.repositories import router as repositories_router

# ── Environment ───────────────────────────────────────────────────────────────
load_dotenv()

# CORS origins: comma-separated list in CORS_ORIGINS env var
# Default: only localhost dev server
_raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI AppSec Platform",
    version="0.1.0",
    description="AI-powered application security platform combining Semgrep with contextual AI analysis.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(findings_router,     prefix="/findings",        tags=["Findings"])
app.include_router(reports_router,      prefix="/report",          tags=["Reports"])
app.include_router(scans_router,        prefix="/api/scans",       tags=["Scans"])
app.include_router(repositories_router, prefix="/api/repositories",tags=["Repositories"])


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "ai-appsec-platform"}
