"""
AI AppSec Platform — FastAPI entry point
========================================
Security hardening applied in this revision:

  1. CORS: allow_credentials only set when an explicit CORS_ORIGINS list is
     configured via env var. The wildcard+credentials combination that browsers
     reject has been removed. Default dev origin: http://localhost:3000.

  2. API key middleware: all routers (scans, findings, reports, repositories, fix)
     are protected via the require_api_key FastAPI dependency.  The /health
     endpoint is intentionally exempted.
     Set API_KEY=<secret> in .env to enable.  If API_KEY is absent the
     dependency logs a warning and passes through (dev convenience).

  3. Router prefixes unchanged — no breaking URL changes.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.auth.api_key import require_api_key
from backend.routes.findings import router as findings_router
from backend.routes.reports import router as reports_router
from backend.api.scans import router as scans_router
from backend.api.repositories import router as repositories_router
from backend.api.fix import router as fix_router

# ── Environment ───────────────────────────────────────────────────────────────
load_dotenv()

_raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000")
ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]
_USE_CREDENTIALS = "*" not in ALLOWED_ORIGINS

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI AppSec Platform",
    version="0.2.0",
    description=(
        "AI-powered application security platform combining Semgrep static analysis "
        "with LangChain + RAG contextual vulnerability analysis (CWE / OWASP / MITRE ATT&CK)."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=_USE_CREDENTIALS,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

# ── Routers (all protected by API key) ───────────────────────────────────────
_auth = [Depends(require_api_key)]

app.include_router(
    findings_router,
    prefix="/findings",
    tags=["Findings"],
    dependencies=_auth,
)
app.include_router(
    reports_router,
    prefix="/report",
    tags=["Reports"],
    dependencies=_auth,
)
app.include_router(
    scans_router,
    prefix="/api/scans",
    tags=["Scans"],
    dependencies=_auth,
)
app.include_router(
    repositories_router,
    prefix="/api/repositories",
    tags=["Repositories"],
    dependencies=_auth,
)
app.include_router(
    fix_router,
    prefix="/api/fix",
    tags=["Fix Suggestions"],
    dependencies=_auth,
)


# ── Public endpoints ──────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
def health_check():
    """Liveness probe — intentionally exempted from API key auth."""
    return {"status": "ok", "service": "ai-appsec-platform", "version": "0.2.0"}
