"""
API Key Authentication
======================
FastAPI dependency that enforces a static API key on all protected
routes.  The key is read from the API_KEY environment variable.

Usage
-----
In a router file:

    from fastapi import APIRouter, Depends
    from backend.auth.api_key import require_api_key

    router = APIRouter(dependencies=[Depends(require_api_key)])

Or on a single endpoint:

    @router.get("/secret", dependencies=[Depends(require_api_key)])
    def secret(): ...

Environment variables
---------------------
API_KEY          — the secret key clients must send in X-API-Key header.
                   If not set, auth is DISABLED (dev convenience only;
                   log a warning so it is never silently skipped in prod).
API_KEY_DISABLED — set to "true" to explicitly skip auth (test use only).

Header
------
X-API-Key: <key>

Response codes
--------------
401 — header missing entirely
403 — header present but value is wrong
"""

import logging
import os

from fastapi import Header, HTTPException, status

logger = logging.getLogger(__name__)

_API_KEY: str | None = os.getenv("API_KEY")
_DISABLED: bool = os.getenv("API_KEY_DISABLED", "").lower() == "true"

if not _API_KEY and not _DISABLED:
    logger.warning(
        "API_KEY env var is not set — all endpoints are UNPROTECTED. "
        "Set API_KEY in .env before deploying."
    )


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """
    FastAPI dependency.  Raises HTTPException if the request does not
    carry a valid API key.  Silently passes when auth is disabled.
    """
    # Auth explicitly disabled (test / local dev without .env)
    if _DISABLED:
        return

    # No API_KEY configured at all — warn once at startup (above), pass through
    if not _API_KEY:
        return

    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Constant-time comparison to prevent timing attacks
    import hmac
    if not hmac.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
