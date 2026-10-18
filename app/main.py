"""
NetGuard API — entrypoint for the SOC dashboard and ML/forensic modules.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Project root (parent of /app) on sys.path for `database`, `capture`, `visibility` imports
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.routers import capture_api, dashboard_api, demo_api, detection_api, forensics_api, health, scan_api, visibility_api
from app.bootstrap import try_auto_demo
from config import ALLOWED_ORIGINS, API_TOKEN, warn_if_unauthenticated
from database.session import init_db
from visibility.service import get_visibility_service


class BearerTokenMiddleware(BaseHTTPMiddleware):
    """
    Optional API protection via NETGUARD_API_TOKEN.
    When unset, all routes remain open (local development).
    When set, require Authorization: Bearer <token> for /api/* except /api/health.
    """

    async def dispatch(self, request: Request, call_next):
        token = API_TOKEN
        if not token:
            return await call_next(request)

        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        if path == "/api/health" or path == "/health":
            return await call_next(request)
        if not path.startswith("/api"):
            return await call_next(request)

        auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
        expected = f"Bearer {token}"
        if auth.strip() != expected:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        return await call_next(request)


@asynccontextmanager
async def lifespan(_: FastAPI):
    warn_if_unauthenticated()
    init_db()
    get_visibility_service().try_reload_from_db()
    try_auto_demo()
    yield


app = FastAPI(title="NetGuard API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(BearerTokenMiddleware)

app.include_router(health.router, prefix="/api")
app.include_router(visibility_api.router, prefix="/api")
app.include_router(capture_api.router, prefix="/api")
app.include_router(scan_api.router, prefix="/api")
app.include_router(detection_api.router, prefix="/api")
app.include_router(forensics_api.router, prefix="/api")
app.include_router(dashboard_api.router, prefix="/api")
app.include_router(demo_api.router, prefix="/api")
