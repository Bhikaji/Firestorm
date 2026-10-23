"""FIRESTORM API application factory."""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import (
    alerts,
    assets,
    auth,
    dashboard,
    incidents,
    integrations,
    policies,
    reports,
    system,
    telemetry,
    users,
)
from app.api.deps import general_limiter
from app.core.config import settings
from app.core.database import init_db
from app.core.errors import error_body, install_error_handlers
from app.core.logging import configure_logging
from app.core.ratelimit import client_key

logger = logging.getLogger("firestorm.app")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    if settings.is_production and not settings.secret_key:
        raise RuntimeError("FIRESTORM_SECRET_KEY is required in production")
    if settings.is_production and "*" in settings.allowed_host_list:
        logger.warning("allowed hosts is wildcard in production; restrict FIRESTORM_ALLOWED_HOSTS")
    if settings.enforcement_mode == "live":
        logger.warning(
            "LIVE enforcement mode is enabled; response actions may change real network state. "
            "Verify approval policy and the allowlist before proceeding."
        )
    init_db()
    # Default policies and admission rules must exist before the first request
    # so admission always evaluates against explicit policy (fail closed).
    from app.core.database import session_scope
    from app.services.seed import ensure_default_configuration

    try:
        with session_scope() as db:
            ensure_default_configuration(db)
    except Exception:  # noqa: BLE001 - never block startup on seeding
        logger.exception("default configuration could not be ensured")

    logger.info("firestorm started", extra={"path": "/startup"})
    yield
    logger.info("firestorm shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="FIRESTORM",
        version="0.1.0",
        description=(
            "Defensive security operations platform. Use only on networks and devices "
            "for which you have explicit authorisation."
        ),
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-API-Key"],
        max_age=600,
    )

    install_error_handlers(app)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        start = time.perf_counter()

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.request_body_limit_bytes:
                    return JSONResponse(
                        status_code=413,
                        content=error_body("payload_too_large", "request body too large"),
                    )
            except ValueError:
                return JSONResponse(status_code=400, content=error_body("bad_request", "invalid Content-Length"))

        # Health endpoints stay unauthenticated and unthrottled for probes.
        if request.url.path not in {"/api/v1/health", "/api/v1/ready", "/api/v1/metrics"}:
            try:
                general_limiter.check(client_key(request))
            except Exception as exc:  # RateLimited
                retry = getattr(exc, "details", {}).get("retry_after_seconds", 60)
                logger.warning(
                    "request throttled",
                    extra={
                        "request_id": request_id,
                        "path": request.url.path,
                        "method": request.method,
                        "client_ip": client_key(request),
                        "status_code": 429,
                    },
                )
                return JSONResponse(
                    status_code=429,
                    content=error_body("rate_limited", "too many requests; slow down", {"retry_after_seconds": retry}),
                    headers={"Retry-After": str(retry)},
                )

        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 1)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-ms"] = str(duration_ms)
        if settings.force_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith(settings.api_prefix):
            response.headers.setdefault("Cache-Control", "no-store")

        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "client_ip": client_key(request),
            },
        )
        return response

    api_prefix = settings.api_prefix
    app.include_router(system.router, prefix=api_prefix)
    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(dashboard.router, prefix=api_prefix)
    app.include_router(assets.router, prefix=api_prefix)
    app.include_router(telemetry.router, prefix=api_prefix)
    app.include_router(alerts.router, prefix=api_prefix)
    app.include_router(incidents.router, prefix=api_prefix)
    app.include_router(policies.router, prefix=api_prefix)
    app.include_router(reports.router, prefix=api_prefix)
    app.include_router(integrations.router, prefix=api_prefix)
    app.include_router(users.router, prefix=api_prefix)

    @app.get("/")
    def root() -> dict[str, Any]:
        return {
            "name": "FIRESTORM",
            "version": "0.1.0",
            "docs": "/api/docs",
            "api": api_prefix,
            "authorisation_notice": (
                "Operate only on networks and systems you are explicitly authorised to monitor."
            ),
        }

    return app


app = create_app()
