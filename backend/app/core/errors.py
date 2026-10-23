"""Structured error types and handlers.

Every API error is returned as ``{"error": {"code", "message", "details"}}`` so
clients can branch on a stable code instead of parsing prose.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("firestorm.errors")


class AppError(Exception):
    status_code = status.HTTP_400_BAD_REQUEST
    code = "app_error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        if status_code:
            self.status_code = status_code


class NotFound(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class Conflict(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class Unauthorized(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "unauthorized"


class Forbidden(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "forbidden"


class RateLimited(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"


class ValidationFailed(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = "validation_failed"


class IntegrationUnavailable(AppError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "integration_unavailable"


def error_body(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return body


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            413: "payload_too_large",
            429: "rate_limited",
        }.get(exc.status_code, "http_error")
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        return JSONResponse(status_code=exc.status_code, content=error_body(code, detail))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo raw input back: it can carry secrets or log-injection payloads.
        fields = [
            {
                "field": ".".join(str(p) for p in err.get("loc", []) if p != "body"),
                "reason": err.get("msg", "invalid value"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_body("validation_failed", "request validation failed", {"fields": fields}),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error", exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_body("internal_error", "an unexpected error occurred"),
        )


__all__ = [
    "AppError",
    "NotFound",
    "Conflict",
    "Unauthorized",
    "Forbidden",
    "RateLimited",
    "ValidationFailed",
    "IntegrationUnavailable",
    "error_body",
    "install_error_handlers",
    "HTTPException",
]
