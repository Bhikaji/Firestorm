"""Structured JSON logging with log-injection protection.

User-controlled values are sanitised before they reach a log line so CRLF or
ANSI escape sequences cannot forge entries or corrupt terminals.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\x1b]")
_MAX_VALUE_LEN = 512

# Keys whose values must never be written to logs.
_REDACT_KEYS = {
    "password",
    "current_password",
    "new_password",
    "secret",
    "secret_key",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "mfa_secret",
    "cookie",
}


def sanitize(value: Any, key: str | None = None) -> Any:
    if key and key.lower() in _REDACT_KEYS:
        return "[redacted]"
    if isinstance(value, str):
        cleaned = _CONTROL_CHARS.sub(" ", value)
        return cleaned[:_MAX_VALUE_LEN]
    if isinstance(value, dict):
        return {k: sanitize(v, k) for k, v in list(value.items())[:50]}
    if isinstance(value, list | tuple):
        return [sanitize(v) for v in value[:50]]
    return value


_CONTEXT_KEYS = ("request_id", "user_id", "path", "method", "status_code", "duration_ms", "client_ip")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize(record.getMessage()),
        }
        for key in _CONTEXT_KEYS:
            if hasattr(record, key):
                payload[key] = sanitize(getattr(record, key))
        if record.exc_info:
            payload["exception"] = sanitize(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=True)


class PlainFormatter(logging.Formatter):
    """Human-readable logs that keep the same context the JSON logs carry.

    Without the context suffix, ``INFO firestorm.app request`` tells an operator
    nothing about which request failed - so plain mode appends the fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        record.msg = sanitize(record.getMessage())
        record.args = ()  # already interpolated; prevents double-formatting errors
        line = super().format(record)
        parts = [
            f"{key}={sanitize(getattr(record, key))}"
            for key in _CONTEXT_KEYS
            if getattr(record, key, None) is not None
        ]
        return f"{line} {' '.join(parts)}" if parts else line


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if settings.log_json else PlainFormatter("%(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())
    for noisy in ("uvicorn.access", "sqlalchemy.engine.Engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(settings.log_level.upper())
