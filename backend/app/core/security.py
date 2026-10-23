"""Password hashing, JWT issuing/verification, MFA helpers and token hashing.

Only established libraries are used: ``bcrypt`` for password hashing,
``PyJWT`` for signed tokens and ``pyotp`` for TOTP. No cryptographic
primitive is implemented from scratch.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import bcrypt
import jwt
import pyotp

from app.core.config import settings

TokenKind = Literal["access", "refresh"]

ACCESS = "access"
REFRESH = "refresh"

# bcrypt silently truncates at 72 bytes; reject longer inputs instead.
MAX_PASSWORD_BYTES = 72
BCRYPT_ROUNDS = 12


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired or of the wrong kind."""


def utcnow() -> datetime:
    return datetime.now(UTC)


def hash_password(password: str) -> str:
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        raw = password.encode("utf-8")
        if len(raw) > MAX_PASSWORD_BYTES:
            return False
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def password_problems(password: str) -> list[str]:
    """Return human-readable policy violations (empty when compliant)."""
    problems: list[str] = []
    if len(password) < 12:
        problems.append("must be at least 12 characters")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        problems.append(f"must be at most {MAX_PASSWORD_BYTES} bytes")
    if not any(c.islower() for c in password):
        problems.append("must contain a lowercase letter")
    if not any(c.isupper() for c in password):
        problems.append("must contain an uppercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("must contain a digit")
    if not any(not c.isalnum() for c in password):
        problems.append("must contain a symbol")
    if password.lower() in {"password", "firestorm", "admin"}:
        problems.append("must not be a common dictionary word")
    return problems


def create_token(
    subject: str,
    kind: TokenKind,
    *,
    role: str,
    extra: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> tuple[str, str, datetime]:
    """Return ``(compact_jwt, jti, expires_at)``."""
    now = utcnow()
    if expires_delta is None:
        expires_delta = (
            timedelta(minutes=settings.access_token_minutes)
            if kind == ACCESS
            else timedelta(days=settings.refresh_token_days)
        )
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "type": kind,
        "jti": jti,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "iss": "firestorm",
    }
    if extra:
        payload.update(extra)
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, jti, now + expires_delta


def decode_token(token: str, *, expected_kind: TokenKind | None = None) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer="firestorm",
            options={"require": ["exp", "iat", "sub", "type", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("invalid token") from exc
    if expected_kind and payload.get("type") != expected_kind:
        raise TokenError(f"expected a {expected_kind} token")
    return payload


def token_fingerprint(token: str) -> str:
    """Stable, non-reversible handle for storing refresh tokens."""
    return hashlib.sha256(f"{settings.secret_key}:{token}".encode()).hexdigest()


def new_api_key(prefix: str = "fs") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=settings.mfa_issuer)


def verify_totp(secret: str, code: str) -> bool:
    if not code or not code.isdigit():
        return False
    # valid_window=1 tolerates one 30s clock step of drift.
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def constant_time_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode(), right.encode())
