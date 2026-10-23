"""Shared FastAPI dependencies: authentication, RBAC, rate limiting."""

from __future__ import annotations

import uuid

from fastapi import Depends, Header, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.errors import Forbidden, Unauthorized
from app.core.permissions import ROLE_PERMISSIONS, Permission, Role, has_permission
from app.core.ratelimit import SlidingWindowLimiter, client_key
from app.core.security import TokenError, decode_token
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.api_prefix}/auth/login", auto_error=False)

general_limiter = SlidingWindowLimiter(limit=settings.rate_limit_per_minute, window_seconds=60)
# Per-IP login budget: stops one host from spraying *many* accounts. Deliberately
# looser than the per-account limit because a whole office (or a lab preview)
# shares one address; only real spraying should trip it.
login_limiter = SlidingWindowLimiter(
    limit=max(settings.login_attempts_per_15min * 3, 30), window_seconds=900
)
# Per-(IP, account) budget: one person's typos must never lock out colleagues
# who share the same NAT address (very common in offices and in lab previews).
account_limiter = SlidingWindowLimiter(limit=settings.login_attempts_per_15min, window_seconds=900)
ingest_limiter = SlidingWindowLimiter(limit=6000, window_seconds=60)


def rate_limit(request: Request) -> None:
    general_limiter.check(client_key(request))


def login_rate_limit(request: Request) -> None:
    """Coarse pre-check before the body is parsed.

    The precise accounting happens in the login handler, where the email is
    known, but rejecting an obvious flood early avoids doing any work for it.
    """
    login_limiter.check(client_key(request))


def request_id(request: Request) -> str:
    existing = request.headers.get("x-request-id")
    if existing and len(existing) <= 64 and existing.isprintable():
        return existing
    return str(uuid.uuid4())


def client_ip(request: Request) -> str:
    return client_key(request)


def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:]
    if not token:
        raise Unauthorized("authentication required")
    try:
        payload = decode_token(token, expected_kind="access")
    except TokenError as exc:
        raise Unauthorized(str(exc)) from exc
    user = db.get(User, payload.get("sub"))
    if user is None or not user.is_active:
        raise Unauthorized("account is not active")
    if user.role != payload.get("role"):
        # Role changed after the token was issued: force re-authentication.
        raise Unauthorized("role changed; sign in again")
    request.state.user = user
    return user


def require(permission: Permission):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, permission):
            raise Forbidden(f"role '{user.role}' lacks permission '{permission}'")
        return user

    return dependency


def require_role(*roles: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise Forbidden(f"requires one of roles: {', '.join(roles)}")
        return user

    return dependency


def permissions_for_user(user: User) -> list[str]:
    return sorted(p.value for p in ROLE_PERMISSIONS.get(user.role, set()))


def verify_ingest_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """Sensors authenticate with a shared ingestion key, not a user session."""
    from app.core.security import constant_time_equals

    expected = settings.ingest_api_key
    if not expected:
        raise Unauthorized(
            "telemetry ingestion is disabled: set FIRESTORM_INGEST_API_KEY to enable the sensor endpoint"
        )
    if not x_api_key or not constant_time_equals(x_api_key, expected):
        raise Unauthorized("invalid ingestion key")


def ensure_can_execute(user: User) -> None:
    if not has_permission(user.role, Permission.ACTION_EXECUTE):
        raise Forbidden("role may not execute response actions")


def is_admin(user: User) -> bool:
    return user.role == Role.ADMIN


def get_optional_user(
    request: Request, db: Session = Depends(get_db)
) -> User | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    try:
        payload = decode_token(header[7:], expected_kind="access")
    except TokenError:
        return None
    return db.execute(select(User).where(User.id == payload.get("sub"))).scalars().first()
