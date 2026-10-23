"""Authentication: login, refresh rotation, logout, MFA and profile."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    account_limiter,
    client_ip,
    get_current_user,
    login_limiter,
    login_rate_limit,
    permissions_for_user,
    request_id,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.errors import Conflict, RateLimited, Unauthorized, ValidationFailed
from app.core.security import (
    ACCESS,
    REFRESH,
    create_token,
    decode_token,
    hash_password,
    new_totp_secret,
    password_problems,
    token_fingerprint,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.models.user import LoginAttempt, RefreshToken, User
from app.schemas.auth import (
    LoginRequest,
    MeOut,
    MfaDisable,
    MfaEnable,
    MfaSetupOut,
    PasswordChange,
    RefreshRequest,
    TokenPair,
    UserOut,
)
from app.schemas.common import Message
from app.services.audit_service import AuditService

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger("firestorm.auth")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
REFRESH_COOKIE = "firestorm_refresh"


def _now() -> datetime:
    return datetime.now(UTC)


def _issue_tokens(db: Session, user: User, request: Request) -> TokenPair:
    access, _, _ = create_token(user.id, ACCESS, role=user.role)
    refresh, jti, expires = create_token(user.id, REFRESH, role=user.role)
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=token_fingerprint(refresh),
            jti=jti,
            expires_at=expires,
            user_agent=(request.headers.get("user-agent") or "")[:255],
            client_ip=client_ip(request),
        )
    )
    db.flush()
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_minutes * 60,
        role=user.role,
        must_change_password=user.must_change_password,
    )


def _record_attempt(db: Session, email: str, success: bool, request: Request, reason: str | None = None) -> None:
    db.add(
        LoginAttempt(
            email=email[:320],
            success=success,
            reason=reason,
            ip_address=client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
    )
    db.flush()


@router.post("/login", response_model=TokenPair, dependencies=[Depends(login_rate_limit)])
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> TokenPair:
    audit = AuditService(db)
    email = payload.email.lower()
    ip = client_ip(request)
    account_key = f"{ip}|{email}"

    # Per-account budget. Every attempt consumes a slot; a successful sign-in is
    # refunded below, so only wrong passwords count. This keeps one colleague's
    # typos from locking out everyone else behind the same NAT address.
    try:
        account_limiter.check(account_key)
    except RateLimited:
        logger.warning("login throttled", extra={"ip": ip, "email": email})
        raise

    user = db.execute(select(User).where(User.email == email)).scalars().first()

    if user is None:
        _record_attempt(db, email, False, request, "unknown_account")
        audit.record(action="auth.login_failed", actor_email=email, outcome="failure",
                     detail={"reason": "unknown_account"}, client_ip=client_ip(request), request_id=request_id(request))
        db.commit()
        # Same message as a bad password to avoid account enumeration.
        raise Unauthorized("invalid credentials")

    if user.is_locked:
        _record_attempt(db, email, False, request, "locked")
        db.commit()
        raise Unauthorized("account temporarily locked after repeated failures")

    if not verify_password(payload.password, user.password_hash):
        user.failed_attempts += 1
        reason = "bad_password"
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = _now() + timedelta(minutes=LOCKOUT_MINUTES)
            reason = "locked_out"
        _record_attempt(db, email, False, request, reason)
        audit.record(action="auth.login_failed", actor_id=user.id, actor_email=email, actor_role=user.role,
                     outcome="failure", detail={"reason": reason, "attempts": user.failed_attempts},
                     client_ip=client_ip(request), request_id=request_id(request))
        db.commit()
        raise Unauthorized("invalid credentials")

    if not user.is_active:
        _record_attempt(db, email, False, request, "inactive")
        db.commit()
        raise Unauthorized("account disabled")

    if user.mfa_enabled:
        if not payload.mfa_code:
            db.commit()
            raise Unauthorized("multi-factor code required")
        if not user.mfa_secret or not verify_totp(user.mfa_secret, payload.mfa_code):
            _record_attempt(db, email, False, request, "bad_mfa")
            audit.record(action="auth.mfa_failed", actor_id=user.id, actor_email=email, actor_role=user.role,
                         outcome="failure", detail={}, client_ip=client_ip(request))
            db.commit()
            raise Unauthorized("invalid multi-factor code")

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = _now()
    # The credentials were correct: return the slots consumed by both limiters so
    # normal sign-ins never eat into the brute-force budget. Failures keep theirs.
    account_limiter.refund(account_key)
    login_limiter.refund(ip)
    tokens = _issue_tokens(db, user, request)
    _record_attempt(db, email, True, request, None)
    audit.record(action="auth.login", actor_id=user.id, actor_email=email, actor_role=user.role,
                 object_type="user", object_id=user.id, detail={"mfa": user.mfa_enabled},
                 client_ip=client_ip(request), request_id=request_id(request))
    db.commit()

    response.set_cookie(
        REFRESH_COOKIE,
        tokens.refresh_token,
        httponly=True,
        secure=settings.force_https,
        samesite="strict",
        max_age=settings.refresh_token_days * 86400,
        path=f"{settings.api_prefix}/auth",
    )
    return tokens


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    try:
        claims = decode_token(payload.refresh_token, expected_kind="refresh")
    except Exception as exc:  # noqa: BLE001
        raise Unauthorized("invalid refresh token") from exc

    record = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_fingerprint(payload.refresh_token))
    ).scalars().first()
    if record is None:
        raise Unauthorized("refresh token is not recognised")

    if record.revoked_at is not None:
        # Reuse of a rotated token: revoke the whole family and force login.
        for token in db.execute(select(RefreshToken).where(RefreshToken.user_id == record.user_id)).scalars():
            token.revoked_at = token.revoked_at or _now()
               
        db.commit()
        logger.warning("refresh token reuse detected for user %s", record.user_id)
        raise Unauthorized("refresh token reuse detected; all sessions revoked")

    if not record.is_active:
        raise Unauthorized("refresh token expired")

    user = db.get(User, claims.get("sub"))
    if user is None or not user.is_active:
        raise Unauthorized("account is not active")

    record.revoked_at = _now()
    tokens = _issue_tokens(db, user, request)
    record.replaced_by = token_fingerprint(tokens.refresh_token)
    AuditService(db).record(
        action="auth.refresh", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        detail={"rotated": True}, client_ip=client_ip(request),
    )
    db.commit()
    return tokens


@router.post("/logout", response_model=Message)
def logout(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Message:
    tokens = (
        db.execute(
            select(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        )
        .scalars()
        .all()
    )
    for token in tokens:
        token.revoked_at = _now()
    AuditService(db).record(
        action="auth.logout",
        actor_id=user.id,
        actor_email=user.email,
        actor_role=user.role,
        client_ip=client_ip(request),
    )
    db.commit()
    return Message(message="signed out")


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(get_current_user)) -> MeOut:
    return MeOut(user=UserOut.model_validate(user), permissions=permissions_for_user(user))


@router.post("/password", response_model=Message)
def change_password(
    payload: PasswordChange,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Message:
    if not verify_password(payload.current_password, user.password_hash):
        raise Unauthorized("current password is incorrect")
    problems = password_problems(payload.new_password)
    if problems:
        raise ValidationFailed("password does not meet policy", details={"problems": problems})
    if verify_password(payload.new_password, user.password_hash):
        raise ValidationFailed("new password must differ from the current password")

    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = _now()
    user.must_change_password = False
    for token in db.execute(select(RefreshToken).where(RefreshToken.user_id == user.id)).scalars():
        token.revoked_at = token.revoked_at or _now()
    AuditService(db).record(
        action="auth.password_changed", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="user", object_id=user.id, client_ip=client_ip(request),
    )
    db.commit()
    return Message(message="password updated; all sessions revoked")


@router.post("/mfa/setup", response_model=MfaSetupOut)
def setup_mfa(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> MfaSetupOut:
    if user.mfa_enabled:
        raise Conflict("multi-factor authentication is already enabled")
    secret = new_totp_secret()
    user.mfa_secret = secret
    db.commit()
    return MfaSetupOut(secret=secret, provisioning_uri=totp_uri(secret, user.email))


@router.post("/mfa/enable", response_model=Message)
def enable_mfa(
    payload: MfaEnable,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Message:
    if user.mfa_enabled:
        raise Conflict("multi-factor authentication is already enabled")
    if not user.mfa_secret:
        raise Conflict("run /auth/mfa/setup first")
    if not verify_totp(user.mfa_secret, payload.code):
        raise Unauthorized("invalid one-time code")
    user.mfa_enabled = True
    AuditService(db).record(
        action="auth.mfa_enabled", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="user", object_id=user.id,
    )
    db.commit()
    return Message(message="multi-factor authentication enabled")


@router.post("/mfa/disable", response_model=Message)
def disable_mfa(
    payload: MfaDisable,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Message:
    if not verify_password(payload.password, user.password_hash):
        raise Unauthorized("password is incorrect")
    user.mfa_enabled = False
    user.mfa_secret = None
    AuditService(db).record(
        action="auth.mfa_disabled", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="user", object_id=user.id,
    )
    db.commit()
    return Message(message="multi-factor authentication disabled")
