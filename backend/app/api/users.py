"""User administration (admin only) and in-app notifications."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.permissions import Permission
from app.core.security import hash_password, password_problems
from app.models.policy import Notification
from app.models.user import LoginAttempt, User
from app.schemas.auth import UserCreate, UserOut, UserUpdate
from app.schemas.common import Message, Page
from app.schemas.policy import NotificationOut
from app.services.audit_service import AuditService

router = APIRouter(tags=["users"])


@router.get("/users", response_model=Page[UserOut])
def list_users(
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require(Permission.USER_ADMIN)),
    db: Session = Depends(get_db),
) -> Page[UserOut]:
    total = int(db.execute(select(func.count(User.id))).scalar_one())
    rows = (
        db.execute(select(User).order_by(User.email).offset((page - 1) * page_size).limit(page_size))
        .scalars()
        .all()
    )
    return Page[UserOut](items=[UserOut.model_validate(u) for u in rows], total=total, page=page, page_size=page_size)


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    request: Request,
    user: User = Depends(require(Permission.USER_ADMIN)),
    db: Session = Depends(get_db),
) -> User:
    email = payload.email.lower()
    if db.execute(select(User).where(User.email == email)).scalars().first():
        raise Conflict("a user with that email already exists")
    problems = password_problems(payload.password)
    if problems:
        raise ValidationFailed("password does not meet policy", details={"problems": problems})
    new_user = User(
        email=email,
        full_name=payload.full_name,
        role=payload.role,
        password_hash=hash_password(payload.password),
        must_change_password=True,
    )
    db.add(new_user)
    db.flush()
    AuditService(db).record(
        action="user.created", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="user", object_id=new_user.id, detail={"email": email, "role": payload.role},
        client_ip=client_ip(request),
    )
    db.commit()
    return new_user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    user: User = Depends(require(Permission.USER_ADMIN)),
    db: Session = Depends(get_db),
) -> User:
    target = db.get(User, user_id)
    if not target:
        raise NotFound("user not found")
    if target.id == user.id and payload.is_active is False:
        raise Conflict("you cannot deactivate your own account")
    if target.role == "admin" and payload.role and payload.role != "admin":
        remaining = db.execute(
            select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True), User.id != target.id)
        ).scalar_one()
        if int(remaining) == 0:
            raise Conflict("cannot demote the last active administrator")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(target, key, value)
    AuditService(db).record(
        action="user.updated", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="user", object_id=target.id, detail={"fields": sorted(changes)},
        client_ip=client_ip(request),
    )
    db.commit()
    return target


@router.post("/users/{user_id}/reset-password", response_model=Message)
def admin_reset_password(
    user_id: str,
    payload: dict,
    request: Request,
    user: User = Depends(require(Permission.USER_ADMIN)),
    db: Session = Depends(get_db),
) -> Message:
    target = db.get(User, user_id)
    if not target:
        raise NotFound("user not found")
    new_password = str(payload.get("password", ""))
    problems = password_problems(new_password)
    if problems:
        raise ValidationFailed("password does not meet policy", details={"problems": problems})
    target.password_hash = hash_password(new_password)
    target.must_change_password = True
    target.failed_attempts = 0
    target.locked_until = None
    AuditService(db).record(
        action="user.password_reset", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="user", object_id=target.id, detail={}, client_ip=client_ip(request),
    )
    db.commit()
    return Message(message="password reset; the user must change it at next sign-in")


@router.get("/users/{user_id}/login-attempts")
def login_attempts(
    user_id: str,
    limit: int = Query(default=25, ge=1, le=200),
    user: User = Depends(require(Permission.USER_ADMIN)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    target = db.get(User, user_id)
    if not target:
        raise NotFound("user not found")
    rows = (
        db.execute(
            select(LoginAttempt)
            .where(LoginAttempt.email == target.email)
            .order_by(LoginAttempt.created_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "success": r.success,
            "reason": r.reason,
            "ip_address": r.ip_address,
            "user_agent": r.user_agent,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@router.get("/notifications", response_model=Page[NotificationOut])
def list_notifications(
    channel: str | None = Query(default=None, pattern="^(in_app|email|webhook)$"),
    status: str | None = None,
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require(Permission.ALERT_READ)),
    db: Session = Depends(get_db),
) -> Page[NotificationOut]:
    stmt = select(Notification)
    if channel:
        stmt = stmt.where(Notification.channel == channel)
    if status:
        stmt = stmt.where(Notification.status == status)
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = (
        db.execute(
            stmt.order_by(Notification.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        )
        .scalars()
        .all()
    )
    return Page[NotificationOut](
        items=[NotificationOut.model_validate(n) for n in rows], total=total, page=page, page_size=page_size
    )


@router.post("/notifications/{notification_id}/acknowledge", response_model=NotificationOut)
def acknowledge_notification(
    notification_id: str,
    request: Request,
    user: User = Depends(require(Permission.ALERT_TRIAGE)),
    db: Session = Depends(get_db),
) -> Notification:
    from app.services.notification_service import NotificationService

    note = NotificationService(db).acknowledge(notification_id, user.id)
    if not note:
        raise NotFound("notification not found")
    AuditService(db).record(
        action="notification.acknowledged", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="notification", object_id=note.id, detail={}, client_ip=client_ip(request),
    )
    db.commit()
    return note


@router.post("/notifications/dispatch", response_model=Message)
def dispatch_notifications(
    user: User = Depends(require(Permission.USER_ADMIN)),
    db: Session = Depends(get_db),
) -> Message:
    """Attempt delivery of queued email notifications (worker-safe, idempotent)."""
    from app.services.notification_service import NotificationService

    result = NotificationService(db).deliver_pending()
    db.commit()
    return Message(
        message="dispatch attempted",
        detail=f"attempted {result.get('attempted', 0)}, delivered {result.get('delivered', 0)}, failed {result.get('failed', 0)}",
    )
