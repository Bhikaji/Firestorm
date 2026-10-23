"""Integration status and connectivity tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, require
from app.core.database import get_db
from app.core.errors import NotFound
from app.core.permissions import Permission
from app.integrations.registry import registry
from app.models.policy import IntegrationConfig
from app.models.user import User
from app.schemas.policy import IntegrationHealth, IntegrationOut, IntegrationUpdate
from app.services.audit_service import AuditService
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("", response_model=list[IntegrationHealth])
def list_integrations(
    user: User = Depends(require(Permission.INTEGRATION_READ)),
) -> list[dict[str, Any]]:
    return registry().health()


@router.post("/test", response_model=list[IntegrationHealth])
def test_integrations(
    request: Request,
    user: User = Depends(require(Permission.INTEGRATION_TEST)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    health = registry().health()
    audit = AuditService(db)
    for item in health:
        row = db.execute(select(IntegrationConfig).where(IntegrationConfig.name == item["name"])).scalars().first()
        if row is None:
            row = IntegrationConfig(name=item["name"], kind=item["kind"])
            db.add(row)
        row.mode = item["mode"]
        row.last_status = item["status"]
        row.last_message = item["detail"]
        row.last_checked_at = datetime.now(UTC)
        row.enabled = item["enabled"]
    audit.record(
        action="integration.tested", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="integration", detail={"count": len(health)}, client_ip=client_ip(request),
    )
    db.commit()
    return health


@router.get("/notifications")
def notification_status(
    user: User = Depends(require(Permission.INTEGRATION_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return NotificationService(db).provider_status()


@router.get("/records")
def integration_records(
    user: User = Depends(require(Permission.INTEGRATION_READ)),
    db: Session = Depends(get_db),
) -> list[IntegrationOut]:
    rows = db.execute(select(IntegrationConfig).order_by(IntegrationConfig.name)).scalars().all()
    return [IntegrationOut.model_validate(r) for r in rows]


@router.patch("/records/{record_id}", response_model=IntegrationOut)
def update_integration_record(
    record_id: str,
    payload: IntegrationUpdate,
    request: Request,
    user: User = Depends(require(Permission.USER_ADMIN)),
    db: Session = Depends(get_db),
) -> IntegrationConfig:
    row = db.get(IntegrationConfig, record_id)
    if not row:
        raise NotFound("integration record not found")
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.endpoint is not None:
        row.endpoint = payload.endpoint
    if payload.settings is not None:
        # Secrets are never accepted here; they belong in the environment.
        row.settings = {k: v for k, v in payload.settings.items() if "token" not in k.lower() and "secret" not in k.lower()}
    AuditService(db).record(
        action="integration.updated", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="integration", object_id=row.id, detail={"name": row.name},
        client_ip=client_ip(request),
    )
    db.commit()
    return row
