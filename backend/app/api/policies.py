"""Policy management: device admission, risk thresholds, response approval."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, rate_limit, require
from app.core.database import get_db
from app.core.errors import NotFound
from app.core.permissions import Permission
from app.models.policy import AdmissionRule, AuditLog, Policy
from app.models.user import User
from app.schemas.common import Message, Page
from app.schemas.policy import (
    AdmissionRuleCreate,
    AdmissionRuleOut,
    AdmissionRuleUpdate,
    AuditOut,
    PolicyOut,
    PolicyUpdate,
)
from app.services.audit_service import AuditService
from app.services.device_posture import AdmissionService

router = APIRouter(tags=["policies"])

DEFAULT_POLICIES: list[dict[str, Any]] = [
    {
        "key": "risk.thresholds",
        "name": "Risk score bands",
        "description": "Policy defaults; tune against validated telemetry before relying on them.",
        "category": "risk",
        "config": {
            "bands": [
                {"name": "informational", "min": 0, "max": 19},
                {"name": "guarded", "min": 20, "max": 39},
                {"name": "medium", "min": 40, "max": 59},
                {"name": "high", "min": 60, "max": 79},
                {"name": "critical", "min": 80, "max": 100},
            ],
            "incident_creation_threshold": 80,
            "dedupe_window_minutes": 15,
        },
    },
    {
        "key": "response.approval",
        "name": "Response approval requirements",
        "description": "Which response actions may run automatically and which require human approval.",
        "category": "response",
        "config": {
            "auto_execute_threshold": 85,
            "allow_auto_low_impact": False,
            "allow_auto_critical_asset": False,
            "allowlist": [],
            "protected_services": [],
        },
    },
    {
        "key": "alert.escalation",
        "name": "Alert escalation",
        "description": "Severity-to-notification mapping and escalation schedule.",
        "category": "notification",
        "config": {
            "info": {"in_app": True, "email": False},
            "low": {"in_app": True, "email": False},
            "medium": {"in_app": True, "email": False},
            "high": {"in_app": True, "email": True, "incident": True},
            "critical": {"in_app": True, "email": True, "incident": True, "on_call": True},
            "schedule": {"business_hours": "08:00-20:00 Asia/Kolkata", "on_call": "24x7"},
        },
    },
    {
        "key": "ingest.retention",
        "name": "Data retention",
        "description": "Retention windows applied by the maintenance worker.",
        "category": "operations",
        "config": {"events_days": 90, "alerts_days": 365, "incidents_days": 1095, "audit_days": 2555},
    },
    {
        "key": "segment.allowlist",
        "name": "Business-critical allowlist",
        "description": "Hosts and services exempt from automated containment.",
        "category": "response",
        "config": {"hosts": [], "services": [], "note": "Add core infrastructure before enabling automatic containment."},
    },
]


@router.get("/policies", response_model=list[PolicyOut], dependencies=[Depends(rate_limit)])
def list_policies(
    user: User = Depends(require(Permission.POLICY_READ)),
    db: Session = Depends(get_db),
) -> list[Policy]:
    if not db.execute(select(Policy.id).limit(1)).first():
        for item in DEFAULT_POLICIES:
            db.add(Policy(**item))
        AdmissionService(db).ensure_default_rules()
        db.commit()
    return list(db.execute(select(Policy).order_by(Policy.category, Policy.key)).scalars().all())


@router.patch("/policies/{key}", response_model=PolicyOut)
def update_policy(
    key: str,
    payload: PolicyUpdate,
    request: Request,
    user: User = Depends(require(Permission.POLICY_WRITE)),
    db: Session = Depends(get_db),
) -> Policy:
    policy = db.execute(select(Policy).where(Policy.key == key)).scalars().first()
    if not policy:
        raise NotFound("policy not found")
    changes: dict[str, Any] = {}
    if payload.name is not None:
        policy.name = payload.name
        changes["name"] = payload.name
    if payload.description is not None:
        policy.description = payload.description
    if payload.enabled is not None:
        policy.enabled = payload.enabled
        changes["enabled"] = payload.enabled
    if payload.config is not None:
        policy.config = payload.config
        changes["config_keys"] = sorted(payload.config)
    policy.version += 1
    policy.updated_by = user.id
    AuditService(db).record(
        action="policy.updated", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="policy", object_id=policy.id, detail={"key": key, "changes": changes, "version": policy.version},
        client_ip=client_ip(request),
    )
    db.commit()
    return policy


@router.get("/admission-rules", response_model=list[AdmissionRuleOut])
def list_admission_rules(
    user: User = Depends(require(Permission.POLICY_READ)),
    db: Session = Depends(get_db),
) -> list[AdmissionRule]:
    service = AdmissionService(db)
    service.ensure_default_rules()
    db.commit()
    return service.rules()


@router.post("/admission-rules", response_model=AdmissionRuleOut, status_code=201)
def create_admission_rule(
    payload: AdmissionRuleCreate,
    request: Request,
    user: User = Depends(require(Permission.POLICY_WRITE)),
    db: Session = Depends(get_db),
) -> AdmissionRule:
    AdmissionService(db).validate_rule_condition(payload.condition)
    rule = AdmissionRule(**payload.model_dump())
    db.add(rule)
    db.flush()
    AuditService(db).record(
        action="admission_rule.created", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="admission_rule", object_id=rule.id, detail={"name": rule.name, "outcome": rule.outcome},
        client_ip=client_ip(request),
    )
    db.commit()
    return rule


@router.patch("/admission-rules/{rule_id}", response_model=AdmissionRuleOut)
def update_admission_rule(
    rule_id: str,
    payload: AdmissionRuleUpdate,
    request: Request,
    user: User = Depends(require(Permission.POLICY_WRITE)),
    db: Session = Depends(get_db),
) -> AdmissionRule:
    rule = db.get(AdmissionRule, rule_id)
    if not rule:
        raise NotFound("admission rule not found")
    changes = payload.model_dump(exclude_unset=True)
    if "condition" in changes:
        AdmissionService(db).validate_rule_condition(changes["condition"])
    for key, value in changes.items():
        setattr(rule, key, value)
    AuditService(db).record(
        action="admission_rule.updated", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="admission_rule", object_id=rule.id, detail={"fields": sorted(changes)},
        client_ip=client_ip(request),
    )
    db.commit()
    return rule


@router.delete("/admission-rules/{rule_id}", response_model=Message)
def delete_admission_rule(
    rule_id: str,
    request: Request,
    user: User = Depends(require(Permission.POLICY_WRITE)),
    db: Session = Depends(get_db),
) -> Message:
    rule = db.get(AdmissionRule, rule_id)
    if not rule:
        raise NotFound("admission rule not found")
    db.delete(rule)
    AuditService(db).record(
        action="admission_rule.deleted", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="admission_rule", object_id=rule_id, detail={"name": rule.name},
        client_ip=client_ip(request),
    )
    db.commit()
    return Message(message="rule deleted")


@router.get("/audit", response_model=Page[AuditOut], dependencies=[Depends(rate_limit)])
def audit_log(
    action: str | None = None,
    actor: str | None = None,
    page: int = 1,
    page_size: int = 50,
    user: User = Depends(require(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> Page[AuditOut]:
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor_email == actor)
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = (
        db.execute(
            stmt.order_by(AuditLog.ts.desc())
            .offset((max(page, 1) - 1) * min(page_size, 200))
            .limit(min(page_size, 200))
        )
        .scalars()
        .all()
    )
    return Page[AuditOut](
        items=[AuditOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size
    )


@router.get("/audit/verify")
def verify_audit_chain(
    user: User = Depends(require(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return AuditService(db).verify_chain()
