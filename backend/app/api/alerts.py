"""Alert list, detail, triage, suppression and false-positive feedback."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, rate_limit, require
from app.core.database import get_db
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.core.permissions import Permission
from app.models.alert import Alert, Suppression
from app.models.base import AlertStatus
from app.models.telemetry import Event
from app.models.user import User
from app.schemas.alert import AlertOut, AlertTriageIn, SuppressionIn, SuppressionOut
from app.schemas.common import Page
from app.services.audit_service import AuditService
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut], dependencies=[Depends(rate_limit)])
def list_alerts(
    status: str | None = Query(default=None, pattern="^(open|acknowledged|investigating|suppressed|closed)$"),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    rule_id: str | None = Query(default=None, max_length=40),
    asset_id: str | None = None,
    q: str | None = Query(default=None, max_length=120),
    min_risk: int | None = Query(default=None, ge=0, le=100),
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="last_seen", pattern="^(last_seen|risk_score|first_seen|severity)$"),
    user: User = Depends(require(Permission.ALERT_READ)),
    db: Session = Depends(get_db),
) -> Page[AlertOut]:
    stmt = select(Alert)
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if asset_id:
        stmt = stmt.where(Alert.asset_id == asset_id)
    if min_risk is not None:
        stmt = stmt.where(Alert.risk_score >= min_risk)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            func.lower(Alert.title).like(like)
            | func.lower(func.coalesce(Alert.src_ip, "")).like(like)
            | func.lower(func.coalesce(Alert.dst_ip, "")).like(like)
        )
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    order = {
        "last_seen": Alert.last_seen.desc(),
        "first_seen": Alert.first_seen.desc(),
        "risk_score": Alert.risk_score.desc(),
        "severity": Alert.risk_score.desc(),
    }[sort]
    rows = (
        db.execute(stmt.order_by(order).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    )
    return Page[AlertOut](items=[AlertOut.model_validate(a) for a in rows], total=total, page=page, page_size=page_size)


@router.get("/{alert_id}")
def get_alert(
    alert_id: str,
    user: User = Depends(require(Permission.ALERT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise NotFound("alert not found")
    events = (
        db.execute(select(Event).where(Event.alert_id == alert.id).order_by(Event.ts.desc()).limit(25))
        .scalars()
        .all()
    )
    return {
        "alert": AlertOut.model_validate(alert).model_dump(mode="json"),
        "events": [
            {
                "id": e.id,
                "ts": e.ts.isoformat(),
                "source": e.source,
                "event_type": e.event_type,
                "severity": e.severity,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
                "dns_query": e.dns_query,
                "signature": e.signature,
                "risk_score": e.risk_score,
            }
            for e in events
        ],
        "explanation": {
            "rule_id": alert.rule_id,
            "rule_version": alert.rule_version,
            "detection_source": alert.detection_source,
            "signals": alert.signals,
            "confidence": alert.confidence,
            "risk_score": alert.risk_score,
            "caveat": "Risk scores are policy defaults and require tuning against real telemetry.",
        },
    }


@router.patch("/{alert_id}", response_model=AlertOut)
def triage_alert(
    alert_id: str,
    payload: AlertTriageIn,
    request: Request,
    user: User = Depends(require(Permission.ALERT_TRIAGE)),
    db: Session = Depends(get_db),
) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise NotFound("alert not found")
    audit = AuditService(db)
    changes: dict[str, Any] = {}

    if payload.status:
        if alert.status == AlertStatus.CLOSED and payload.status != AlertStatus.CLOSED:
            raise Conflict("closed alerts cannot be reopened; open a new incident instead")
        if payload.status == AlertStatus.CLOSED:
            alert.closed_at = datetime.now(UTC)
        alert.status = payload.status
        changes["status"] = payload.status
        if payload.status == AlertStatus.ACKNOWLEDGED and not alert.acknowledged_at:
            alert.acknowledged_at = datetime.now(UTC)
            alert.acknowledged_by = user.id
    if payload.assignee_id:
        assignee = db.get(User, payload.assignee_id)
        if not assignee:
            raise NotFound("assignee not found")
        alert.assignee_id = assignee.id
        changes["assignee"] = assignee.email
    if payload.note:
        alert.analyst_note = payload.note
        changes["note"] = payload.note[:200]
    if payload.false_positive is not None:
        alert.false_positive = payload.false_positive
        changes["false_positive"] = payload.false_positive
    if payload.suppress_minutes:
        now = datetime.now(UTC)
        alert.suppressed_until = now + timedelta(minutes=payload.suppress_minutes)
        db.add(
            Suppression(
                fingerprint=alert.fingerprint,
                rule_id=alert.rule_id,
                asset_id=alert.asset_id,
                reason=payload.note or "Analyst suppression from alert triage",
                created_by=user.id,
                expires_at=alert.suppressed_until,
                active=True,
            )
        )
        changes["suppressed_until"] = alert.suppressed_until.isoformat()

    if payload.create_incident:
        incident = IncidentService(db).create_from_alerts(actor=user, alert_ids=[alert.id])
        alert.incident_id = incident.id
        changes["incident_id"] = incident.id

    audit.record(
        action="alert.triaged", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="alert", object_id=alert.id, detail=changes, client_ip=client_ip(request),
    )
    db.commit()
    return alert


@router.post("/suppressions", response_model=SuppressionOut, status_code=201)
def create_suppression(
    payload: SuppressionIn,
    request: Request,
    user: User = Depends(require(Permission.POLICY_WRITE)),
    db: Session = Depends(get_db),
) -> Suppression:
    if not any((payload.fingerprint, payload.rule_id, payload.asset_id)):
        raise ValidationFailed("suppression must target a fingerprint, rule or asset")
    now = datetime.now(UTC)
    suppression = Suppression(
        fingerprint=payload.fingerprint,
        rule_id=payload.rule_id,
        asset_id=payload.asset_id,
        reason=payload.reason,
        created_by=user.id,
        expires_at=now + timedelta(minutes=payload.duration_minutes),
        active=True,
    )
    db.add(suppression)
    db.flush()
    AuditService(db).record(
        action="alert.suppression_created", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="suppression", object_id=suppression.id,
        detail={"reason": payload.reason, "expires_at": suppression.expires_at.isoformat()},
        client_ip=client_ip(request),
    )
    db.commit()
    return suppression


@router.get("/suppressions/list", response_model=list[SuppressionOut])
def list_suppressions(
    active_only: bool = True,
    user: User = Depends(require(Permission.POLICY_READ)),
    db: Session = Depends(get_db),
) -> list[Suppression]:
    now = datetime.now(UTC)
    stmt = select(Suppression).order_by(Suppression.expires_at.desc())
    if active_only:
        stmt = stmt.where(Suppression.active.is_(True), Suppression.expires_at > now)
    return list(db.execute(stmt.limit(200)).scalars().all())


@router.delete("/suppressions/{suppression_id}", status_code=204, response_class=Response)
def revoke_suppression(
    suppression_id: str,
    request: Request,
    user: User = Depends(require(Permission.POLICY_WRITE)),
    db: Session = Depends(get_db),
) -> Response:
    suppression = db.get(Suppression, suppression_id)
    if not suppression:
        raise NotFound("suppression not found")
    suppression.active = False
    AuditService(db).record(
        action="alert.suppression_revoked", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="suppression", object_id=suppression.id, detail={}, client_ip=client_ip(request),
    )
    db.commit()
    return Response(status_code=204)


@router.get("/rules/catalog")
def rule_catalog(user: User = Depends(require(Permission.ALERT_READ))) -> list[dict[str, str]]:
    from app.services.detection_rules import rules_catalog

    return rules_catalog()
