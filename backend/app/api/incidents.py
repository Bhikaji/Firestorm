"""Incident investigation, evidence, response actions and recovery."""

from __future__ import annotations

from datetime import UTC
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, rate_limit, require
from app.core.database import get_db
from app.core.errors import ValidationFailed
from app.core.permissions import Permission
from app.models.incident import Evidence, Incident, ResponseAction
from app.models.user import User
from app.schemas.common import Message, Page
from app.schemas.incident import (
    ActionDecision,
    ActionOut,
    ActionRequest,
    EvidenceCollectIn,
    EvidenceOut,
    IncidentCreate,
    IncidentDetail,
    IncidentOut,
    IncidentUpdate,
    TimelineEntry,
)
from app.services.audit_service import AuditService
from app.services.evidence_service import EvidenceService
from app.services.incident_service import IncidentService
from app.services.response_engine import ResponseEngine

router = APIRouter(tags=["incidents"])


@router.get("/incidents", response_model=Page[IncidentOut], dependencies=[Depends(rate_limit)])
def list_incidents(
    status: str | None = Query(default=None, pattern="^(new|triage|containment|contained|eradication|recovery|closed)$"),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    q: str | None = Query(default=None, max_length=120),
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=200),
    user: User = Depends(require(Permission.INCIDENT_READ)),
    db: Session = Depends(get_db),
) -> Page[IncidentOut]:
    stmt = select(Incident)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            func.lower(Incident.title).like(like) | func.lower(Incident.reference).like(like)
        )
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = (
        db.execute(stmt.order_by(Incident.detected_at.desc()).offset((page - 1) * page_size).limit(page_size))
        .scalars()
        .all()
    )
    return Page[IncidentOut](
        items=[IncidentOut.model_validate(i) for i in rows], total=total, page=page, page_size=page_size
    )


@router.post("/incidents", response_model=IncidentOut, status_code=201)
def create_incident(
    payload: IncidentCreate,
    request: Request,
    user: User = Depends(require(Permission.INCIDENT_WRITE)),
    db: Session = Depends(get_db),
) -> Incident:
    service = IncidentService(db)
    if payload.alert_ids:
        incident = service.create_from_alerts(
            actor=user, alert_ids=payload.alert_ids, title=payload.title, summary=payload.summary
        )
        if payload.affected_asset_ids:
            incident.affected_asset_ids = payload.affected_asset_ids
        if payload.observed_facts:
            incident.observed_facts = payload.observed_facts
    else:
        import secrets
        from datetime import datetime

        incident = Incident(
            reference=f"INC-{datetime.now(UTC):%Y%m%d}-{secrets.token_hex(3).upper()}",
            title=payload.title,
            summary=payload.summary,
            severity=payload.severity,
            status="new",
            observed_facts=payload.observed_facts,
            affected_asset_ids=payload.affected_asset_ids,
        )
        db.add(incident)
        db.flush()
    AuditService(db).record(
        action="incident.created", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="incident", object_id=incident.id, detail={"reference": incident.reference},
        client_ip=client_ip(request),
    )
    db.commit()
    return incident


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: str,
    user: User = Depends(require(Permission.INCIDENT_READ)),
    db: Session = Depends(get_db),
) -> IncidentDetail:
    service = IncidentService(db)
    incident = service.get(incident_id)
    timeline = service.timeline(incident_id)
    alerts = service.related_alerts(incident_id)
    actions = service.actions(incident_id)
    evidence = (
        db.execute(select(Evidence).where(Evidence.incident_id == incident_id).order_by(Evidence.collected_at.desc()))
        .scalars()
        .all()
    )
    detail = IncidentDetail.model_validate(incident)
    detail.timeline = [TimelineEntry.model_validate(t) for t in timeline]
    detail.evidence = [EvidenceOut.model_validate(e) for e in evidence]
    detail.actions = [ActionOut.model_validate(a) for a in actions]
    detail.alerts = [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "status": a.status,
            "rule_id": a.rule_id,
            "first_seen": a.first_seen.isoformat(),
        }
        for a in alerts
    ]
    return detail


@router.patch("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    request: Request,
    user: User = Depends(require(Permission.INCIDENT_WRITE)),
    db: Session = Depends(get_db),
) -> Incident:
    incident = IncidentService(db).update(
        incident_id,
        actor=user,
        status=payload.status,
        owner_id=payload.owner_id,
        severity=payload.severity,
        summary=payload.summary,
        post_incident_review=payload.post_incident_review,
        hypothesis=payload.hypothesis,
    )
    db.commit()
    return incident


@router.post("/incidents/{incident_id}/notes", response_model=TimelineEntry, status_code=201)
def add_note(
    incident_id: str,
    payload: dict,
    request: Request,
    user: User = Depends(require(Permission.INCIDENT_WRITE)),
    db: Session = Depends(get_db),
) -> TimelineEntry:
    message = str(payload.get("message", "")).strip()
    if not message or len(message) > 4000:
        raise ValidationFailed("note message is required and must be under 4000 characters")
    entry = IncidentService(db).add_note(incident_id, user, message)
    db.commit()
    return TimelineEntry.model_validate(entry)


@router.get("/incidents/{incident_id}/correlations")
def correlations(
    incident_id: str,
    user: User = Depends(require(Permission.INCIDENT_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return IncidentService(db).correlate(incident_id)


@router.post("/incidents/{incident_id}/evidence", response_model=EvidenceOut, status_code=201)
def collect_evidence(
    incident_id: str,
    payload: EvidenceCollectIn,
    request: Request,
    user: User = Depends(require(Permission.EVIDENCE_COLLECT)),
    db: Session = Depends(get_db),
) -> Evidence:
    IncidentService(db).get(incident_id)
    evidence = EvidenceService(db).collect(
        actor=user,
        kind=payload.kind,
        label=payload.label,
        incident_id=incident_id,
        alert_id=payload.alert_id,
        event_ids=payload.event_ids,
        file_hash=payload.file_hash,
        content=payload.content,
        metadata=payload.metadata,
    )
    db.commit()
    return evidence


@router.get("/evidence/{evidence_id}/verify")
def verify_evidence(
    evidence_id: str,
    user: User = Depends(require(Permission.INCIDENT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return EvidenceService(db).verify(evidence_id)


@router.get("/actions", response_model=Page[ActionOut])
def list_actions(
    status: str | None = None,
    incident_id: str | None = None,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=200),
    user: User = Depends(require(Permission.INCIDENT_READ)),
    db: Session = Depends(get_db),
) -> Page[ActionOut]:
    stmt = select(ResponseAction)
    if status:
        stmt = stmt.where(ResponseAction.status == status)
    if incident_id:
        stmt = stmt.where(ResponseAction.incident_id == incident_id)
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = (
        db.execute(
            stmt.order_by(ResponseAction.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        )
        .scalars()
        .all()
    )
    return Page[ActionOut](
        items=[ActionOut.model_validate(a) for a in rows], total=total, page=page, page_size=page_size
    )


@router.post("/actions", response_model=ActionOut, status_code=201)
def request_action(
    payload: ActionRequest,
    request: Request,
    user: User = Depends(require(Permission.ACTION_REQUEST)),
    db: Session = Depends(get_db),
) -> ResponseAction:
    action = ResponseEngine(db).request(
        action_type=payload.action_type,
        target=payload.target,
        reason=payload.reason,
        actor=user,
        incident_id=payload.incident_id,
        alert_id=payload.alert_id,
        asset_id=payload.asset_id,
        risk_score=90,
        require_approval=payload.require_approval,
    )
    db.commit()
    return action


@router.post("/actions/{action_id}/approve", response_model=ActionOut)
def approve_action(
    action_id: str,
    payload: ActionDecision,
    request: Request,
    user: User = Depends(require(Permission.ACTION_APPROVE)),
    db: Session = Depends(get_db),
) -> ResponseAction:
    action = ResponseEngine(db).approve(action_id, user, payload.note)
    db.commit()
    return action


@router.post("/actions/{action_id}/reject", response_model=ActionOut)
def reject_action(
    action_id: str,
    payload: ActionDecision,
    request: Request,
    user: User = Depends(require(Permission.ACTION_APPROVE)),
    db: Session = Depends(get_db),
) -> ResponseAction:
    action = ResponseEngine(db).reject(action_id, user, payload.note)
    db.commit()
    return action


@router.post("/actions/{action_id}/execute", response_model=ActionOut)
def execute_action(
    action_id: str,
    request: Request,
    user: User = Depends(require(Permission.ACTION_EXECUTE)),
    db: Session = Depends(get_db),
) -> ResponseAction:
    action = ResponseEngine(db).execute(action_id, user)
    db.commit()
    return action


@router.post("/actions/{action_id}/revert", response_model=ActionOut)
def revert_action(
    action_id: str,
    payload: ActionDecision,
    request: Request,
    user: User = Depends(require(Permission.ACTION_EXECUTE)),
    db: Session = Depends(get_db),
) -> ResponseAction:
    action = ResponseEngine(db).revert(action_id, user, note=payload.note)
    db.commit()
    return action


@router.post("/actions/emergency-release", response_model=Message)
def emergency_release(
    payload: dict,
    request: Request,
    user: User = Depends(require(Permission.ACTION_APPROVE)),
    db: Session = Depends(get_db),
) -> Message:
    note = str(payload.get("note", "")).strip()
    if len(note) < 10:
        raise ValidationFailed("an explanation of at least 10 characters is required")
    result = ResponseEngine(db).release_all(user, note=note)
    db.commit()
    return Message(
        message="emergency release executed",
        detail=f"released {result['released']}, failed {len(result['failed'])}, remaining {result['remaining']}",
    )


@router.get("/enforcement")
def active_enforcement(
    user: User = Depends(require(Permission.INCIDENT_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = ResponseEngine(db).active_enforcement()
    return [
        {
            "id": r.id,
            "kind": r.kind,
            "target": r.target,
            "integration": r.integration,
            "mode": r.mode,
            "state": r.state,
            "detail": r.detail,
            "created_at": r.created_at.isoformat(),
            "action_id": r.action_id,
        }
        for r in rows
    ]
