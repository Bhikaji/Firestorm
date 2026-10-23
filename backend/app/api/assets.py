"""Device inventory, segments, posture and admission endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, rate_limit, require
from app.core.database import get_db
from app.core.errors import Conflict, NotFound
from app.core.permissions import Permission
from app.models.alert import Alert
from app.models.asset import Asset, Segment
from app.models.base import TrustState
from app.models.incident import Incident
from app.models.user import User
from app.schemas.asset import (
    AdmissionDecision,
    AssetCreate,
    AssetOut,
    AssetUpdate,
    PostureReport,
    QuarantineRequest,
    SegmentCreate,
    SegmentOut,
    TrustChange,
)
from app.schemas.common import Message, Page
from app.services.audit_service import AuditService
from app.services.device_posture import AdmissionService

router = APIRouter(tags=["assets"])


@router.get("/segments", response_model=list[SegmentOut], dependencies=[Depends(rate_limit)])
def list_segments(
    user: User = Depends(require(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> list[Segment]:
    return list(db.execute(select(Segment).order_by(Segment.name)).scalars().all())


@router.post("/segments", response_model=SegmentOut, status_code=201)
def create_segment(
    payload: SegmentCreate,
    request: Request,
    user: User = Depends(require(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> Segment:
    if db.execute(select(Segment).where(Segment.name == payload.name)).scalars().first():
        raise Conflict("a segment with that name already exists")
    segment = Segment(**payload.model_dump())
    db.add(segment)
    db.flush()
    AuditService(db).record(
        action="segment.created", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="segment", object_id=segment.id, detail={"name": segment.name, "cidr": segment.cidr},
        client_ip=client_ip(request),
    )
    db.commit()
    return segment


@router.get("/assets", response_model=Page[AssetOut], dependencies=[Depends(rate_limit)])
def list_assets(
    q: str | None = Query(default=None, max_length=120),
    trust_state: str | None = Query(default=None, pattern="^(trusted|unknown|noncompliant|quarantined|compromised)$"),
    segment_id: str | None = None,
    min_criticality: int | None = Query(default=None, ge=1, le=5),
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=200),
    user: User = Depends(require(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> Page[AssetOut]:
    stmt = select(Asset)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Asset.hostname).like(like),
                func.lower(Asset.ip_address).like(like),
                func.lower(func.coalesce(Asset.owner, "")).like(like),
                func.lower(func.coalesce(Asset.mac_address, "")).like(like),
            )
        )
    if trust_state:
        stmt = stmt.where(Asset.trust_state == trust_state)
    if segment_id:
        stmt = stmt.where(Asset.segment_id == segment_id)
    if min_criticality:
        stmt = stmt.where(Asset.criticality >= min_criticality)
    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = (
        db.execute(stmt.order_by(Asset.criticality.desc(), Asset.hostname).offset((page - 1) * page_size).limit(page_size))
        .scalars()
        .all()
    )
    return Page[AssetOut](items=[AssetOut.model_validate(a) for a in rows], total=total, page=page, page_size=page_size)


@router.get("/assets/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: str,
    user: User = Depends(require(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise NotFound("asset not found")
    return asset


@router.get("/assets/{asset_id}/context")
def asset_context(
    asset_id: str,
    user: User = Depends(require(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise NotFound("asset not found")
    alerts = (
        db.execute(select(Alert).where(Alert.asset_id == asset_id).order_by(Alert.last_seen.desc()).limit(20))
        .scalars()
        .all()
    )
    incidents = (
        db.execute(select(Incident).order_by(Incident.detected_at.desc()).limit(50)).scalars().all()
    )
    linked = [i for i in incidents if asset_id in (i.affected_asset_ids or [])]
    return {
        "asset": AssetOut.model_validate(asset).model_dump(mode="json"),
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "status": a.status,
                "last_seen": a.last_seen.isoformat(),
            }
            for a in alerts
        ],
        "incidents": [
            {"id": i.id, "reference": i.reference, "title": i.title, "status": i.status} for i in linked
        ],
        "admission": AdmissionService(db).evaluate(asset, persist=False),
    }


@router.post("/assets", response_model=AssetOut, status_code=201)
def create_asset(
    payload: AssetCreate,
    request: Request,
    user: User = Depends(require(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> Asset:
    existing = db.execute(select(Asset).where(Asset.ip_address == payload.ip_address, Asset.hostname == payload.hostname)).scalars().first()
    if existing:
        raise Conflict("asset with that hostname and IP already exists")
    if payload.segment_id and not db.get(Segment, payload.segment_id):
        raise NotFound("segment not found")
    asset = Asset(**payload.model_dump(), trust_state=TrustState.UNKNOWN)
    db.add(asset)
    db.flush()
    AuditService(db).record(
        action="asset.created", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="asset", object_id=asset.id,
        detail={"hostname": asset.hostname, "ip": asset.ip_address}, client_ip=client_ip(request),
    )
    db.commit()
    return asset


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    request: Request,
    user: User = Depends(require(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise NotFound("asset not found")
    changes = payload.model_dump(exclude_unset=True)
    if "segment_id" in changes and changes["segment_id"] and not db.get(Segment, changes["segment_id"]):
        raise NotFound("segment not found")
    for key, value in changes.items():
        setattr(asset, key, value)
    AuditService(db).record(
        action="asset.updated", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="asset", object_id=asset.id, detail={"fields": sorted(changes)}, client_ip=client_ip(request),
    )
    db.commit()
    return asset


@router.post("/assets/{asset_id}/posture", response_model=AssetOut)
def report_posture(
    asset_id: str,
    payload: PostureReport,
    request: Request,
    user: User = Depends(require(Permission.EVENT_INGEST)),
    db: Session = Depends(get_db),
) -> Asset:
    asset = AdmissionService(db).record_posture(asset_id, payload, actor=user)
    db.commit()
    return asset


@router.post("/assets/{asset_id}/admission", response_model=AdmissionDecision)
def evaluate_admission(
    asset_id: str,
    request: Request,
    user: User = Depends(require(Permission.ASSET_READ)),
    db: Session = Depends(get_db),
) -> AdmissionDecision:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise NotFound("asset not found")
    decision = AdmissionService(db).evaluate(asset)
    AuditService(db).record(
        action="admission.evaluated", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="asset", object_id=asset.id,
        detail={"outcome": decision["outcome"], "rule": decision["matched_rule"]},
        client_ip=client_ip(request),
    )
    db.commit()
    return AdmissionDecision(**decision)


@router.post("/assets/{asset_id}/trust", response_model=AssetOut)
def set_trust_state(
    asset_id: str,
    payload: TrustChange,
    request: Request,
    user: User = Depends(require(Permission.ASSET_WRITE)),
    db: Session = Depends(get_db),
) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise NotFound("asset not found")
    previous = asset.trust_state
    asset.trust_state = payload.trust_state
    if payload.trust_state == TrustState.QUARANTINED:
        asset.quarantine_reason = payload.reason
    AuditService(db).record(
        action="asset.trust_changed", actor_id=user.id, actor_email=user.email, actor_role=user.role,
        object_type="asset", object_id=asset.id,
        detail={"from": previous, "to": payload.trust_state, "reason": payload.reason},
        client_ip=client_ip(request),
    )
    db.commit()
    return asset


@router.post("/assets/{asset_id}/quarantine", response_model=Message)
def quarantine_asset(
    asset_id: str,
    payload: QuarantineRequest,
    request: Request,
    user: User = Depends(require(Permission.ACTION_REQUEST)),
    db: Session = Depends(get_db),
) -> Message:
    """Request quarantine. Execution follows the normal approval workflow."""
    from app.services.response_engine import ResponseEngine

    asset = db.get(Asset, asset_id)
    if not asset:
        raise NotFound("asset not found")
    engine = ResponseEngine(db)
    action = engine.request(
        action_type="quarantine_asset",
        target=asset.mac_address or asset.ip_address,
        reason=payload.reason,
        actor=user,
        asset_id=asset.id,
        risk_score=100,
    )
    db.commit()
    return Message(
        message="quarantine requested",
        detail=f"action {action.id} is {action.status}",
    )


@router.get("/admission/rules")
def admission_rules(
    user: User = Depends(require(Permission.POLICY_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    service = AdmissionService(db)
    service.ensure_default_rules()
    db.commit()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "priority": r.priority,
            "enabled": r.enabled,
            "condition": r.condition,
            "outcome": r.outcome,
            "outcome_reason": r.outcome_reason,
            "min_posture_score": r.min_posture_score,
        }
        for r in service.rules()
    ]
