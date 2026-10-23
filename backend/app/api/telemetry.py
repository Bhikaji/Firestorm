"""Telemetry ingestion and event exploration.

Two ingestion paths:

* ``POST /telemetry/events`` uses the shared ``X-API-Key`` sensor credential
  (no user session) - this is what a small sensor shipper would use.
* ``POST /telemetry/events/batch`` accepts up to 500 events per request and
  reports accepted/duplicate/rejected counts so a shipper can apply backpressure.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import rate_limit, require, verify_ingest_key
from app.core.database import get_db
from app.core.errors import NotFound
from app.core.permissions import Permission
from app.models.telemetry import Event
from app.models.user import User
from app.schemas.common import Page
from app.schemas.telemetry import BatchIngestResult, EventBatch, EventDetail, EventIn, EventOut
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.post("/events", response_model=BatchIngestResult, status_code=202)
def ingest_event(
    payload: EventIn,
    request: Request,
    _: None = Depends(verify_ingest_key),
    db: Session = Depends(get_db),
) -> BatchIngestResult:
    service = DetectionService(db)
    event, alerts = service.ingest(payload)
    return BatchIngestResult(
        accepted=1 if event else 0,
        duplicates=0 if event else 1,
        rejected=0,
        alerts_created=len(alerts),
    )


@router.post("/events/batch", response_model=BatchIngestResult, status_code=202)
def ingest_batch(
    payload: EventBatch,
    request: Request,
    _: None = Depends(verify_ingest_key),
    db: Session = Depends(get_db),
) -> BatchIngestResult:
    result = DetectionService(db).ingest_batch(payload.events)
    return BatchIngestResult(**result)


@router.get("/events", response_model=Page[EventOut], dependencies=[Depends(rate_limit)])
def list_events(
    source: str | None = Query(default=None, max_length=40),
    event_type: str | None = Query(default=None, max_length=60),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    src_ip: str | None = Query(default=None, max_length=45),
    asset_id: str | None = None,
    q: str | None = Query(default=None, max_length=120),
    start: datetime | None = None,
    end: datetime | None = None,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require(Permission.EVENT_READ)),
    db: Session = Depends(get_db),
) -> Page[EventOut]:
    stmt = select(Event)
    if source:
        stmt = stmt.where(Event.source == source)
    if event_type:
        stmt = stmt.where(Event.event_type == event_type)
    if severity:
        stmt = stmt.where(Event.severity == severity)
    if src_ip:
        stmt = stmt.where(Event.src_ip == src_ip)
    if asset_id:
        stmt = stmt.where(Event.asset_id == asset_id)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            func.lower(func.coalesce(Event.dns_query, "")).like(like)
            | func.lower(func.coalesce(Event.hostname, "")).like(like)
            | func.lower(func.coalesce(Event.signature, "")).like(like)
        )
    if start:
        stmt = stmt.where(Event.ts >= start)
    if end:
        stmt = stmt.where(Event.ts <= end)

    total = int(db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one())
    rows = (
        db.execute(stmt.order_by(Event.ts.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    )
    return Page[EventOut](items=[EventOut.model_validate(e) for e in rows], total=total, page=page, page_size=page_size)


@router.get("/events/{event_id}", response_model=EventDetail)
def get_event(
    event_id: str,
    user: User = Depends(require(Permission.EVENT_READ)),
    db: Session = Depends(get_db),
) -> Event:
    event = db.get(Event, event_id)
    if not event:
        raise NotFound("event not found")
    return event


@router.get("/sources")
def event_sources(
    user: User = Depends(require(Permission.EVENT_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Event.source, func.count(Event.id), func.max(Event.ts)).group_by(Event.source).order_by(func.count(Event.id).desc())
    ).all()
    return [
        {"source": source, "events": int(count), "last_seen": last.isoformat() if last else None}
        for source, count, last in rows
    ]
