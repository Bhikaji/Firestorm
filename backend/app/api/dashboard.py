"""Aggregated dashboard endpoints consumed by FIRESTORM COMMAND."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import rate_limit, require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.user import User
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(rate_limit)])


@router.get("/overview")
def overview(
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return DashboardService(db).overview()


@router.get("/topology")
def topology(
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return DashboardService(db).topology()


@router.get("/feed")
def feed(
    limit: int = Query(default=40, ge=1, le=200),
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return DashboardService(db).recent_events(limit)


@router.get("/severity")
def severity(
    hours: int = Query(default=24, ge=1, le=720),
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return DashboardService(db).severity_distribution(hours)


@router.get("/trend")
def trend(
    days: int = Query(default=7, ge=1, le=90),
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return DashboardService(db).alert_trend(days)


@router.get("/trust")
def trust(
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return DashboardService(db).trust_overview()


@router.get("/risky-assets")
def risky_assets(
    limit: int = Query(default=8, ge=1, le=50),
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return DashboardService(db).top_risky_assets(limit)


@router.get("/layers")
def layers(
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return DashboardService(db).protection_layers()


@router.get("/attention")
def attention(
    user: User = Depends(require(Permission.ALERT_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return DashboardService(db).approaching_deadlines()
