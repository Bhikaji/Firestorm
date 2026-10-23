"""Reports and exports."""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.database import get_db
from app.core.permissions import Permission
from app.models.user import User
from app.services.incident_service import IncidentService
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/daily")
def daily_report(
    day: date | None = Query(default=None),
    user: User = Depends(require(Permission.REPORT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return ReportService(db).daily(day)


@router.get("/monthly")
def monthly_report(
    year: int | None = Query(default=None, ge=2024, le=2100),
    month: int | None = Query(default=None, ge=1, le=12),
    user: User = Depends(require(Permission.REPORT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return ReportService(db).monthly(year, month)


@router.get("/incidents")
def incident_stats(
    days: int = Query(default=30, ge=1, le=365),
    user: User = Depends(require(Permission.REPORT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return IncidentService(db).stats(days)


@router.get("/daily/export", response_class=PlainTextResponse)
def export_daily(
    day: date | None = Query(default=None),
    user: User = Depends(require(Permission.REPORT_READ)),
    db: Session = Depends(get_db),
) -> PlainTextResponse:
    service = ReportService(db)
    report = service.daily(day)
    return PlainTextResponse(
        service.render_markdown(report),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="firestorm-daily-report.md"'},
    )
