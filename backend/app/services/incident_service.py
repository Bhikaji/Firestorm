"""Incident lifecycle, timeline and correlation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import Conflict, NotFound
from app.models.alert import Alert
from app.models.base import AlertStatus, IncidentStatus
from app.models.incident import Incident, IncidentTimelineEvent, ResponseAction
from app.models.user import User
from app.services.audit_service import AuditService

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    IncidentStatus.NEW: {IncidentStatus.TRIAGE, IncidentStatus.CLOSED},
    IncidentStatus.TRIAGE: {IncidentStatus.CONTAINMENT, IncidentStatus.CLOSED, IncidentStatus.NEW},
    IncidentStatus.CONTAINMENT: {IncidentStatus.CONTAINED, IncidentStatus.ERADICATION, IncidentStatus.TRIAGE},
    IncidentStatus.CONTAINED: {IncidentStatus.ERADICATION, IncidentStatus.RECOVERY},
    IncidentStatus.ERADICATION: {IncidentStatus.RECOVERY},
    IncidentStatus.RECOVERY: {IncidentStatus.CLOSED},
    IncidentStatus.CLOSED: set(),
}


def _now() -> datetime:
    return datetime.now(UTC)


class IncidentService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

    def get(self, incident_id: str) -> Incident:
        incident = self.db.get(Incident, incident_id)
        if not incident:
            raise NotFound("incident not found")
        return incident

    def create_from_alerts(
        self, *, actor: User, alert_ids: list[str], title: str | None = None, summary: str | None = None
    ) -> Incident:
        alerts = list(self.db.execute(select(Alert).where(Alert.id.in_(alert_ids))).scalars().all())
        if not alerts:
            raise NotFound("no matching alerts")
        top = max(alerts, key=lambda a: a.risk_score)
        reference = f"INC-{_now():%Y%m%d}-{top.id[:8].upper()}"
        incident = Incident(
            reference=reference,
            title=title or f"Investigation: {top.title}",
            summary=summary
            or (
                f"Analyst-created incident from {len(alerts)} alert(s). Highest risk {top.risk_score}/100 "
                f"({top.rule_id})."
            ),
            severity=top.severity,
            status=IncidentStatus.NEW,
            risk_score=top.risk_score,
            detected_at=min(a.first_seen for a in alerts),
            observed_facts=[
                {"fact": "Correlated alerts", "detail": ", ".join(a.id for a in alerts)}
            ],
            affected_asset_ids=sorted({a.asset_id for a in alerts if a.asset_id}),
        )
        self.db.add(incident)
        self.db.flush()
        for alert in alerts:
            alert.incident_id = incident.id
        self.db.add(
            IncidentTimelineEvent(
                incident_id=incident.id,
                ts=_now(),
                kind="status",
                actor=actor.email,
                message=f"Incident created from {len(alerts)} alert(s)",
                payload={"alert_ids": [a.id for a in alerts]},
            )
        )
        self.audit.record(
            action="incident.created",
            actor_id=actor.id,
            actor_email=actor.email,
            actor_role=actor.role,
            object_type="incident",
            object_id=incident.id,
            detail={"alert_ids": alert_ids, "reference": reference},
        )
        self.db.flush()
        return incident

    def update(
        self,
        incident_id: str,
        *,
        actor: User,
        status: str | None = None,
        owner_id: str | None = None,
        severity: str | None = None,
        summary: str | None = None,
        post_incident_review: str | None = None,
        hypothesis: str | None = None,
    ) -> Incident:
        incident = self.get(incident_id)
        changes: dict[str, Any] = {}

        if status and status != incident.status:
            allowed = ALLOWED_TRANSITIONS.get(incident.status, set())
            if status not in allowed:
                raise Conflict(
                    f"cannot move incident from '{incident.status}' to '{status}'; "
                    f"allowed: {sorted(allowed) or 'none'}"
                )
            changes["status"] = {"from": incident.status, "to": status}
            incident.status = status
            if status == IncidentStatus.CONTAINED:
                incident.contained_at = _now()
            if status == IncidentStatus.CLOSED:
                incident.closed_at = _now()
                # Close is idempotent for linked alerts, but only after review.
                for alert in self.db.execute(
                    select(Alert).where(Alert.incident_id == incident.id)
                ).scalars():
                    if alert.status != AlertStatus.CLOSED:
                        alert.status = AlertStatus.CLOSED
                        alert.closed_at = _now()
            self._timeline(incident.id, actor.email, "status", f"Status changed to {status}", {"from": incident.status, "to": status})

        if owner_id is not None:
            owner = self.db.get(User, owner_id)
            if not owner:
                raise NotFound("owner not found")
            incident.owner_id = owner.id
            changes["owner_id"] = owner.email
            self._timeline(incident.id, actor.email, "note", f"Assigned to {owner.email}", {})

        if severity:
            incident.severity = severity
            changes["severity"] = severity
        if summary is not None:
            incident.summary = summary
        if post_incident_review is not None:
            incident.post_incident_review = post_incident_review
        if hypothesis:
            incident.hypotheses = [
                *(incident.hypotheses or []),
                {"hypothesis": hypothesis, "confidence": 0.5, "status": "unverified", "added_by": actor.email},
            ]
            self._timeline(incident.id, actor.email, "note", "Hypothesis recorded", {"hypothesis": hypothesis})

        self.audit.record(
            action="incident.updated",
            actor_id=actor.id,
            actor_email=actor.email,
            actor_role=actor.role,
            object_type="incident",
            object_id=incident.id,
            detail=changes,
        )
        self.db.flush()
        return incident

    def add_note(self, incident_id: str, actor: User, message: str) -> IncidentTimelineEvent:
        self.get(incident_id)
        entry = self._timeline(incident_id, actor.email, "note", message, {})
        self.audit.record(
            action="incident.note_added",
            actor_id=actor.id,
            actor_email=actor.email,
            actor_role=actor.role,
            object_type="incident",
            object_id=incident_id,
            detail={"message": message[:500]},
        )
        self.db.flush()
        return entry

    def timeline(self, incident_id: str) -> list[IncidentTimelineEvent]:
        self.get(incident_id)
        return list(
            self.db.execute(
                select(IncidentTimelineEvent)
                .where(IncidentTimelineEvent.incident_id == incident_id)
                .order_by(IncidentTimelineEvent.ts.asc())
            ).scalars()
        )

    def related_alerts(self, incident_id: str) -> list[Alert]:
        return list(
            self.db.execute(
                select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.risk_score.desc())
            ).scalars()
        )

    def actions(self, incident_id: str) -> list[ResponseAction]:
        return list(
            self.db.execute(
                select(ResponseAction)
                .where(ResponseAction.incident_id == incident_id)
                .order_by(ResponseAction.created_at.desc())
            ).scalars()
        )

    def correlate(self, incident_id: str) -> list[dict[str, Any]]:
        """Suggest additional alerts that likely belong to this incident."""
        incident = self.get(incident_id)
        window_start = incident.detected_at - timedelta(hours=1)
        window_end = (incident.closed_at or _now()) + timedelta(hours=1)
        stmt = select(Alert).where(
            Alert.incident_id.is_(None),
            Alert.first_seen >= window_start,
            Alert.first_seen <= window_end,
        )
        if incident.affected_asset_ids:
            stmt = stmt.where(Alert.asset_id.in_(incident.affected_asset_ids))
        elif incident.observed_facts:
            stmt = stmt.where(Alert.risk_score >= 40)
        suggestions = self.db.execute(stmt.order_by(Alert.risk_score.desc()).limit(20)).scalars().all()
        return [
            {
                "alert_id": a.id,
                "title": a.title,
                "risk_score": a.risk_score,
                "first_seen": a.first_seen.isoformat(),
                "reason": "same asset" if a.asset_id in incident.affected_asset_ids else "time proximity",
            }
            for a in suggestions
        ]

    def stats(self, days: int = 30) -> dict[str, Any]:
        since = _now() - timedelta(days=days)
        rows = (
            self.db.execute(select(Incident).where(Incident.detected_at >= since)).scalars().all()
        )
        closed = [r for r in rows if r.closed_at]
        mttr = [r.mttr_minutes for r in closed if r.mttr_minutes is not None]
        by_severity: dict[str, int] = {}
        for row in rows:
            by_severity[row.severity] = by_severity.get(row.severity, 0) + 1
        return {
            "window_days": days,
            "total": len(rows),
            "open": len([r for r in rows if r.status != IncidentStatus.CLOSED]),
            "closed": len(closed),
            "mttr_minutes": round(sum(mttr) / len(mttr), 1) if mttr else None,
            "by_severity": by_severity,
        }

    def _timeline(self, incident_id: str, actor: str, kind: str, message: str, payload: dict) -> IncidentTimelineEvent:
        entry = IncidentTimelineEvent(
            incident_id=incident_id, ts=_now(), kind=kind, actor=actor, message=message, payload=payload
        )
        self.db.add(entry)
        self.db.flush()
        return entry
