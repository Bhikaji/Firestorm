"""Security reporting: daily/monthly summaries and operational metrics."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import Asset, Segment
from app.models.base import AlertStatus, IncidentStatus, TrustState
from app.models.incident import Evidence, Incident, ResponseAction
from app.models.policy import AuditLog
from app.models.telemetry import Event


def _now() -> datetime:
    return datetime.now(UTC)


class ReportService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def summary(self, *, start: datetime, end: datetime, label: str, generated_by: str) -> dict[str, Any]:
        alerts = (
            self.db.execute(select(Alert).where(Alert.created_at >= start, Alert.created_at <= end)).scalars().all()
        )
        incidents = (
            self.db.execute(select(Incident).where(Incident.detected_at >= start, Incident.detected_at <= end))
            .scalars()
            .all()
        )
        events_count = int(
            self.db.execute(
                select(func.count(Event.id)).where(Event.ts >= start, Event.ts <= end)
            ).scalar_one()
        )
        actions = (
            self.db.execute(
                select(ResponseAction).where(ResponseAction.created_at >= start, ResponseAction.created_at <= end)
            )
            .scalars()
            .all()
        )
        evidence_count = int(
            self.db.execute(
                select(func.count(Evidence.id)).where(Evidence.collected_at >= start, Evidence.collected_at <= end)
            ).scalar_one()
        )

        by_rule: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        fp = 0
        for alert in alerts:
            by_rule[alert.rule_id] = by_rule.get(alert.rule_id, 0) + 1
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
            if alert.false_positive:
                fp += 1

        closed = [i for i in incidents if i.closed_at]
        mttr = [i.mttr_minutes for i in closed if i.mttr_minutes is not None]

        assets = self.db.execute(select(Asset)).scalars().all()
        compliant = [a for a in assets if a.trust_state == TrustState.TRUSTED and a.posture_score >= 60]

        return {
            "label": label,
            "generated_at": _now().isoformat(),
            "generated_by": generated_by,
            "window": {"start": start.isoformat(), "end": end.isoformat()},
            "events_ingested": events_count,
            "alerts": {
                "total": len(alerts),
                "by_severity": by_severity,
                "by_rule": dict(sorted(by_rule.items(), key=lambda kv: kv[1], reverse=True)[:10]),
                "false_positives": fp,
                "false_positive_rate": round(fp / len(alerts) * 100, 1) if alerts else 0.0,
                "open": len([a for a in alerts if a.status != AlertStatus.CLOSED]),
            },
            "incidents": {
                "total": len(incidents),
                "open": len([i for i in incidents if i.status != IncidentStatus.CLOSED]),
                "closed": len(closed),
                "mttr_minutes": round(sum(mttr) / len(mttr), 1) if mttr else None,
                "by_severity": _tally(i.severity for i in incidents),
            },
            "response_actions": {
                "total": len(actions),
                "succeeded": len([a for a in actions if a.status == "succeeded"]),
                "simulated": len([a for a in actions if a.mode == "simulated"]),
            },
            "evidence_collected": evidence_count,
            "device_compliance": {
                "total_assets": len(assets),
                "compliant": len(compliant),
                "unknown": len([a for a in assets if a.trust_state == TrustState.UNKNOWN]),
                "quarantined": len([a for a in assets if a.trust_state == TrustState.QUARANTINED]),
                "compliance_percent": round(len(compliant) / len(assets) * 100, 1) if assets else 0.0,
            },
            "sensor_coverage": self._coverage(),
            "administrative_activity": self._admin_activity(start, end),
            "caveats": [
                "Counts reflect telemetry actually ingested; unmonitored segments are invisible to these figures.",
                "A low alert count is not evidence of a low-risk environment.",
            ],
        }

    def _coverage(self) -> dict[str, Any]:
        segments = self.db.execute(select(Segment)).scalars().all()
        assets = self.db.execute(select(Asset)).scalars().all()
        per_segment = []
        for segment in segments:
            members = [a for a in assets if a.segment_id == segment.id]
            enrolled = [a for a in members if a.enrolled]
            per_segment.append(
                {
                    "segment": segment.name,
                    "cidr": segment.cidr,
                    "monitored": segment.monitored,
                    "devices": len(members),
                    "enrolled_percent": round(len(enrolled) / len(members) * 100, 1) if members else 0.0,
                }
            )
        enrolled_total = len([a for a in assets if a.enrolled])
        return {
            "segments": len(segments),
            "per_segment": per_segment,
            "enrolled_percent": round(enrolled_total / len(assets) * 100, 1) if assets else 0.0,
        }

    def _admin_activity(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(AuditLog.action, func.count(AuditLog.id))
            .where(AuditLog.ts >= start, AuditLog.ts <= end)
            .group_by(AuditLog.action)
            .order_by(func.count(AuditLog.id).desc())
            .limit(15)
        ).all()
        return [{"action": action, "count": int(count)} for action, count in rows]

    def daily(self, day: date | None = None) -> dict[str, Any]:
        day = day or _now().date()
        start = datetime(day.year, day.month, day.day, tzinfo=UTC)
        end = start + timedelta(days=1)
        return self.summary(start=start, end=end, label=f"Daily summary {day}", generated_by="report-service")

    def monthly(self, year: int | None = None, month: int | None = None) -> dict[str, Any]:
        now = _now()
        year = year or now.year
        month = month or now.month
        start = datetime(year, month, 1, tzinfo=UTC)
        end = datetime(year + (month // 12), (month % 12) + 1, 1, tzinfo=UTC)
        return self.summary(start=start, end=end, label=f"Monthly summary {year}-{month:02d}", generated_by="report-service")

    def render_markdown(self, report: dict[str, Any]) -> str:
        """Render a report as Markdown for download or email attachment."""
        lines = [
            f"# FIRESTORM - {report['label']}",
            "",
            f"Generated: {report['generated_at']} by {report['generated_by']}",
            f"Window: {report['window']['start']} to {report['window']['end']}",
            "",
            "## Alerts",
            f"- Total: {report['alerts']['total']}",
            f"- Open: {report['alerts']['open']}",
            f"- False positives: {report['alerts']['false_positives']} ({report['alerts']['false_positive_rate']}%)",
        ]
        for severity, count in report["alerts"]["by_severity"].items():
            lines.append(f"  - {severity}: {count}")
        lines += ["", "## Incidents", f"- Total: {report['incidents']['total']}",
                  f"- Closed: {report['incidents']['closed']}",
                  f"- Mean time to resolve: {report['incidents']['mttr_minutes']} minutes", "",
                  "## Devices", f"- Assets: {report['device_compliance']['total_assets']}",
                  f"- Compliant: {report['device_compliance']['compliant']}",
                  f"- Unknown: {report['device_compliance']['unknown']}", "",
                  "## Response actions",
                  f"- Total: {report['response_actions']['total']}",
                  f"- Simulated: {report['response_actions']['simulated']}", "",
                  "## Caveats"]
        lines += [f"- {c}" for c in report["caveats"]]
        return "\n".join(lines)


def _tally(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out
