"""Aggregations for the FIRESTORM COMMAND dashboard.

All figures come from the database with explicit time windows. When the demo
dataset is loaded the API marks responses with ``demo: true`` so the UI can
label simulated demonstration data.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.integrations.registry import registry
from app.models.alert import Alert
from app.models.asset import Asset, Segment
from app.models.base import AlertStatus, IncidentStatus, Severity, TrustState
from app.models.incident import Incident, ResponseAction
from app.models.policy import AdmissionRule, Notification
from app.models.telemetry import Event
from app.models.user import User
from app.services.detection_rules import rules_catalog
from app.services.threat_intel import ThreatIntelService


def _now() -> datetime:
    return datetime.now(UTC)


def _count(db: Session, stmt) -> int:
    return int(db.execute(stmt).scalar_one() or 0)


class DashboardService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- overview -------------------------------------------------------
    def overview(self) -> dict[str, Any]:
        now = _now()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)

        assets_total = _count(self.db, select(func.count(Asset.id)))
        unknown_assets = _count(
            self.db, select(func.count(Asset.id)).where(Asset.trust_state == TrustState.UNKNOWN)
        )
        quarantined = _count(
            self.db, select(func.count(Asset.id)).where(Asset.trust_state == TrustState.QUARANTINED)
        )
        high_risk_assets = _count(
            self.db, select(func.count(Asset.id)).where(Asset.trust_state.in_([TrustState.COMPROMISED, TrustState.NONCOMPLIANT]))
        )
        open_alerts = _count(
            self.db,
            select(func.count(Alert.id)).where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING])),
        )
        critical_alerts = _count(
            self.db,
            select(func.count(Alert.id)).where(
                Alert.severity == Severity.CRITICAL,
                Alert.status != AlertStatus.CLOSED,
            ),
        )
        active_incidents = _count(
            self.db, select(func.count(Incident.id)).where(Incident.status != IncidentStatus.CLOSED)
        )
        events_24h = _count(self.db, select(func.count(Event.id)).where(Event.ts >= day_ago))
        pending_approvals = _count(
            self.db, select(func.count(ResponseAction.id)).where(ResponseAction.status == "pending_approval")
        )

        # Posture: share of devices that are trusted and compliant.
        compliant = _count(
            self.db,
            select(func.count(Asset.id)).where(
                Asset.trust_state == TrustState.TRUSTED, Asset.posture_score >= 60
            ),
        )
        posture_score = round((compliant / assets_total) * 100) if assets_total else 0

        last_event = self.db.execute(select(Event.ts).order_by(Event.ts.desc()).limit(1)).scalar_one_or_none()
        stale = None
        if last_event:
            stale = (now - last_event).total_seconds() > 900

        return {
            "generated_at": now.isoformat(),
            "demo": settings.demo_data,
            "posture": {
                "score": posture_score,
                "label": (
                    "Healthy" if posture_score >= 80 else
                    "Guarded" if posture_score >= 60 else
                    "Degraded" if posture_score >= 40 else
                    "Critical"
                ),
                "trusted": compliant,
                "unknown": unknown_assets,
                "quarantined": quarantined,
            },
            "counts": {
                "segments": _count(self.db, select(func.count(Segment.id))),
                "assets": assets_total,
                "unknown_assets": unknown_assets,
                "high_risk_assets": high_risk_assets,
                "open_alerts": open_alerts,
                "critical_alerts": critical_alerts,
                "active_incidents": active_incidents,
                "events_24h": events_24h,
                "pending_approvals": pending_approvals,
            },
            "freshness": {
                "last_event_at": last_event.isoformat() if last_event else None,
                "stale": stale,
                "stale_after_seconds": 900,
            },
            "window": {"events_since": day_ago.isoformat(), "trend_since": week_ago.isoformat()},
        }

    # -- charts ---------------------------------------------------------
    def severity_distribution(self, hours: int = 24) -> list[dict[str, Any]]:
        since = _now() - timedelta(hours=hours)
        rows = self.db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.created_at >= since)
            .group_by(Alert.severity)
        ).all()
        counts = {row[0]: int(row[1]) for row in rows}
        return [
            {"severity": level, "count": counts.get(level, 0)}
            for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        ]

    def alert_trend(self, days: int = 7) -> list[dict[str, Any]]:
        since = _now() - timedelta(days=days)
        rows = self.db.execute(
            select(func.date(Alert.created_at), Alert.severity, func.count(Alert.id))
            .where(Alert.created_at >= since)
            .group_by(func.date(Alert.created_at), Alert.severity)
            .order_by(func.date(Alert.created_at))
        ).all()
        buckets: dict[str, dict[str, Any]] = {}
        for day, severity, count in rows:
            key = str(day)
            buckets.setdefault(key, {"date": key, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
            buckets[key][severity] = int(count)
        return list(buckets.values())

    def trust_overview(self) -> list[dict[str, Any]]:
        rows = self.db.execute(select(Asset.trust_state, func.count(Asset.id)).group_by(Asset.trust_state)).all()
        counts = {row[0]: int(row[1]) for row in rows}
        return [{"state": state, "count": counts.get(state, 0)} for state in TrustState]

    def top_risky_assets(self, limit: int = 8) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(Alert.asset_id, func.max(Alert.risk_score), func.count(Alert.id))
            .where(Alert.asset_id.is_not(None), Alert.status != AlertStatus.CLOSED)
            .group_by(Alert.asset_id)
            .order_by(func.max(Alert.risk_score).desc())
            .limit(limit)
        ).all()
        out = []
        for asset_id, risk, alerts in rows:
            asset = self.db.get(Asset, asset_id)
            if not asset:
                continue
            out.append(
                {
                    "asset_id": asset.id,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "criticality": asset.criticality,
                    "trust_state": asset.trust_state,
                    "risk_score": int(risk),
                    "open_alerts": int(alerts),
                }
            )
        return out

    # -- topology -------------------------------------------------------
    def topology(self) -> dict[str, Any]:
        segments = self.db.execute(select(Segment)).scalars().all()
        assets = self.db.execute(select(Asset)).scalars().all()
        since = _now() - timedelta(hours=6)
        alerts = self.db.execute(
            select(Alert)
            .where(Alert.created_at >= since, Alert.status != AlertStatus.CLOSED)
            .order_by(Alert.risk_score.desc())
            .limit(120)
        ).scalars().all()

        nodes = [
            {
                "id": seg.id,
                "type": "segment",
                "label": seg.name,
                "cidr": seg.cidr,
                "sensitivity": seg.sensitivity,
                "device_count": len([a for a in assets if a.segment_id == seg.id]),
            }
            for seg in segments
        ]
        nodes += [
            {
                "id": asset.id,
                "type": "asset",
                "label": asset.hostname,
                "ip": asset.ip_address,
                "segment_id": asset.segment_id,
                "device_type": asset.device_type,
                "trust_state": asset.trust_state,
                "criticality": asset.criticality,
                "posture_score": asset.posture_score,
            }
            for asset in assets
        ]

        by_ip = {asset.ip_address: asset for asset in assets}
        links: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for alert in alerts:
            src = by_ip.get(alert.src_ip or "")
            dst = by_ip.get(alert.dst_ip or "")
            if not src and not dst:
                continue
            key = (src.id if src else alert.src_ip or "-", dst.id if dst else alert.dst_ip or "-")
            if key in seen:
                continue
            seen.add(key)
            links.append(
                {
                    "id": f"link-{alert.id[:8]}",
                    "source": key[0],
                    "target": key[1],
                    "suspicious": True,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "label": alert.title,
                    "alert_id": alert.id,
                }
            )
        for asset in assets:
            if asset.segment_id:
                links.append(
                    {
                        "id": f"seg-{asset.id[:8]}",
                        "source": asset.segment_id,
                        "target": asset.id,
                        "suspicious": asset.trust_state in {TrustState.QUARANTINED, TrustState.COMPROMISED},
                        "severity": "info",
                        "risk_score": 0,
                        "label": "member",
                    }
                )
        return {
            "nodes": nodes,
            "links": links,
            "external_note": "External addresses are shown as indicators only; geolocation is approximate and never proves identity.",
            "demo": settings.demo_data,
        }

    # -- live feed ------------------------------------------------------
    def recent_events(self, limit: int = 40) -> list[dict[str, Any]]:
        rows = self.db.execute(select(Event).order_by(Event.ts.desc()).limit(min(limit, 200))).scalars().all()
        return [
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
                "hostname": e.hostname,
                "risk_score": e.risk_score,
                "alert_id": e.alert_id,
                "signature": e.signature,
            }
            for e in rows
        ]

    def approaching_deadlines(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(Alert)
            .where(Alert.severity.in_([Severity.CRITICAL, Severity.HIGH]), Alert.status != AlertStatus.CLOSED)
            .order_by(Alert.risk_score.desc())
            .limit(limit)
        ).scalars().all()
        return [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "status": a.status,
                "first_seen": a.first_seen.isoformat(),
                "age_minutes": round((_now() - a.first_seen).total_seconds() / 60, 1),
                "assignee": a.assignee_id,
            }
            for a in rows
        ]

    # -- layer health ---------------------------------------------------
    def _platform_component(self, name: str, layer: str, status: str, detail: str) -> dict[str, Any]:
        return {
            "name": name,
            "kind": "platform",
            "layer": layer,
            "mode": "live",
            "enabled": True,
            "status": status,
            "detail": detail,
            "latency_ms": None,
            "checked_at": _now().isoformat(),
        }

    def protection_layers(self) -> list[dict[str, Any]]:
        """The eight defence layers, each with its real components and state.

        Platform-native components are computed from the database so the view
        never implies a control exists when it does not. A layer with no
        configured control reports ``not_configured``, and a layer with any
        unconfigured or degraded component is never reported ``healthy``.
        """
        health = registry().health()
        by_layer: dict[str, list[dict[str, Any]]] = {}
        for item in health:
            by_layer.setdefault(item["layer"], []).append(item)

        now = _now()
        day_ago = now - timedelta(hours=24)
        intel = ThreatIntelService(self.db)

        assets_total = _count(self.db, select(func.count(Asset.id)))
        enrolled = _count(self.db, select(func.count(Asset.id)).where(Asset.enrolled.is_(True)))
        segments_total = _count(self.db, select(func.count(Segment.id)))
        posture_assets = _count(self.db, select(func.count(Asset.id)).where(Asset.posture_score.is_not(None)))
        admission_rules = _count(self.db, select(func.count(AdmissionRule.id)))
        events_24h = _count(self.db, select(func.count(Event.id)).where(Event.received_at >= day_ago))
        last_event = self.db.execute(select(func.max(Event.received_at))).scalar_one()

        east_west = _count(
            self.db,
            select(func.count(Event.id))
            .where(Event.received_at >= day_ago)
            .where(Event.src_ip.is_not(None))
            .where(Event.dst_ip.is_not(None))
            .where(Event.src_ip.like("10.%"))
            .where(Event.dst_ip.like("10.%")),
        )
        admins = _count(
            self.db,
            select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True)),
        )
        open_incidents = _count(
            self.db, select(func.count(Incident.id)).where(Incident.status != IncidentStatus.CLOSED)
        )
        notifications_queued = _count(
            self.db, select(func.count(Notification.id)).where(Notification.status.in_(["queued", "retrying"]))
        )
        notifications_failed = _count(
            self.db, select(func.count(Notification.id)).where(Notification.status == "failed")
        )
        detection_rules = len(rules_catalog())

        flow_status = "healthy" if events_24h else "degraded"
        flow_detail = (
            f"{events_24h} event(s) in 24h; last receipt {last_event.isoformat() if last_event else 'never'}"
        )
        identity_status = "healthy" if assets_total and enrolled else "degraded"
        identity_detail = f"{assets_total} asset(s) inventoried, {enrolled} enrolled for identity signals"
        posture_status = "healthy" if admission_rules and posture_assets else "degraded"
        posture_detail = f"{posture_assets} asset(s) with posture data, {admission_rules} admission rule(s)"
        east_west_status = "healthy" if east_west else "degraded"
        east_west_detail = (
            f"{east_west} internal-to-internal connection(s) in 24h across {segments_total} segment(s)"
            if segments_total
            else "no segments defined; east-west visibility is unverified"
        )
        approval_status = "healthy" if admins >= 2 else "degraded"
        approval_detail = (
            f"{admins} active admin(s); four-eyes approval is enforceable"
            if admins >= 2
            else "fewer than two active admins: four-eyes approval cannot be satisfied"
        )
        if notifications_failed or (notifications_queued and not settings.smtp_host):
            notification_status = "degraded"
        elif notifications_queued:
            notification_status = "partial"
        else:
            notification_status = "healthy"

        layers = [
            {
                "id": "layer-1",
                "name": "Layer 1 - Network visibility",
                "description": "Flow, DNS and sensor telemetry from approved segments.",
                "components": [
                    *by_layer.get("layer-1", []),
                    self._platform_component("Telemetry pipeline", "layer-1", flow_status, flow_detail),
                ],
            },
            {
                "id": "layer-2",
                "name": "Layer 2 - Device identity",
                "description": "Inventory and multi-signal identity instead of IP/MAC trust.",
                "components": [
                    *by_layer.get("layer-2", []),
                    self._platform_component("Asset inventory", "layer-2", identity_status, identity_detail),
                ],
            },
            {
                "id": "layer-3",
                "name": "Layer 3 - Pre-access posture",
                "description": "Enrolment, posture scoring and fail-closed admission decisions.",
                "components": [
                    *by_layer.get("layer-3", []),
                    self._platform_component("Admission engine", "layer-3", posture_status, posture_detail),
                ],
            },
            {
                "id": "layer-4",
                "name": "Layer 4 - Malware scanning",
                "description": "Signature and pattern scanning through maintained engines.",
                "components": [*by_layer.get("layer-4", [])],
            },
            {
                "id": "layer-5",
                "name": "Layer 5 - IDS/IPS",
                "description": "Network and host intrusion detection with deterministic rules.",
                "components": [
                    *by_layer.get("layer-5", []),
                    self._platform_component(
                        "Detection rule engine",
                        "layer-5",
                        "healthy",
                        f"{detection_rules} deterministic rule(s); {intel.active_count()} active indicator(s)",
                    ),
                ],
            },
            {
                "id": "layer-6",
                "name": "Layer 6 - East-west movement",
                "description": "Internal-only telemetry, segmentation and lateral-movement analytics.",
                "components": [
                    self._platform_component("Lateral-movement analytics", "layer-6", east_west_status, east_west_detail),
                ],
            },
            {
                "id": "layer-7",
                "name": "Layer 7 - Automated containment",
                "description": "Firewall, NAC, endpoint isolation and identity actions with approvals.",
                "components": [
                    *by_layer.get("layer-7", []),
                    self._platform_component("Approval workflow", "layer-7", approval_status, approval_detail),
                ],
            },
            {
                "id": "layer-8",
                "name": "Layer 8 - SOC and recovery",
                "description": "Incident workflow, evidence custody, notification and audit integrity.",
                "components": [
                    self._platform_component(
                        "Incident workflow",
                        "layer-8",
                        "healthy" if open_incidents or events_24h else "degraded",
                        f"{open_incidents} open incident(s)",
                    ),
                    self._platform_component(
                        "Notification delivery",
                        "layer-8",
                        notification_status,
                        f"{notifications_queued} queued, {notifications_failed} failed"
                        + ("" if settings.smtp_host else "; email channel not configured"),
                    ),
                ],
            },
        ]

        for layer in layers:
            statuses = [c["status"] for c in layer["components"]]
            if not statuses or all(s == "not_configured" for s in statuses):
                layer["status"] = "not_configured"
            elif any(s == "unavailable" for s in statuses):
                layer["status"] = "degraded"
            elif all(s == "simulated" for s in statuses):
                layer["status"] = "simulated"
            elif any(s in {"degraded", "not_configured"} for s in statuses):
                # A layer is only as good as its weakest configured component: an
                # unconfigured sensor must never be reported as healthy coverage.
                layer["status"] = "degraded"
            elif any(s == "simulated" for s in statuses):
                layer["status"] = "partial"
            else:
                layer["status"] = "healthy"
        return layers
