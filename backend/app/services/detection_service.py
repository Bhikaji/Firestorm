"""Telemetry ingestion -> detection -> risk -> alert -> notification pipeline.

The pipeline is synchronous on purpose for a single-node deployment: it keeps
ordering obvious and makes tests deterministic. For higher throughput the same
class is invoked by a worker consuming a bounded queue (see
``app/workers/queue.py``); ingestion itself is idempotent on the event
fingerprint so at-least-once delivery is safe.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, Suppression
from app.models.asset import Asset
from app.models.base import AlertStatus, IncidentStatus, Severity
from app.models.incident import Incident, IncidentTimelineEvent
from app.models.telemetry import Event
from app.schemas.telemetry import EventIn
from app.services.audit_service import AuditService
from app.services.detection_rules import Detection, EventContext, evaluate
from app.services.notification_service import NotificationService
from app.services.risk_engine import RiskEngine, severity_for_score
from app.services.threat_intel import IndicatorMatch, ThreatIntelService

logger = logging.getLogger("firestorm.detection")

DEDUPE_WINDOW_MINUTES = 15
CORRELATION_WINDOW_MINUTES = 30
CRITICAL_INCIDENT_SCORE = 80


def fingerprint_for(payload: EventIn) -> str:
    if payload.external_id:
        basis = f"{payload.source}|{payload.sensor or '-'}|{payload.external_id}"
    else:
        basis = "|".join(
            str(part)
            for part in (
                payload.source,
                payload.sensor,
                payload.event_type,
                payload.ts.isoformat() if payload.ts else "",
                payload.src_ip,
                payload.dst_ip,
                payload.src_port,
                payload.dst_port,
                payload.signature,
                payload.file_hash,
                payload.username,
                payload.dns_query,
                payload.bytes_out,
            )
        )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


class DetectionService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.intel = ThreatIntelService(db)
        self.notifications = NotificationService(db)
        self.audit = AuditService(db)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def ingest(self, payload: EventIn, *, commit: bool = True) -> tuple[Event | None, list[Alert]]:
        fp = fingerprint_for(payload)
        existing = self.db.execute(select(Event).where(Event.fingerprint == fp)).scalars().first()
        if existing is not None:
            return None, []

        asset = self._resolve_asset(payload)
        event = Event(
            **payload.model_dump(exclude={"raw", "external_id"}),
            raw=payload.raw or {},
            fingerprint=fp,
            asset_id=asset.id if asset else None,
        )
        self.db.add(event)
        self.db.flush()

        alerts = self._process(event, asset)
        event.processed = True
        if asset:
            asset.last_seen_at = event.ts or _now()
        if commit:
            self.db.commit()
        return event, alerts

    def ingest_batch(self, payloads: Sequence[EventIn]) -> dict[str, Any]:
        accepted = duplicates = rejected = 0
        alerts_created = 0
        errors: list[str] = []
        seen: set[str] = set()
        for payload in payloads:
            fp = fingerprint_for(payload)
            if fp in seen:
                duplicates += 1
                continue
            seen.add(fp)
            try:
                event, alerts = self.ingest(payload, commit=False)
            except Exception as exc:  # noqa: BLE001 - one bad event must not kill the batch
                rejected += 1
                errors.append(f"{payload.event_type}: {type(exc).__name__}")
                continue
            if event is None:
                duplicates += 1
            else:
                accepted += 1
                alerts_created += len(alerts)
        self.db.commit()
        return {
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected,
            "alerts_created": alerts_created,
            "errors": errors[:10],
        }

    def _resolve_asset(self, payload: EventIn) -> Asset | None:
        stmt = None
        if payload.hostname:
            stmt = select(Asset).where(func.lower(Asset.hostname) == payload.hostname.lower())
        if stmt is None and payload.src_ip:
            stmt = select(Asset).where(Asset.ip_address == payload.src_ip)
        if stmt is None:
            return None
        asset = self.db.execute(stmt.limit(1)).scalars().first()
        if asset and payload.src_ip and asset.ip_address != payload.src_ip:
            # IP churn is normal (DHCP); hostname match wins but we note the drift.
            asset.tags = {**(asset.tags or {}), "ip_drift_from": asset.ip_address, "ip_drift_to": payload.src_ip}
        return asset

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    def _related(self, event: Event) -> list[Event]:
        window_start = (event.ts or _now()) - timedelta(minutes=CORRELATION_WINDOW_MINUTES)
        stmt = select(Event).where(Event.ts >= window_start, Event.id != event.id)
        if event.src_ip:
            stmt = stmt.where(Event.src_ip == event.src_ip)
        elif event.asset_id:
            stmt = stmt.where(Event.asset_id == event.asset_id)
        else:
            return []
        return list(self.db.execute(stmt.order_by(Event.ts.desc()).limit(400)).scalars().all())

    def _threat_match(self, event: Event) -> IndicatorMatch | None:
        for probe in (
            self.intel.lookup_hash(event.file_hash),
            self.intel.lookup_domain(event.dns_query),
            self.intel.lookup_domain(event.http_host),
            self.intel.lookup_ip(event.dst_ip),
            self.intel.lookup_ip(event.src_ip),
            self.intel.lookup_url(event.url),
        ):
            if probe:
                return probe
        return None

    def _process(self, event: Event, asset: Asset | None) -> list[Alert]:
        threat_match = self._threat_match(event)
        ctx = EventContext(
            event=event,
            related=self._related(event),
            asset_criticality=asset.criticality if asset else 3,
            asset_trust_state=asset.trust_state if asset else "unknown",
            asset_id=asset.id if asset else None,
            threat_match=threat_match,
        )
        detections = evaluate(ctx)
        if not detections:
            return []

        alerts: list[Alert] = []
        for detection in detections:
            if self._is_suppressed(detection, asset):
                continue
            alert = self._upsert_alert(detection, event, asset, threat_match)
            event.risk_score = max(event.risk_score, alert.risk_score)
            event.alert_id = alert.id
            alerts.append(alert)
        return alerts

    def _is_suppressed(self, detection: Detection, asset: Asset | None) -> bool:
        now = _now()
        rows = (
            self.db.execute(
                select(Suppression).where(
                    Suppression.active.is_(True),
                    Suppression.expires_at > now,
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            if row.fingerprint and row.fingerprint != detection.fingerprint:
                continue
            if row.rule_id and row.rule_id != detection.rule_id:
                continue
            if row.asset_id and (asset is None or row.asset_id != asset.id):
                continue
            if any((row.fingerprint, row.rule_id, row.asset_id)):
                return True
        return False

    def _historical_context(self, asset_id: str | None) -> tuple[int, int]:
        if not asset_id:
            return 0, 0
        since = _now() - timedelta(days=7)
        alert_count = self.db.execute(
            select(func.count(Alert.id)).where(Alert.asset_id == asset_id, Alert.created_at >= since)
        ).scalar_one()
        incident_count = self.db.execute(
            select(func.count(Incident.id)).where(Incident.detected_at >= since)
        ).scalar_one()
        return int(alert_count), min(int(incident_count), 2)

    def _upsert_alert(
        self,
        detection: Detection,
        event: Event,
        asset: Asset | None,
        threat_match: IndicatorMatch | None,
    ) -> Alert:
        # Dedupe on fingerprint, tolerant of late/out-of-order delivery: an
        # alert is the same incident if it is close to the event timestamp OR
        # was refreshed within the window in real time.
        now = _now()
        window = timedelta(minutes=DEDUPE_WINDOW_MINUTES)
        existing = self.db.execute(
            select(Alert)
            .where(
                Alert.fingerprint == detection.fingerprint,
                Alert.last_seen >= (event.ts or now) - window,
                Alert.last_seen <= (event.ts or now) + window,
            )
            .order_by(Alert.last_seen.desc())
        ).scalars().first()
        if existing is None:
            existing = self.db.execute(
                select(Alert)
                .where(
                    Alert.fingerprint == detection.fingerprint,
                    Alert.last_seen >= now - window,
                )
                .order_by(Alert.last_seen.desc())
            ).scalars().first()

        hist_alerts, hist_incidents = self._historical_context(asset.id if asset else None)
        engine = RiskEngine(
            historical_alert_count=hist_alerts,
            asset_criticality=asset.criticality if asset else 3,
            asset_trust_state=asset.trust_state if asset else "unknown",
            recent_incidents=hist_incidents,
        )

        if existing is not None:
            # Deduplicate: bump counters, refresh score, do not re-notify.
            existing.occurrence_count += 1
            existing.last_seen = max(existing.last_seen, event.ts)
            existing.first_seen = min(existing.first_seen, event.ts)
            risk = engine.score(
                severity=existing.severity,
                confidence=existing.confidence,
                signals=existing.signals,
                repeat_count=existing.occurrence_count,
            )
            existing.risk_score = risk.score
            existing.signals = risk.signals
            self.db.flush()
            return existing

        risk = engine.score(
            severity=detection.severity,
            confidence=detection.confidence,
            signals=detection.signals,
        )
        severity = severity_for_score(risk.score)
        alert = Alert(
            code=detection.code,
            title=detection.title,
            description=detection.description,
            severity=severity,
            confidence=detection.confidence,
            risk_score=risk.score,
            status=AlertStatus.OPEN,
            rule_id=detection.rule_id,
            rule_version="1.0.0",
            detection_source=event.source,
            fingerprint=detection.fingerprint,
            first_seen=event.ts,
            last_seen=event.ts,
            asset_id=asset.id if asset else detection.asset_id,
            src_ip=detection.src_ip,
            dst_ip=detection.dst_ip,
            dst_port=detection.dst_port,
            dns_query=detection.dns_query,
            signals=risk.signals,
            ttps=detection.ttps,
            recommended_actions=detection.recommended_actions,
            evidence_refs=[],
        )
        self.db.add(alert)
        self.db.flush()
        event.alert_id = alert.id

        self._record_detection_audit(alert, event, risk.explanation)

        if risk.score >= CRITICAL_INCIDENT_SCORE:
            incident = self._open_incident(alert, asset)
            alert.incident_id = incident.id

        body = (
            f"{alert.title}\n\n"
            f"Risk score: {alert.risk_score}/100 ({risk.band})\n"
            f"Confidence: {alert.confidence:.0%} | Severity: {alert.severity}\n"
            f"Detection: {alert.rule_id} via {alert.detection_source}\n"
            f"Source: {alert.src_ip or 'n/a'} -> {alert.dst_ip or 'n/a'}"
            f"{':' + str(alert.dst_port) if alert.dst_port else ''}\n"
            f"Explanation: {risk.explanation}\n\n"
            "Open FIRESTORM COMMAND for evidence and response options."
        )
        self.notifications.notify_alert(
            alert_id=alert.id,
            incident_id=alert.incident_id,
            title=alert.title,
            body=body,
            severity=alert.severity,
        )
        if asset and severity == Severity.CRITICAL:
            asset.tags = {**(asset.tags or {}), "last_critical_alert": alert.id}

        # Attribute the score band to the alert for the UI.
        alert.signals = risk.signals
        self.db.flush()
        return alert

    def _record_detection_audit(self, alert: Alert, event: Event, explanation: str) -> None:
        self.audit.record(
            action="alert.created",
            actor_email="detection-engine",
            actor_role="system",
            object_type="alert",
            object_id=alert.id,
            detail={
                "rule_id": alert.rule_id,
                "risk_score": alert.risk_score,
                "explanation": explanation,
                "event_id": event.id,
            },
        )

    def _open_incident(self, alert: Alert, asset: Asset | None) -> Incident:
        reference = f"INC-{_now():%Y%m%d}-{alert.id[:6].upper()}"
        incident = Incident(
            reference=reference,
            title=f"Critical: {alert.title}",
            summary=(
                f"Automatically opened from alert {alert.id} (rule {alert.rule_id}, "
                f"risk {alert.risk_score}/100). Requires analyst validation; automation "
                "has not confirmed compromise."
            ),
            severity=Severity.CRITICAL,
            status=IncidentStatus.NEW,
            risk_score=alert.risk_score,
            detected_at=alert.first_seen,
            observed_facts=[
                {
                    "fact": "Alert raised by detection engine",
                    "detail": alert.title,
                    "source": f"{alert.rule_id} v{alert.rule_version}",
                },
                {
                    "fact": "Network endpoints observed",
                    "detail": f"{alert.src_ip or 'unknown'} -> {alert.dst_ip or 'unknown'}"
                    + (f":{alert.dst_port}" if alert.dst_port else ""),
                },
            ],
            hypotheses=[
                {
                    "hypothesis": "Device may be compromised and requires validation",
                    "confidence": round(alert.confidence, 2),
                    "status": "unverified",
                }
            ],
            affected_asset_ids=[asset.id] if asset else [],
        )
        self.db.add(incident)
        self.db.flush()
        self.db.add(
            IncidentTimelineEvent(
                incident_id=incident.id,
                ts=_now(),
                kind="detection",
                actor="detection-engine",
                message=f"Incident opened from alert {alert.id}",
                payload={"alert_id": alert.id, "rule_id": alert.rule_id, "risk_score": alert.risk_score},
            )
        )
        self.audit.record(
            action="incident.auto_opened",
            actor_email="detection-engine",
            actor_role="system",
            object_type="incident",
            object_id=incident.id,
            detail={"alert_id": alert.id, "reference": reference},
        )
        self.db.flush()
        return incident
