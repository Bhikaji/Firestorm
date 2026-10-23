from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import (
    ActionStatus,
    IncidentStatus,
    Severity,
    StringIdMixin,
    TimestampMixin,
    UTCDateTime,
    utcnow,
)


class Incident(StringIdMixin, TimestampMixin, Base):
    __tablename__ = "incidents"

    reference: Mapped[str] = mapped_column(String(24), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(220), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.HIGH, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default=IncidentStatus.NEW, nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    contained_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Facts vs hypotheses are stored separately and rendered distinctly.
    observed_facts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    hypotheses: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    affected_asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    affected_accounts: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    post_incident_review: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary_report: Mapped[str | None] = mapped_column(Text, nullable=True)

    @property
    def mttr_minutes(self) -> float | None:
        if not self.closed_at:
            return None
        return round((self.closed_at - self.detected_at).total_seconds() / 60, 1)


class IncidentTimelineEvent(StringIdMixin, Base):
    """Append-only incident timeline."""

    __tablename__ = "incident_timeline"

    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # detection|action|note|status|evidence|notification
    actor: Mapped[str] = mapped_column(String(160), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class Evidence(StringIdMixin, TimestampMixin, Base):
    """Evidence record with content hash and chain-of-custody metadata."""

    __tablename__ = "evidence"

    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True, nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # event_bundle|file_hash|email_header|pcap_ref|screenshot
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    collected_by: Mapped[str] = mapped_column(String(160), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    source: Mapped[str] = mapped_column(String(120), default="firestorm", nullable=False)
    custody: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    sealed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ResponseAction(StringIdMixin, TimestampMixin, Base):
    """A containment action with approval + execution audit trail."""

    __tablename__ = "response_actions"

    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True, nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    action_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default=ActionStatus.PENDING_APPROVAL, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(36), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    reverted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    integration: Mapped[str | None] = mapped_column(String(60), nullable=True)
    mode: Mapped[str] = mapped_column(String(20), default="simulated", nullable=False)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    reversible: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class EnforcementRecord(StringIdMixin, TimestampMixin, Base):
    """Currently-applied enforcement state (firewall blocks, VLAN moves, isolates).

    Keeping the applied state in the database makes containment reversible and
    auditable, and lets recovery tooling enumerate everything that is still in
    force - including after a restart.
    """

    __tablename__ = "enforcement_records"

    action_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)  # firewall_block|vlan_move|endpoint_isolate|dns_sinkhole|account_disable
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    integration: Mapped[str] = mapped_column(String(60), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="simulated", nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="applied", nullable=False, index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    reverted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
