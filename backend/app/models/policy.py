from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import StringIdMixin, TimestampMixin, UTCDateTime, utcnow


class Policy(StringIdMixin, TimestampMixin, Base):
    """Configuration-as-data for admission, risk, escalation and response."""

    __tablename__ = "policies"

    key: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(40), default="general", nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class AdmissionRule(StringIdMixin, TimestampMixin, Base):
    """Device admission rule, evaluated in priority order."""

    __tablename__ = "admission_rules"

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # condition: {"all": [{"field": "enrolled", "op": "eq", "value": true}, ...]}
    condition: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    # outcome: allow | restrict_remediation | deny | quarantine
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome_reason: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    min_posture_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class IntegrationConfig(StringIdMixin, TimestampMixin, Base):
    """Stored integration settings. Secrets live in the environment, never here."""

    __tablename__ = "integration_configs"

    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="simulated", nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(24), default="unknown", nullable=False)
    last_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(StringIdMixin, Base):
    """Append-only audit trail for admin and response activity."""

    __tablename__ = "audit_log"

    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor_email: Mapped[str] = mapped_column(String(320), default="system", nullable=False)
    actor_role: Mapped[str] = mapped_column(String(20), default="system", nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    object_type: Mapped[str] = mapped_column(String(60), default="", nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(20), default="success", nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Hash chain makes tampering with history detectable.
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class Notification(StringIdMixin, TimestampMixin, Base):
    __tablename__ = "notifications"

    channel: Mapped[str] = mapped_column(String(30), nullable=False)  # in_app|email|webhook
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ThreatIndicator(StringIdMixin, TimestampMixin, Base):
    """Locally cached threat-intelligence indicator.

    Populated by the threat-intel service from signed feeds, or seeded with
    clearly-labelled lab indicators in demo mode.
    """

    __tablename__ = "threat_indicators"

    indicator: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # ip|domain|sha256|url
    category: Mapped[str] = mapped_column(String(60), default="unknown", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    source: Mapped[str] = mapped_column(String(80), default="local", nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
