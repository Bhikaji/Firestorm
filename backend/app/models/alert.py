from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import AlertStatus, Severity, StringIdMixin, TimestampMixin, UTCDateTime, utcnow


class Alert(StringIdMixin, TimestampMixin, Base):
    """A deduplicated detection result with an explainable risk score."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_sev", "status", "severity"),
        Index("ix_alerts_fp_window", "fingerprint", "last_seen"),
    )

    code: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(220), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.MEDIUM, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default=AlertStatus.OPEN, nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(20), default="1.0.0", nullable=False)
    detection_source: Mapped[str] = mapped_column(String(60), default="firestorm", nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dns_query: Mapped[str | None] = mapped_column(String(255), nullable=True)

    signals: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    ttps: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    suppressed_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class Suppression(StringIdMixin, TimestampMixin, Base):
    """Time-boxed alert suppression. Always expires: no permanent mutes."""

    __tablename__ = "suppressions"

    fingerprint: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
