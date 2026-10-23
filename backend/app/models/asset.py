from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import StringIdMixin, TimestampMixin, TrustState, UTCDateTime


class Segment(StringIdMixin, TimestampMixin, Base):
    """A monitored, authorised network segment."""

    __tablename__ = "segments"

    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sensitivity: Mapped[str] = mapped_column(String(20), default="standard", nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    monitored: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    assets: Mapped[list[Asset]] = relationship(back_populates="segment")


class Asset(StringIdMixin, TimestampMixin, Base):
    """A device on an authorised segment.

    Identity is deliberately multi-signal: IP and MAC alone are never treated
    as proof of identity (both are spoofable).
    """

    __tablename__ = "assets"

    hostname: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(17), index=True, nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    device_type: Mapped[str] = mapped_column(String(40), default="workstation", nullable=False)
    os_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(160), nullable=True)
    department: Mapped[str | None] = mapped_column(String(120), nullable=True)
    segment_id: Mapped[str | None] = mapped_column(ForeignKey("segments.id"), index=True, nullable=True)
    criticality: Mapped[int] = mapped_column(Integer, default=3, nullable=False)  # 1 low .. 5 business critical
    trust_state: Mapped[str] = mapped_column(String(20), default=TrustState.UNKNOWN, nullable=False, index=True)
    enrolled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Endpoint posture (reported by an EDR/Wazuh/OSQuery agent)
    agent_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    edr_status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    patch_level: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    firewall_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    disk_encrypted: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    posture_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_posture_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, index=True)
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    quarantined_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    tags: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    segment: Mapped[Segment | None] = relationship(back_populates="assets")

    @property
    def risk_rank(self) -> int:
        return int(self.criticality)
