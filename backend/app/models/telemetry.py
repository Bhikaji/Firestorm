from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.base import Severity, StringIdMixin, UTCDateTime, new_id, utcnow


class Event(StringIdMixin, Base):
    """Normalised telemetry from sensors, agents and integrations.

    Raw payloads are retained in ``raw`` for investigation. Ingestion is
    idempotent on ``fingerprint`` (source + sensor event id or a hash of the
    normalised fields), so retries from a sensor never double-count.
    """

    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_ts_type", "ts", "event_type"),
        Index("ix_events_src_ts", "src_ip", "ts"),
        Index("ix_events_dst_ts", "dst_ip", "ts"),
        Index("ix_events_alert", "alert_id"),
    )

    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False, index=True)  # suricata|zeek|wazuh|osquery|antivirus|firewall|firestorm
    sensor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.INFO, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    packets: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dns_query: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    username: Mapped[str | None] = mapped_column(String(160), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(160), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), index=True, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    signature: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str | None] = mapped_column(String(40), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("id", new_id())
        super().__init__(**kwargs)
