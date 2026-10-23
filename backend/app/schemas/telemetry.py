from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.common import ORMModel


class EventIn(BaseModel):
    """Normalised event accepted by the ingestion API.

    Sensors post either this schema or, via their own adapters, the vendor
    payload which the adapter maps to this schema.
    """

    source: str = Field(max_length=40)
    sensor: str | None = Field(default=None, max_length=120)
    event_type: str = Field(min_length=1, max_length=60, pattern=r"^[a-z0-9_.:-]+$")
    severity: str = Field(default="info", pattern=r"^(info|low|medium|high|critical)$")
    ts: datetime | None = None
    src_ip: str | None = Field(default=None, max_length=45)
    dst_ip: str | None = Field(default=None, max_length=45)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=20)
    bytes_in: int = Field(default=0, ge=0, le=10**13)
    bytes_out: int = Field(default=0, ge=0, le=10**13)
    packets: int = Field(default=0, ge=0, le=10**12)
    duration_ms: int | None = Field(default=None, ge=0, le=86_400_000)
    dns_query: str | None = Field(default=None, max_length=255)
    http_host: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    username: str | None = Field(default=None, max_length=160)
    hostname: str | None = Field(default=None, max_length=160)
    file_hash: str | None = Field(default=None, max_length=64, pattern=r"^[a-fA-F0-9]{32,64}$")
    file_name: str | None = Field(default=None, max_length=255)
    signature: str | None = Field(default=None, max_length=255)
    action: str | None = Field(default=None, max_length=40)
    raw: dict[str, Any] = {}
    external_id: str | None = Field(default=None, max_length=128)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        if not value:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc

    @field_validator("url")
    @classmethod
    def _no_control_chars(cls, value: str | None) -> str | None:
        if value and any(ord(c) < 32 for c in value):
            raise ValueError("must not contain control characters")
        return value

    @model_validator(mode="after")
    def _default_ts(self) -> EventIn:
        if self.ts is None:
            self.ts = datetime.now(UTC)
        elif self.ts.tzinfo is None:
            self.ts = self.ts.replace(tzinfo=UTC)
        return self


class EventOut(ORMModel):
    id: str
    ts: datetime
    received_at: datetime
    source: str
    sensor: str | None
    event_type: str
    severity: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    bytes_in: int
    bytes_out: int
    packets: int
    dns_query: str | None
    http_host: str | None
    username: str | None
    hostname: str | None
    file_hash: str | None
    signature: str | None
    action: str | None
    risk_score: int
    asset_id: str | None
    alert_id: str | None


class EventDetail(EventOut):
    url: str | None
    file_name: str | None
    duration_ms: int | None
    raw: dict[str, Any]
    fingerprint: str
    processed: bool


class BatchIngestResult(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    alerts_created: int
    errors: list[str] = []


class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _limit(self) -> EventBatch:
        if len(self.events) > 500:  # defensive: Field max_length covers it
            raise ValueError("batch too large")
        return self
