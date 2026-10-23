"""Shared model helpers: UUID primary keys, UTC timestamps, enums."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, String, TypeDecorator
from sqlalchemy.orm import Mapped, mapped_column


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetime that survives SQLite's naive storage."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> Any:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return value if dialect.name != "sqlite" else value.replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class TrustState(StrEnum):
    TRUSTED = "trusted"
    UNKNOWN = "unknown"
    NONCOMPLIANT = "noncompliant"
    QUARANTINED = "quarantined"
    COMPROMISED = "compromised"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    SUPPRESSED = "suppressed"
    CLOSED = "closed"


class IncidentStatus(StrEnum):
    NEW = "new"
    TRIAGE = "triage"
    CONTAINMENT = "containment"
    CONTAINED = "contained"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"


class ActionType(StrEnum):
    BLOCK_IP = "block_ip"
    QUARANTINE_ASSET = "quarantine_asset"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_ACCOUNT = "disable_account"
    SINKHOLE_DOMAIN = "sinkhole_domain"
    NOTIFY_TEAM = "notify_team"


class ActionStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    REVERTED = "reverted"


class StringIdMixin:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
