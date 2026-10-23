from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class PolicyOut(ORMModel):
    id: str
    key: str
    name: str
    description: str
    category: str
    enabled: bool
    version: int
    config: dict[str, Any]
    updated_at: datetime


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool | None = None
    config: dict[str, Any] | None = None


class AdmissionRuleOut(ORMModel):
    id: str
    name: str
    description: str
    priority: int
    enabled: bool
    condition: dict[str, Any]
    outcome: str
    outcome_reason: str
    min_posture_score: int
    updated_at: datetime


class AdmissionRuleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=4000)
    priority: int = Field(default=100, ge=1, le=10_000)
    condition: dict[str, Any] = {}
    outcome: str = Field(pattern="^(allow|restrict_remediation|deny|quarantine)$")
    outcome_reason: str = Field(default="", max_length=255)
    min_posture_score: int = Field(default=0, ge=0, le=100)


class AdmissionRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    priority: int | None = Field(default=None, ge=1, le=10_000)
    enabled: bool | None = None
    condition: dict[str, Any] | None = None
    outcome: str | None = Field(default=None, pattern="^(allow|restrict_remediation|deny|quarantine)$")
    outcome_reason: str | None = Field(default=None, max_length=255)
    min_posture_score: int | None = Field(default=None, ge=0, le=100)


class AuditOut(ORMModel):
    id: str
    ts: datetime
    actor_email: str
    actor_role: str
    action: str
    object_type: str
    object_id: str | None
    outcome: str
    detail: dict[str, Any]
    client_ip: str | None
    entry_hash: str


class IntegrationOut(ORMModel):
    id: str
    name: str
    kind: str
    enabled: bool
    mode: str
    endpoint: str | None
    settings: dict[str, Any]
    last_checked_at: datetime | None
    last_status: str
    last_message: str | None


class IntegrationUpdate(BaseModel):
    enabled: bool | None = None
    endpoint: str | None = Field(default=None, max_length=255)
    settings: dict[str, Any] | None = None


class IntegrationHealth(BaseModel):
    name: str
    kind: str
    layer: str
    mode: str
    enabled: bool
    status: str
    checked_at: datetime
    detail: str
    latency_ms: float | None = None


class NotificationOut(ORMModel):
    id: str
    channel: str
    recipient: str
    subject: str
    body: str
    severity: str
    alert_id: str | None
    incident_id: str | None
    status: str
    attempts: int
    last_error: str | None
    delivered_at: datetime | None
    acknowledged_at: datetime | None
    created_at: datetime
