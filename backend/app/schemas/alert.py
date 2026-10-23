from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class RiskSignal(BaseModel):
    key: str
    label: str
    weight: int
    detail: str
    source: str


class AlertOut(ORMModel):
    id: str
    code: str
    title: str
    description: str
    severity: str
    confidence: float
    risk_score: int
    status: str
    rule_id: str
    rule_version: str
    detection_source: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    asset_id: str | None
    incident_id: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    dns_query: str | None
    signals: list[dict[str, Any]] = []
    ttps: list[str] = []
    recommended_actions: list[str] = []
    evidence_refs: list[str] = []
    assignee_id: str | None
    acknowledged_at: datetime | None
    closed_at: datetime | None
    suppressed_until: datetime | None
    false_positive: bool
    analyst_note: str | None
    created_at: datetime
    updated_at: datetime


class AlertTriageIn(BaseModel):
    status: str | None = Field(default=None, pattern="^(open|acknowledged|investigating|suppressed|closed)$")
    assignee_id: str | None = None
    note: str | None = Field(default=None, max_length=4000)
    false_positive: bool | None = None
    suppress_minutes: int | None = Field(default=None, ge=5, le=10080)
    create_incident: bool = False


class SuppressionIn(BaseModel):
    fingerprint: str | None = Field(default=None, max_length=128)
    rule_id: str | None = Field(default=None, max_length=40)
    asset_id: str | None = None
    reason: str = Field(min_length=10, max_length=2000)
    duration_minutes: int = Field(ge=5, le=10080)


class SuppressionOut(ORMModel):
    id: str
    fingerprint: str | None
    rule_id: str | None
    asset_id: str | None
    reason: str
    created_by: str
    expires_at: datetime
    active: bool
    created_at: datetime
