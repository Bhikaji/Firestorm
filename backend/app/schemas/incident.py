from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class IncidentOut(ORMModel):
    id: str
    reference: str
    title: str
    summary: str
    severity: str
    status: str
    risk_score: int
    owner_id: str | None
    detected_at: datetime
    contained_at: datetime | None
    closed_at: datetime | None
    observed_facts: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    affected_asset_ids: list[str] = []
    affected_accounts: list[str] = []
    mitre_tactics: list[str] = []
    post_incident_review: str | None
    summary_report: str | None
    created_at: datetime
    updated_at: datetime


class TimelineEntry(ORMModel):
    id: str
    incident_id: str
    ts: datetime
    kind: str
    actor: str
    message: str
    payload: dict[str, Any] = {}


class EvidenceOut(ORMModel):
    id: str
    incident_id: str | None
    alert_id: str | None
    kind: str
    label: str
    sha256: str
    size_bytes: int
    collected_by: str
    collected_at: datetime
    source: str
    custody: list[dict[str, Any]] = []
    metadata_json: dict[str, Any] = {}
    sealed: bool


class ActionOut(ORMModel):
    id: str
    incident_id: str | None
    alert_id: str | None
    action_type: str
    target: str
    asset_id: str | None
    status: str
    reason: str
    requested_by: str
    approved_by: str | None
    approved_at: datetime | None
    executed_at: datetime | None
    reverted_at: datetime | None
    integration: str | None
    mode: str
    result: str | None
    confidence: float
    reversible: bool
    created_at: datetime


class IncidentDetail(IncidentOut):
    timeline: list[TimelineEntry] = []
    evidence: list[EvidenceOut] = []
    actions: list[ActionOut] = []
    alerts: list[dict[str, Any]] = []


class IncidentCreate(BaseModel):
    title: str = Field(min_length=5, max_length=220)
    summary: str = Field(min_length=10, max_length=8000)
    severity: str = Field(default="high", pattern="^(info|low|medium|high|critical)$")
    alert_ids: list[str] = []
    affected_asset_ids: list[str] = []
    observed_facts: list[dict[str, Any]] = []


class IncidentUpdate(BaseModel):
    status: str | None = Field(default=None, pattern="^(new|triage|containment|contained|eradication|recovery|closed)$")
    owner_id: str | None = None
    severity: str | None = Field(default=None, pattern="^(info|low|medium|high|critical)$")
    summary: str | None = Field(default=None, max_length=8000)
    post_incident_review: str | None = Field(default=None, max_length=20000)
    hypothesis: str | None = Field(default=None, max_length=2000)


class ActionRequest(BaseModel):
    action_type: str = Field(pattern="^(block_ip|quarantine_asset|isolate_endpoint|disable_account|sinkhole_domain|notify_team)$")
    target: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=2000)
    incident_id: str | None = None
    alert_id: str | None = None
    asset_id: str | None = None
    require_approval: bool | None = None


class ActionDecision(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class EvidenceCollectIn(BaseModel):
    kind: str = Field(default="event_bundle", pattern="^(event_bundle|file_hash|email_header|pcap_ref|screenshot|analyst_note)$")
    label: str = Field(min_length=3, max_length=255)
    alert_id: str | None = None
    event_ids: list[str] = []
    file_hash: str | None = Field(default=None, max_length=64)
    content: str | None = Field(default=None, max_length=1_000_000)
    metadata: dict[str, Any] = {}
