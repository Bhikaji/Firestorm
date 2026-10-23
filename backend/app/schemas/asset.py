from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

from app.schemas.common import ORMModel


class SegmentOut(ORMModel):
    id: str
    name: str
    cidr: str
    vlan_id: int | None
    sensitivity: str
    description: str | None
    monitored: bool
    created_at: datetime


class SegmentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    cidr: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F:.]+/\d{1,3}$")
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    sensitivity: str = Field(default="standard", pattern="^(standard|elevated|restricted|management)$")
    description: str | None = Field(default=None, max_length=2000)


class AssetOut(ORMModel):
    id: str
    hostname: str
    ip_address: str
    mac_address: str | None
    device_type: str
    os_name: str | None
    os_version: str | None
    owner: str | None
    department: str | None
    segment_id: str | None
    criticality: int
    trust_state: str
    enrolled: bool
    edr_status: str
    patch_level: str
    firewall_enabled: bool | None
    disk_encrypted: bool | None
    posture_score: float
    last_posture_at: datetime | None
    last_seen_at: datetime | None
    quarantine_reason: str | None
    quarantined_at: datetime | None
    tags: dict[str, Any] = {}
    updated_at: datetime


class AssetCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=160)
    ip_address: str = Field(max_length=45)
    mac_address: str | None = Field(default=None, max_length=17)
    device_type: str = Field(default="workstation", max_length=40)
    os_name: str | None = Field(default=None, max_length=80)
    os_version: str | None = Field(default=None, max_length=80)
    owner: str | None = Field(default=None, max_length=160)
    department: str | None = Field(default=None, max_length=120)
    segment_id: str | None = None
    criticality: int = Field(default=3, ge=1, le=5)

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return str(IPvAnyAddress(value))  # type: ignore[return-value]


class AssetUpdate(BaseModel):
    hostname: str | None = Field(default=None, max_length=160)
    owner: str | None = Field(default=None, max_length=160)
    department: str | None = Field(default=None, max_length=120)
    criticality: int | None = Field(default=None, ge=1, le=5)
    segment_id: str | None = None
    notes: str | None = Field(default=None, max_length=4000)


class PostureReport(BaseModel):
    """Endpoint agent posture report (trusted agents only)."""

    agent_version: str | None = Field(default=None, max_length=40)
    edr_status: str = Field(default="unknown", pattern="^(active|inactive|degraded|unknown)$")
    patch_level: str = Field(default="unknown", pattern="^(current|behind|critical_pending|unknown)$")
    firewall_enabled: bool | None = None
    disk_encrypted: bool | None = None
    os_name: str | None = Field(default=None, max_length=80)
    os_version: str | None = Field(default=None, max_length=80)
    malware_detections_24h: int = Field(default=0, ge=0, le=100000)
    certificate_valid: bool | None = None
    extra: dict[str, Any] = {}


class AdmissionDecision(BaseModel):
    asset_id: str
    outcome: str
    reason: str
    matched_rule: str | None
    posture_score: float
    trust_state: str
    risk_score: int
    evaluated_at: datetime


class QuarantineRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)
    duration_minutes: int | None = Field(default=None, ge=5, le=10080)


class TrustChange(BaseModel):
    trust_state: str = Field(pattern="^(trusted|unknown|noncompliant|quarantined|compromised)$")
    reason: str = Field(min_length=5, max_length=2000)
