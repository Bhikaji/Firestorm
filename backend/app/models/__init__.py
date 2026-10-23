"""Importing this module registers every table with SQLAlchemy metadata."""

from app.models.alert import Alert, Suppression
from app.models.asset import Asset, Segment
from app.models.base import (
    ActionStatus,
    ActionType,
    AlertStatus,
    IncidentStatus,
    Severity,
    TrustState,
)
from app.models.incident import (
    EnforcementRecord,
    Evidence,
    Incident,
    IncidentTimelineEvent,
    ResponseAction,
)
from app.models.policy import (
    AdmissionRule,
    AuditLog,
    IntegrationConfig,
    Notification,
    Policy,
    ThreatIndicator,
)
from app.models.telemetry import Event
from app.models.user import LoginAttempt, RefreshToken, User

__all__ = [
    "Alert",
    "Suppression",
    "Asset",
    "Segment",
    "Event",
    "Incident",
    "IncidentTimelineEvent",
    "EnforcementRecord",
    "Evidence",
    "ResponseAction",
    "Policy",
    "ThreatIndicator",
    "AdmissionRule",
    "IntegrationConfig",
    "AuditLog",
    "Notification",
    "User",
    "LoginAttempt",
    "RefreshToken",
    "Severity",
    "TrustState",
    "AlertStatus",
    "IncidentStatus",
    "ActionType",
    "ActionStatus",
]
