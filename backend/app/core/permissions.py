"""Role-based access control.

Four roles with strictly separated capabilities:

* ``viewer``    - read-only dashboards and reports.
* ``analyst``   - triage: acknowledge alerts, annotate incidents, collect evidence.
* ``responder`` - analyst rights plus executing response actions.
* ``admin``     - user/policy/configuration management and approvals.

Response execution additionally requires that the acting user's role is at
least ``responder`` *and*, for approval-gated actions, that the approver is a
different account (four-eyes principle).
"""

from __future__ import annotations

from enum import StrEnum

from fastapi import HTTPException, status


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"


ROLE_RANK: dict[str, int] = {
    Role.VIEWER: 10,
    Role.ANALYST: 20,
    Role.RESPONDER: 30,
    Role.ADMIN: 40,
}


class Permission(StrEnum):
    DASHBOARD_VIEW = "dashboard:view"
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    EVENT_READ = "event:read"
    EVENT_INGEST = "event:ingest"
    ALERT_READ = "alert:read"
    ALERT_TRIAGE = "alert:triage"
    INCIDENT_READ = "incident:read"
    INCIDENT_WRITE = "incident:write"
    EVIDENCE_COLLECT = "evidence:collect"
    ACTION_REQUEST = "action:request"
    ACTION_APPROVE = "action:approve"
    ACTION_EXECUTE = "action:execute"
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    REPORT_READ = "report:read"
    AUDIT_READ = "audit:read"
    USER_ADMIN = "user:admin"
    INTEGRATION_READ = "integration:read"
    INTEGRATION_TEST = "integration:test"


ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    Role.VIEWER: {
        Permission.DASHBOARD_VIEW,
        Permission.ASSET_READ,
        Permission.EVENT_READ,
        Permission.ALERT_READ,
        Permission.INCIDENT_READ,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
        Permission.INTEGRATION_READ,
    },
    Role.ANALYST: {
        Permission.DASHBOARD_VIEW,
        Permission.ASSET_READ,
        Permission.EVENT_READ,
        Permission.ALERT_READ,
        Permission.ALERT_TRIAGE,
        Permission.INCIDENT_READ,
        Permission.INCIDENT_WRITE,
        Permission.EVIDENCE_COLLECT,
        Permission.ACTION_REQUEST,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
        Permission.INTEGRATION_READ,
    },
    Role.RESPONDER: {
        Permission.DASHBOARD_VIEW,
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
        Permission.EVENT_READ,
        Permission.EVENT_INGEST,
        Permission.ALERT_READ,
        Permission.ALERT_TRIAGE,
        Permission.INCIDENT_READ,
        Permission.INCIDENT_WRITE,
        Permission.EVIDENCE_COLLECT,
        Permission.ACTION_REQUEST,
        Permission.ACTION_EXECUTE,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
        Permission.AUDIT_READ,
        Permission.INTEGRATION_READ,
        Permission.INTEGRATION_TEST,
    },
    Role.ADMIN: set(Permission),
}


def permissions_for(role: str) -> set[Permission]:
    return ROLE_PERMISSIONS.get(role, set())


def has_permission(role: str, permission: Permission) -> bool:
    return permission in permissions_for(role)


def require_permission(role: str, permission: Permission) -> None:
    if not has_permission(role, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role '{role}' lacks permission '{permission}'",
        )


def can_approve(approver_role: str) -> bool:
    return ROLE_RANK.get(approver_role, 0) >= ROLE_RANK[Role.ADMIN]


def can_execute(role: str) -> bool:
    return ROLE_RANK.get(role, 0) >= ROLE_RANK[Role.RESPONDER]
