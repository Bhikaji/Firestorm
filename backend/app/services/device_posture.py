"""Endpoint posture scoring and admission decisions.

Posture is a weighted, bounded score (0-100) computed from independent
signals - never a single check. Admission rules are evaluated in priority
order; the first matching rule wins. Default rules implement the required
behaviour:

* trusted + compliant -> allow (least privilege)
* unassessed        -> restrict to remediation network
* noncompliant      -> deny protected resources
* compromised       -> quarantine

A network scan cannot prove a device is malware-free. The score therefore
measures *reported compliance*, and unknown values reduce confidence rather
than being treated as healthy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFound, ValidationFailed
from app.models.asset import Asset
from app.models.base import TrustState
from app.models.policy import AdmissionRule
from app.models.user import User
from app.schemas.asset import PostureReport
from app.services.audit_service import AuditService

# Weights sum to 100.
WEIGHTS = {
    "enrolled": 15,
    "edr_active": 25,
    "patch_current": 20,
    "firewall": 15,
    "encryption": 15,
    "no_recent_malware": 10,
}

OUTCOME_LABELS = {
    "allow": "Allow - least-privilege access to permitted resources",
    "restrict_remediation": "Restrict - registration/remediation network only",
    "deny": "Deny - protected resources blocked until remediation",
    "quarantine": "Quarantine - enforce containment via NAC/EDR",
}

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "name": "Confirmed compromise",
        "description": "Device is confirmed compromised or already quarantined.",
        "priority": 10,
        "condition": {"any": [{"field": "trust_state", "op": "in", "value": ["compromised", "quarantined"]}]},
        "outcome": "quarantine",
        "outcome_reason": "Device is confirmed compromised or under containment.",
        "min_posture_score": 0,
    },
    {
        "name": "Unenrolled device",
        "description": "Device is not enrolled in device management, so identity cannot be verified.",
        "priority": 20,
        "condition": {"all": [{"field": "enrolled", "op": "eq", "value": False}]},
        "outcome": "restrict_remediation",
        "outcome_reason": "Unenrolled device must complete registration before production access.",
        "min_posture_score": 0,
    },
    {
        "name": "Missing endpoint protection",
        "description": "EDR is inactive or unknown while the device claims to be managed.",
        "priority": 30,
        "condition": {"any": [{"field": "edr_status", "op": "in", "value": ["inactive", "unknown"]}]},
        "outcome": "deny",
        "outcome_reason": "No trustworthy endpoint protection signal; access to protected resources denied.",
        "min_posture_score": 0,
    },
    {
        "name": "Critical patches pending",
        "description": "Device reports critically pending patches.",
        "priority": 40,
        "condition": {"all": [{"field": "patch_level", "op": "eq", "value": "critical_pending"}]},
        "outcome": "restrict_remediation",
        "outcome_reason": "Critical patches pending; remediation network only.",
        "min_posture_score": 0,
    },
    {
        "name": "Low posture score",
        "description": "Composite posture score below the acceptable baseline.",
        "priority": 50,
        "condition": {"all": [{"field": "posture_score", "op": "lt", "value": 60}]},
        "outcome": "restrict_remediation",
        "outcome_reason": "Posture score below baseline; remediation required.",
        "min_posture_score": 60,
    },
    {
        "name": "Compliant managed device",
        "description": "Enrolled, patched, protected and encrypted.",
        "priority": 100,
        "condition": {
            "all": [
                {"field": "enrolled", "op": "eq", "value": True},
                {"field": "edr_status", "op": "eq", "value": "active"},
                {"field": "patch_level", "op": "in", "value": ["current"]},
                {"field": "posture_score", "op": "gte", "value": 60},
            ]
        },
        "outcome": "allow",
        "outcome_reason": "Device meets admission baseline.",
        "min_posture_score": 60,
    },
]


def _now() -> datetime:
    return datetime.now(UTC)


def compute_posture(asset: Asset, report: PostureReport | None = None) -> tuple[float, dict[str, Any]]:
    malware = report.malware_detections_24h if report else 0
    checks = {
        "enrolled": asset.enrolled,
        "edr_active": (report.edr_status if report else asset.edr_status) == "active",
        "patch_current": (report.patch_level if report else asset.patch_level) in {"current"},
        "firewall": bool(report.firewall_enabled if report and report.firewall_enabled is not None else asset.firewall_enabled),
        "encryption": bool(report.disk_encrypted if report and report.disk_encrypted is not None else asset.disk_encrypted),
        "no_recent_malware": malware == 0,
    }
    score = sum(WEIGHTS[key] for key, ok in checks.items() if ok)
    return float(score), {**checks, "malware_detections_24h": malware, "max_score": sum(WEIGHTS.values())}


class AdmissionService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

    # -- rules ----------------------------------------------------------
    def ensure_default_rules(self) -> None:
        existing = self.db.execute(select(AdmissionRule.id).limit(1)).first()
        if existing:
            return
        for rule in DEFAULT_RULES:
            self.db.add(AdmissionRule(**rule))
        self.db.flush()

    def rules(self) -> list[AdmissionRule]:
        return list(
            self.db.execute(select(AdmissionRule).order_by(AdmissionRule.priority.asc())).scalars().all()
        )

    def _match(self, condition: dict[str, Any], facts: dict[str, Any]) -> bool:
        if not condition:
            return True
        if "all" in condition:
            return all(self._match(c, facts) for c in condition["all"])
        if "any" in condition:
            return any(self._match(c, facts) for c in condition["any"])
        field = condition.get("field")
        op = condition.get("op", "eq")
        expected = condition.get("value")
        actual = facts.get(field)
        if op == "eq":
            return actual == expected
        if op == "neq":
            return actual != expected
        if op == "in":
            return actual in (expected or [])
        if op == "gte":
            return actual is not None and actual >= expected
        if op == "lte":
            return actual is not None and actual <= expected
        if op == "lt":
            return actual is not None and actual < expected
        if op == "gt":
            return actual is not None and actual > expected
        if op == "exists":
            return (actual is not None) is bool(expected)
        return False

    # -- posture --------------------------------------------------------
    def record_posture(self, asset_id: str, report: PostureReport, *, actor: User | None = None) -> Asset:
        asset = self.db.get(Asset, asset_id)
        if not asset:
            raise NotFound("asset not found")
        score, checks = compute_posture(asset, report)
        asset.agent_version = report.agent_version or asset.agent_version
        asset.edr_status = report.edr_status
        asset.patch_level = report.patch_level
        if report.firewall_enabled is not None:
            asset.firewall_enabled = report.firewall_enabled
        if report.disk_encrypted is not None:
            asset.disk_encrypted = report.disk_encrypted
        if report.os_name:
            asset.os_name = report.os_name
        if report.os_version:
            asset.os_version = report.os_version
        asset.posture_score = score
        asset.last_posture_at = _now()
        asset.last_seen_at = _now()
        asset.tags = {**(asset.tags or {}), "posture_checks": checks}

        if asset.trust_state == TrustState.UNKNOWN and asset.enrolled:
            asset.trust_state = TrustState.TRUSTED if score >= 60 else TrustState.NONCOMPLIANT
        elif asset.trust_state == TrustState.TRUSTED and score < 40:
            asset.trust_state = TrustState.NONCOMPLIANT

        self.audit.record(
            action="asset.posture_recorded",
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else "posture-collector",
            actor_role=actor.role if actor else "system",
            object_type="asset",
            object_id=asset.id,
            detail={"posture_score": score, "checks": checks},
        )
        self.db.flush()
        return asset

    def evaluate(self, asset: Asset, *, persist: bool = True) -> dict[str, Any]:
        facts = {
            "enrolled": asset.enrolled,
            "edr_status": asset.edr_status,
            "patch_level": asset.patch_level,
            "firewall_enabled": asset.firewall_enabled,
            "disk_encrypted": asset.disk_encrypted,
            "posture_score": asset.posture_score,
            "trust_state": asset.trust_state,
            "criticality": asset.criticality,
            "device_type": asset.device_type,
            "department": asset.department,
        }
        matched: AdmissionRule | None = None
        outcome = "restrict_remediation"
        reason = "No admission rule matched; defaulting to restricted access."
        for rule in self.rules():
            if not rule.enabled:
                continue
            if asset.posture_score < rule.min_posture_score and rule.outcome != "allow":
                # min_posture_score is an additional gate, not a bypass
                continue
            if self._match(rule.condition, facts):
                matched = rule
                outcome = rule.outcome
                reason = rule.outcome_reason or rule.name
                break

        if matched is None:
            reason = "No admission rule matched; defaulting to restricted access (fail closed)."

        if persist:
            if outcome == "allow":
                asset.trust_state = TrustState.TRUSTED
            elif outcome in {"deny", "restrict_remediation"}:
                if asset.trust_state not in {TrustState.COMPROMISED, TrustState.QUARANTINED}:
                    asset.trust_state = TrustState.NONCOMPLIANT
            self.db.flush()

        return {
            "asset_id": asset.id,
            "outcome": outcome,
            "reason": reason,
            "matched_rule": matched.name if matched else None,
            "posture_score": asset.posture_score,
            "trust_state": asset.trust_state,
            "risk_score": int(max(0, min(100, 100 - asset.posture_score + (asset.criticality - 3) * 5))),
            "evaluated_at": _now(),
            "outcome_label": OUTCOME_LABELS.get(outcome, outcome),
        }

    def evaluate_all(self) -> list[dict[str, Any]]:
        assets = self.db.execute(select(Asset)).scalars().all()
        results = [self.evaluate(asset) for asset in assets]
        self.db.flush()
        return results

    def validate_rule_condition(self, condition: dict[str, Any]) -> None:
        allowed_fields = {
            "enrolled", "edr_status", "patch_level", "firewall_enabled", "disk_encrypted",
            "posture_score", "trust_state", "criticality", "device_type", "department",
        }
        allowed_ops = {"eq", "neq", "in", "gte", "lte", "lt", "gt", "exists"}

        def walk(node: dict[str, Any]) -> None:
            if "all" in node or "any" in node:
                children = node.get("all") or node.get("any")
                if not isinstance(children, list) or not children:
                    raise ValidationFailed("condition groups must contain a non-empty list")
                for child in children[:50]:
                    walk(child)
                return
            if "field" not in node:
                raise ValidationFailed("leaf conditions require a field")
            if node["field"] not in allowed_fields:
                raise ValidationFailed(f"unknown condition field '{node['field']}'")
            if node.get("op", "eq") not in allowed_ops:
                raise ValidationFailed(f"unknown operator '{node.get('op')}'")

        walk(condition)
