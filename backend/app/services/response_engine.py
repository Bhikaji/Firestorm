"""Policy-driven containment engine.

Flow for every action:

1. ``request`` - validate target, decide whether approval is required, persist
   a ``ResponseAction`` in ``pending_approval`` or ``approved``.
2. ``approve``/``reject`` - a *different* admin approves (four-eyes).
3. ``execute`` - call the enforcement adapter, then record the applied state in
   ``enforcement_records`` for reversibility.
4. ``revert``  - undo a specific action.

Guarantees:
* every step is audited with actor, rationale, and result;
* an unconfigured live adapter fails the action instead of claiming success;
* simulated adapters mark the action ``mode="simulated"`` so the UI never shows
  simulated containment as real;
* critical business services on the allowlist are protected from automated
  actions, and there is an emergency "release all" path to prevent lockout.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.core.permissions import can_approve, can_execute
from app.integrations.base import EnforcementIntegration
from app.integrations.registry import registry
from app.models.asset import Asset
from app.models.base import ActionStatus, ActionType
from app.models.incident import EnforcementRecord, IncidentTimelineEvent, ResponseAction
from app.models.policy import Policy
from app.models.user import User
from app.services.audit_service import AuditService

logger = logging.getLogger("firestorm.response")

ALWAYS_APPROVAL = {ActionType.DISABLE_ACCOUNT}


def _now() -> datetime:
    return datetime.now(UTC)


class ResponseEngine:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)
        self.integrations = registry()

    # -- policy ---------------------------------------------------------
    def _policy(self) -> dict:
        row = self.db.execute(select(Policy).where(Policy.key == "response.approval")).scalars().first()
        return row.config if row and row.enabled else {}

    def requires_approval(self, action_type: str, *, risk_score: int, asset: Asset | None) -> tuple[bool, str]:
        policy = self._policy()
        if action_type in ALWAYS_APPROVAL:
            return True, "Account suspension always requires human approval."
        if settings.require_approval_for_containment and not policy.get("allow_auto_low_impact", False):
            return True, "Global policy requires approval for containment actions."
        if asset and asset.criticality >= 4 and not policy.get("allow_auto_critical_asset", False):
            return True, "Business-critical asset: approval required by policy."
        threshold = int(policy.get("auto_execute_threshold", settings.auto_containment_threshold))
        if risk_score < threshold:
            return True, f"Risk score {risk_score} is below the automatic execution threshold ({threshold})."
        if policy.get("allowlist") and asset and asset.hostname in policy["allowlist"]:
            return True, "Asset is on the protected allowlist."
        return False, "Risk score and policy permit automatic execution."

    def is_allowlisted(self, target: str, asset: Asset | None) -> bool:
        allowlist = self._policy().get("allowlist") or []
        values = {target}
        if asset:
            values.update({asset.hostname, asset.ip_address, asset.id})
        return any(value in allowlist for value in values)

    # -- lifecycle ------------------------------------------------------
    def request(
        self,
        *,
        action_type: str,
        target: str,
        reason: str,
        actor: User,
        incident_id: str | None = None,
        alert_id: str | None = None,
        asset_id: str | None = None,
        risk_score: int = 0,
        require_approval: bool | None = None,
    ) -> ResponseAction:
        if action_type not in {a.value for a in ActionType}:
            raise ValidationFailed("unknown action type")
        if action_type == ActionType.NOTIFY_TEAM:
            raise ValidationFailed("use the notification service for notifications")

        asset = self.db.get(Asset, asset_id) if asset_id else self._guess_asset(target)
        if self.is_allowlisted(target, asset):
            raise Forbidden("target is on the protected allowlist; escalate for a manual exception")

        integration = self.integrations.enforcement_for(action_type)
        if integration is None:
            raise ValidationFailed(f"no enforcement integration mapped for {action_type}")

        needs_approval, why = self.requires_approval(action_type, risk_score=risk_score, asset=asset)
        if require_approval:
            # A requester may always ask for *more* scrutiny.
            needs_approval = True
            if why and not why.endswith("explicitly requested."):
                why = f"{why} Approval was explicitly requested by the requester."
        elif require_approval is False and needs_approval:
            # Never let a caller waive a mandatory gate: that would defeat
            # four-eyes approval for destructive actions.
            why = f"{why} A waiver was requested and ignored."

        action = ResponseAction(
            incident_id=incident_id,
            alert_id=alert_id,
            action_type=action_type,
            target=target,
            asset_id=asset.id if asset else None,
            status=ActionStatus.PENDING_APPROVAL if needs_approval else ActionStatus.APPROVED,
            reason=reason,
            requested_by=actor.id,
            integration=integration.name,
            mode=integration.mode,
            confidence=0.0,
            reversible=True,
        )
        self.db.add(action)
        self.db.flush()
        self._timeline(
            incident_id,
            kind="action",
            actor=actor.email,
            message=f"Requested {action_type} on {target}" + (" (approval required)" if needs_approval else ""),
            payload={"action_id": action.id, "reason": reason, "decision_basis": why},
        )
        self.audit.record(
            action="action.requested",
            actor_id=actor.id,
            actor_email=actor.email,
            actor_role=actor.role,
            object_type="response_action",
            object_id=action.id,
            detail={"action_type": action_type, "target": target, "approval_required": needs_approval, "basis": why},
        )
        self.db.flush()
        return action

    def approve(self, action_id: str, approver: User, note: str | None = None) -> ResponseAction:
        action = self._get(action_id)
        if not can_approve(approver.role):
            raise Forbidden("only administrators may approve response actions")
        if action.status != ActionStatus.PENDING_APPROVAL:
            raise Conflict(f"action is {action.status}, not pending approval")
        if action.requested_by == approver.id:
            raise Forbidden("the requester cannot approve their own action (four-eyes principle)")
        action.status = ActionStatus.APPROVED
        action.approved_by = approver.id
        action.approved_at = _now()
        self.db.flush()
        self._timeline(
            action.incident_id, kind="action", actor=approver.email,
            message=f"Approved {action.action_type} on {action.target}",
            payload={"action_id": action.id, "note": note},
        )
        self.audit.record(
            action="action.approved", actor_id=approver.id, actor_email=approver.email, actor_role=approver.role,
            object_type="response_action", object_id=action.id, detail={"note": note or ""},
        )
        self.db.flush()
        return action

    def reject(self, action_id: str, approver: User, note: str | None = None) -> ResponseAction:
        action = self._get(action_id)
        if not can_approve(approver.role):
            raise Forbidden("only administrators may reject response actions")
        if action.status != ActionStatus.PENDING_APPROVAL:
            raise Conflict(f"action is {action.status}, not pending approval")
        action.status = ActionStatus.REJECTED
        action.approved_by = approver.id
        action.approved_at = _now()
        action.result = note or "rejected"
        self.db.flush()
        self.audit.record(
            action="action.rejected", actor_id=approver.id, actor_email=approver.email, actor_role=approver.role,
            object_type="response_action", object_id=action.id, detail={"note": note or ""},
        )
        self.db.flush()
        return action

    def execute(self, action_id: str, actor: User) -> ResponseAction:
        action = self._get(action_id)
        if not can_execute(actor.role):
            raise Forbidden("role may not execute response actions")
        if action.status == ActionStatus.PENDING_APPROVAL:
            raise Conflict("action requires approval before execution")
        if action.status not in {ActionStatus.APPROVED, ActionStatus.FAILED}:
            raise Conflict(f"action is {action.status} and cannot be executed")

        integration = self.integrations.enforcement_for(action.action_type)
        if integration is None:
            raise ValidationFailed("no integration available")

        action.status = ActionStatus.EXECUTING
        self.db.flush()
        try:
            result = self._apply(action, integration)
        except Exception as exc:  # noqa: BLE001 - adapter failures must be recorded
            action.status = ActionStatus.FAILED
            action.result = f"{type(exc).__name__}: {exc}"
            self.db.flush()
            self.audit.record(
                action="action.failed", actor_id=actor.id, actor_email=actor.email, actor_role=actor.role,
                object_type="response_action", object_id=action.id, outcome="failure",
                detail={"error": action.result},
            )
            self.db.flush()
            return action

        action.executed_at = _now()
        action.result = result.message
        action.mode = result.mode
        if result.ok:
            action.status = ActionStatus.SUCCEEDED
            self._record_enforcement(action, integration, result)
            self._apply_local_state(action)
        else:
            action.status = ActionStatus.FAILED

        self._timeline(
            action.incident_id,
            kind="action",
            actor=actor.email,
            message=f"{'Executed' if result.ok else 'Failed'} {action.action_type} on {action.target}: {result.message}",
            payload={"action_id": action.id, "mode": result.mode, "ok": result.ok},
        )
        self.audit.record(
            action="action.executed",
            actor_id=actor.id,
            actor_email=actor.email,
            actor_role=actor.role,
            object_type="response_action",
            object_id=action.id,
            outcome="success" if result.ok else "failure",
            detail={"target": action.target, "mode": result.mode, "message": result.message},
        )
        self.db.flush()
        return action

    def _apply(self, action: ResponseAction, integration: EnforcementIntegration):
        if action.action_type == ActionType.BLOCK_IP:
            return integration.apply(action.target, reason=action.reason)
        if action.action_type == ActionType.SINKHOLE_DOMAIN:
            return integration.apply(action.target, reason=action.reason)
        if action.action_type in {ActionType.QUARANTINE_ASSET, ActionType.ISOLATE_ENDPOINT}:
            return integration.apply(action.target, reason=action.reason)
        if action.action_type == ActionType.DISABLE_ACCOUNT:
            return integration.apply(action.target, reason=action.reason)
        raise ValidationFailed(f"unhandled action type {action.action_type}")

    def _record_enforcement(self, action: ResponseAction, integration: EnforcementIntegration, result) -> None:
        record = EnforcementRecord(
            action_id=action.id,
            kind={
                ActionType.BLOCK_IP: "firewall_block",
                ActionType.QUARANTINE_ASSET: "vlan_move",
                ActionType.ISOLATE_ENDPOINT: "endpoint_isolate",
                ActionType.SINKHOLE_DOMAIN: "dns_sinkhole",
                ActionType.DISABLE_ACCOUNT: "account_disable",
            }[action.action_type],
            target=action.target,
            integration=integration.name,
            mode=result.mode,
            state="applied",
            detail=action.reason,
        )
        self.db.add(record)
        self.db.flush()

    def _apply_local_state(self, action: ResponseAction) -> None:
        """Mirror successful containment into the asset inventory."""
        if not action.asset_id:
            return
        asset = self.db.get(Asset, action.asset_id)
        if not asset:
            return
        if action.action_type in {ActionType.QUARANTINE_ASSET, ActionType.ISOLATE_ENDPOINT}:
            asset.trust_state = "quarantined"
            asset.quarantine_reason = action.reason
            asset.quarantined_at = _now()

    def revert(self, action_id: str, actor: User, *, note: str | None = None) -> ResponseAction:
        action = self._get(action_id)
        if not can_execute(actor.role):
            raise Forbidden("role may not revert response actions")
        if action.status not in {ActionStatus.SUCCEEDED}:
            raise Conflict("only successfully executed actions can be reverted")
        integration = self.integrations.enforcement_for(action.action_type)
        if integration is None:
            raise ValidationFailed("no integration available")
        result = integration.revert(action.target)
        action.reverted_at = _now()
        action.status = ActionStatus.REVERTED
        action.result = f"{action.result or ''}\nRevert: {result.message}".strip()

        for record in self.db.execute(
            select(EnforcementRecord).where(EnforcementRecord.action_id == action.id, EnforcementRecord.state == "applied")
        ).scalars():
            record.state = "reverted"
            record.reverted_at = _now()

        if action.asset_id:
            asset = self.db.get(Asset, action.asset_id)
            if asset and asset.trust_state == "quarantined":
                asset.trust_state = "unknown"
                asset.quarantine_reason = None
                asset.quarantined_at = None

        self._timeline(action.incident_id, kind="action", actor=actor.email,
                       message=f"Reverted {action.action_type} on {action.target}",
                       payload={"action_id": action.id, "note": note})
        self.audit.record(
            action="action.reverted", actor_id=actor.id, actor_email=actor.email, actor_role=actor.role,
            object_type="response_action", object_id=action.id, detail={"message": result.message, "note": note},
        )
        self.db.flush()
        return action

    def release_all(self, actor: User, *, note: str) -> dict:
        """Emergency recovery: undo every applied containment action."""
        if not can_approve(actor.role):
            raise Forbidden("only administrators may perform emergency release")
        records = self.db.execute(
            select(EnforcementRecord).where(EnforcementRecord.state == "applied")
        ).scalars().all()
        released = 0
        failed: list[str] = []
        for record in records:
            integration = self.integrations.by_name(record.integration)
            if integration is None or not hasattr(integration, "revert"):
                failed.append(record.target)
                continue
            try:
                result = integration.revert(record.target)  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001
                failed.append(record.target)
                logger.warning("release_all revert failed: %s", type(exc).__name__)
                continue
            if result.ok:
                record.state = "reverted"
                record.reverted_at = _now()
                released += 1
                if record.action_id:
                    action = self.db.get(ResponseAction, record.action_id)
                    if action and action.status == ActionStatus.SUCCEEDED:
                        action.status = ActionStatus.REVERTED
                        action.reverted_at = _now()
            else:
                failed.append(record.target)
        self.audit.record(
            action="response.emergency_release", actor_id=actor.id, actor_email=actor.email,
            actor_role=actor.role, object_type="enforcement", detail={"released": released, "failed": failed, "note": note},
        )
        self.db.flush()
        return {"released": released, "failed": failed, "remaining": len(records) - released}

    # -- helpers --------------------------------------------------------
    def _get(self, action_id: str) -> ResponseAction:
        action = self.db.get(ResponseAction, action_id)
        if not action:
            raise NotFound("response action not found")
        return action

    def _guess_asset(self, target: str) -> Asset | None:
        return self.db.execute(
            select(Asset).where((Asset.ip_address == target) | (Asset.hostname == target) | (Asset.mac_address == target))
        ).scalars().first()

    def _timeline(self, incident_id: str | None, *, kind: str, actor: str, message: str, payload: dict) -> None:
        if not incident_id:
            return
        self.db.add(
            IncidentTimelineEvent(
                incident_id=incident_id, ts=_now(), kind=kind, actor=actor, message=message, payload=payload
            )
        )

    def active_enforcement(self) -> list[EnforcementRecord]:
        return list(
            self.db.execute(
                select(EnforcementRecord).where(EnforcementRecord.state == "applied").order_by(
                    EnforcementRecord.created_at.desc()
                )
            ).scalars()
        )
