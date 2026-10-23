"""Identity-provider integration for account suspension.

Disabled-account actions are high-impact: the response engine always requires
approval unless an admin explicitly lowers the policy, and every call is
audited. Live mode speaks a minimal SCIM-like REST contract
(``PATCH /Users/{id}``); the adapter is deliberately conservative and does not
fall back to guessing an account id from an email address.
"""

from __future__ import annotations

import logging

import httpx

from app.core.config import settings
from app.integrations.base import EnforcementIntegration, HTTPIntegration, IntegrationResult

logger = logging.getLogger("firestorm.integrations.identity")


class LdapIdentity(HTTPIntegration, EnforcementIntegration):
    name = "Identity provider"
    kind = "identity"
    layer = "layer-7"
    simulated = False

    def __init__(self, *, endpoint: str | None, token: str | None) -> None:
        super().__init__(
            endpoint=endpoint if endpoint is not None else settings.idp_endpoint,
            token=token if token is not None else settings.idp_token,
        )

    def _set_active(self, account: str, active: bool) -> IntegrationResult:
        if not self.enabled:
            return IntegrationResult(
                ok=False,
                mode="live",
                message="Identity provider is not configured; account state was not changed.",
                detail={"required": ["FIRESTORM_IDP_ENDPOINT", "FIRESTORM_IDP_TOKEN"]},
            )
        if "@" not in account:
            return IntegrationResult(
                ok=False,
                mode="live",
                message="Account target must be a fully qualified user principal name.",
            )
        try:
            with self._client() as client:
                response = client.patch(f"/scim/v2/Users/{account}", json={"active": active})
                response.raise_for_status()
            return IntegrationResult(
                ok=True,
                mode="live",
                message=f"Account {account} {'disabled' if not active else 're-enabled'}.",
                detail={"account": account, "active": active},
            )
        except httpx.HTTPError as exc:
            logger.warning("identity API error: %s", type(exc).__name__)
            return IntegrationResult(ok=False, mode="live", message=f"Identity API error: {type(exc).__name__}")

    def apply(self, target: str, *, reason: str) -> IntegrationResult:
        result = self._set_active(target, False)
        result.detail.setdefault("reason", reason)
        return result

    def revert(self, target: str) -> IntegrationResult:
        return self._set_active(target, True)
