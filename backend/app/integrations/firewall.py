"""Firewall block integration (pfSense/OPNsense-style alias API).

Live mode requires ``FIRESTORM_FIREWALL_ENDPOINT`` and ``FIRESTORM_FIREWALL_TOKEN``.
Blocking is implemented as membership of a named firewall alias
(``FIRESTORM_BLOCK``) so every block is enumerable and reversible, and so an
operator can audit the whole block list in one place.

A pfSense REST API package must be installed on the appliance; the adapter
refuses to act when unconfigured rather than pretending to have blocked
traffic.
"""

from __future__ import annotations

import logging

import httpx

from app.core.config import settings
from app.integrations.base import EnforcementIntegration, HealthStatus, HTTPIntegration, IntegrationResult

logger = logging.getLogger("firestorm.integrations.firewall")


class PfSenseFirewall(HTTPIntegration, EnforcementIntegration):
    name = "pfSense firewall"
    kind = "firewall"
    layer = "layer-7"
    simulated = False

    def __init__(self, *, endpoint: str | None, token: str | None, alias: str | None = None) -> None:
        super().__init__(
            endpoint=endpoint if endpoint is not None else settings.firewall_endpoint,
            token=token if token is not None else settings.firewall_token,
        )
        self.alias = alias or settings.firewall_alias

    def _update_alias(self, ip: str, *, add: bool) -> IntegrationResult:
        if not self.enabled:
            return IntegrationResult(
                ok=False,
                mode="live",
                message="Firewall integration is not configured; no block was applied.",
                detail={"required": ["FIRESTORM_FIREWALL_ENDPOINT", "FIRESTORM_FIREWALL_TOKEN"]},
            )
        try:
            with self._client() as client:
                current = client.get(f"/api/v1/firewall/alias/{self.alias}")
                current.raise_for_status()
                addresses = list(current.json().get("addresses", []))
                if add and ip not in addresses:
                    addresses.append(ip)
                if not add:
                    addresses = [a for a in addresses if a != ip]
                payload = {"name": self.alias, "type": "host", "addresses": addresses, "detail": "Managed by FIRESTORM"}
                response = client.put(f"/api/v1/firewall/alias/{self.alias}", json=payload)
                response.raise_for_status()
                apply_response = client.post("/api/v1/firewall/alias/apply")
                apply_response.raise_for_status()
            return IntegrationResult(
                ok=True,
                mode="live",
                message=f"{'Blocked' if add else 'Unblocked'} {ip} in alias {self.alias}.",
                detail={"alias": self.alias, "addresses": addresses},
            )
        except httpx.HTTPError as exc:
            logger.warning("firewall API error: %s", type(exc).__name__)
            return IntegrationResult(ok=False, mode="live", message=f"Firewall API error: {type(exc).__name__}", detail={})

    def apply(self, target: str, *, reason: str) -> IntegrationResult:
        result = self._update_alias(target, add=True)
        result.detail.setdefault("reason", reason)
        return result

    def revert(self, target: str) -> IntegrationResult:
        return self._update_alias(target, add=False)


__all__ = ["PfSenseFirewall", "HealthStatus"]
