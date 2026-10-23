"""Network access control / VLAN quarantine integration (UniFi controller).

Placing a device on a restricted VLAN is the preferred containment action
because it keeps the endpoint reachable for remediation while cutting it off
from production resources. When no controller is configured the registry
substitutes a simulation adapter.
"""

from __future__ import annotations

import logging

import httpx

from app.core.config import settings
from app.integrations.base import EnforcementIntegration, HTTPIntegration, IntegrationResult

logger = logging.getLogger("firestorm.integrations.nac")


class UnifiNac(HTTPIntegration, EnforcementIntegration):
    name = "UniFi NAC"
    kind = "nac"
    layer = "layer-7"
    simulated = False

    def __init__(self, *, endpoint: str | None, token: str | None) -> None:
        super().__init__(
            endpoint=endpoint if endpoint is not None else settings.nac_endpoint,
            token=token if token is not None else settings.nac_token,
        )
        self.quarantine_vlan = settings.nac_quarantine_vlan

    def _move_vlan(self, mac: str, vlan: int | None) -> IntegrationResult:
        if not self.enabled:
            return IntegrationResult(
                ok=False,
                mode="live",
                message="NAC controller is not configured; the device was not moved.",
                detail={"required": ["FIRESTORM_NAC_ENDPOINT", "FIRESTORM_NAC_TOKEN"]},
            )
        try:
            with self._client() as client:
                lookup = client.get("/proxy/network/api/s/default/stat/sta", params={"mac": mac})
                lookup.raise_for_status()
                clients = lookup.json().get("data", [])
                if not clients:
                    return IntegrationResult(
                        ok=False, mode="live", message=f"MAC {mac} is not currently connected to the controller."
                    )
                client_id = clients[0]["_id"]
                body = {"name": "firestorm-quarantine"} if vlan else {"name": "firestorm-restored"}
                payload = {"networkconf_id": str(vlan) if vlan else ""}
                response = client.put(
                    f"/proxy/network/api/s/default/rest/user/{client_id}",
                    json={**payload, "note": body["name"], "usergroup_id": ""},
                )
                response.raise_for_status()
            return IntegrationResult(
                ok=True,
                mode="live",
                message=f"Device {mac} moved to VLAN {vlan}." if vlan else f"VLAN override cleared for {mac}.",
                detail={"mac": mac, "vlan": vlan},
            )
        except httpx.HTTPError as exc:
            logger.warning("NAC API error: %s", type(exc).__name__)
            return IntegrationResult(ok=False, mode="live", message=f"NAC API error: {type(exc).__name__}")

    def apply(self, target: str, *, reason: str) -> IntegrationResult:
        result = self._move_vlan(target, self.quarantine_vlan)
        result.detail.setdefault("reason", reason)
        return result

    def revert(self, target: str) -> IntegrationResult:
        return self._move_vlan(target, None)
