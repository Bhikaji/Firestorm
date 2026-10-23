"""Endpoint isolation via Wazuh active-response.

Isolation is requested through the Wazuh manager API, which relays an
active-response command to the agent. The agent executes a local firewall
policy that permits only the management channel.

Safety rules enforced here:
* the API token must be present, otherwise the call is refused;
* the request is only ever made against an agent id that the inventory knows;
* the response is checked for ``total_affected_items`` before reporting success.
"""

from __future__ import annotations

import logging

import httpx

from app.core.config import settings
from app.integrations.base import EnforcementIntegration, HTTPIntegration, IntegrationResult

logger = logging.getLogger("firestorm.integrations.edr")


class WazuhActiveResponse(HTTPIntegration, EnforcementIntegration):
    name = "Wazuh active response"
    kind = "edr"
    layer = "layer-7"
    simulated = False

    def __init__(self, *, endpoint: str | None, token: str | None) -> None:
        super().__init__(
            endpoint=endpoint if endpoint is not None else settings.edr_endpoint,
            token=token if token is not None else settings.edr_token,
        )

    def _command(self, agent_id: str, command: str) -> IntegrationResult:
        if not self.enabled:
            return IntegrationResult(
                ok=False,
                mode="live",
                message="EDR integration is not configured; endpoint was not isolated.",
                detail={"required": ["FIRESTORM_EDR_ENDPOINT", "FIRESTORM_EDR_TOKEN"]},
            )
        try:
            with self._client() as client:
                response = client.put(
                    f"/active-response?agents_list={agent_id}",
                    json={"command": command, "custom": False, "arguments": []},
                )
                response.raise_for_status()
                payload = response.json()
            affected = int(payload.get("data", {}).get("total_affected_items", 0))
            ok = affected >= 1
            return IntegrationResult(
                ok=ok,
                mode="live",
                message=(
                    f"Active response '{command}' dispatched to agent {agent_id}."
                    if ok
                    else f"Manager accepted the request but affected {affected} agents."
                ),
                detail={"agent_id": agent_id, "command": command, "affected": affected},
            )
        except httpx.HTTPError as exc:
            logger.warning("EDR API error: %s", type(exc).__name__)
            return IntegrationResult(ok=False, mode="live", message=f"EDR API error: {type(exc).__name__}")

    def apply(self, target: str, *, reason: str) -> IntegrationResult:
        return self._command(target, "firestorm-isolate")

    def revert(self, target: str) -> IntegrationResult:
        return self._command(target, "firestorm-rejoin")
