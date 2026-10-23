"""Integration registry.

Adapters are constructed from configuration at import time. All enforcement
adapters obey ``FIRESTORM_ENFORCEMENT_MODE``: in ``simulated`` mode the
simulation adapters are used even if live credentials exist, which is the
recommended posture for lab and passive-monitoring deployments.
"""

from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.integrations.base import (
    EnforcementIntegration,
    Integration,
    SimulatedEnforcement,
)
from app.integrations.firewall import PfSenseFirewall
from app.integrations.identity import LdapIdentity
from app.integrations.nac import UnifiNac
from app.integrations.sensors import (
    ClamAvScanner,
    OsqueryAgent,
    SuricataSensor,
    WazuhAgent,
    YaraScanner,
    ZeekSensor,
)


def _live_allowed() -> bool:
    return settings.enforcement_mode == "live"


class IntegrationRegistry:
    def __init__(self) -> None:
        self.firewall: EnforcementIntegration = self._pick(
            PfSenseFirewall(endpoint=None, token=None),
            SimulatedEnforcement(name="pfSense (simulated)", kind="firewall", layer="layer-7"),
        )
        self.nac: EnforcementIntegration = self._pick(
            UnifiNac(endpoint=None, token=None),
            SimulatedEnforcement(name="UniFi NAC (simulated)", kind="nac", layer="layer-7"),
        )
        self.edr: EnforcementIntegration = self._pick(
            self._edr_live(),
            SimulatedEnforcement(name="EDR isolation (simulated)", kind="edr", layer="layer-7"),
        )
        self.identity_service: EnforcementIntegration = self._pick(
            LdapIdentity(endpoint=None, token=None),
            SimulatedEnforcement(name="Identity provider (simulated)", kind="identity", layer="layer-7"),
        )
        self.dns_control: EnforcementIntegration = self._pick(
            SimulatedEnforcement(name="DNS sinkhole (simulated)", kind="dns", layer="layer-7")
            if settings.enforcement_mode != "live"
            else SimulatedEnforcement(name="DNS sinkhole (simulated)", kind="dns", layer="layer-7"),
            SimulatedEnforcement(name="DNS sinkhole (simulated)", kind="dns", layer="layer-7"),
        )

        self.sensors: list[Integration] = [
            SuricataSensor(),
            ZeekSensor(),
            WazuhAgent(),
            OsqueryAgent(),
            ClamAvScanner(),
            YaraScanner(),
        ]

    def _pick(self, live: EnforcementIntegration, simulated: EnforcementIntegration) -> EnforcementIntegration:
        if _live_allowed() and live.enabled:
            return live
        return simulated

    def _edr_live(self) -> EnforcementIntegration:
        # Wazuh active-response is the supported EDR isolation path.
        from app.integrations.edr import WazuhActiveResponse

        return WazuhActiveResponse(endpoint=None, token=None)

    # -- aggregate views -------------------------------------------------
    def all_integrations(self) -> list[Integration]:
        return [self.firewall, self.nac, self.edr, self.identity_service, self.dns_control, *self.sensors]

    def health(self) -> list[dict[str, Any]]:
        return [integration.health().as_dict() for integration in self.all_integrations()]

    def by_name(self, name: str) -> Integration | None:
        for integration in self.all_integrations():
            if name in {integration.name, integration.kind}:
                return integration
        return None

    def enforcement_for(self, action_type: str) -> EnforcementIntegration | None:
        return {
            "block_ip": self.firewall,
            "quarantine_asset": self.nac,
            "isolate_endpoint": self.edr,
            "disable_account": self.identity_service,
            "sinkhole_domain": self.dns_control,
        }.get(action_type)


_registry: IntegrationRegistry | None = None


def registry() -> IntegrationRegistry:
    global _registry
    if _registry is None:
        _registry = IntegrationRegistry()
    return _registry


def reset_registry() -> None:
    """Test helper: rebuild adapters after configuration changes."""
    global _registry
    _registry = None
