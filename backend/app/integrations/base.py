"""Integration contracts.

Every adapter declares the layer it protects, its mode (``simulated`` or
``live``) and whether it is currently reachable. Enforcement adapters expose
``apply`` and ``revert`` so containment is always reversible and auditable.

A ``simulated`` adapter performs no changes to any real device; it records the
intent in ``enforcement_records`` with ``mode="simulated"`` so the UI can never
present it as real protection. A ``live`` adapter refuses to act when its
credentials or endpoint are missing instead of silently pretending success.
"""

from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger("firestorm.integrations")


@dataclass
class IntegrationResult:
    ok: bool
    mode: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None


@dataclass
class HealthStatus:
    name: str
    kind: str
    layer: str
    mode: str
    enabled: bool
    status: str  # healthy|degraded|unavailable|simulated|not_configured
    detail: str
    latency_ms: float | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "layer": self.layer,
            "mode": self.mode,
            "enabled": self.enabled,
            "status": self.status,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
            "checked_at": self.checked_at.isoformat(),
        }


class Integration(abc.ABC):
    name: str = "unnamed"
    kind: str = "generic"
    layer: str = "layer-1"
    simulated: bool = True

    @property
    def mode(self) -> str:
        return "simulated" if self.simulated else "live"

    @property
    def enabled(self) -> bool:
        return True

    @abc.abstractmethod
    def health(self) -> HealthStatus: ...


class EnforcementIntegration(Integration):
    """An integration able to change network/endpoint state."""

    @abc.abstractmethod
    def apply(self, target: str, *, reason: str) -> IntegrationResult: ...

    @abc.abstractmethod
    def revert(self, target: str) -> IntegrationResult: ...


class HTTPIntegration(Integration):
    """Base for live adapters that speak HTTP to an appliance API."""

    simulated = False

    def __init__(self, *, endpoint: str | None, token: str | None, timeout: float = 8.0) -> None:
        self.endpoint = (endpoint or "").rstrip("/")
        self.token = token
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.endpoint and self.token)

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.endpoint,
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            timeout=self.timeout,
            verify=True,
        )

    def health(self) -> HealthStatus:
        start = time.perf_counter()
        if not self.enabled:
            return HealthStatus(
                name=self.name,
                kind=self.kind,
                layer=self.layer,
                mode=self.mode,
                enabled=False,
                status="not_configured",
                detail="endpoint or API token not configured; adapter will refuse to act",
            )
        try:
            with self._client() as client:
                response = client.get("/health")
            latency = (time.perf_counter() - start) * 1000
            ok = response.status_code < 400
            return HealthStatus(
                name=self.name,
                kind=self.kind,
                layer=self.layer,
                mode=self.mode,
                enabled=True,
                status="healthy" if ok else "degraded",
                detail=f"HTTP {response.status_code} from {self.endpoint}/health",
                latency_ms=round(latency, 1),
            )
        except httpx.HTTPError as exc:
            return HealthStatus(
                name=self.name,
                kind=self.kind,
                layer=self.layer,
                mode=self.mode,
                enabled=True,
                status="unavailable",
                detail=f"{type(exc).__name__}: {exc}",
            )


class SimulatedEnforcement(EnforcementIntegration):
    """Records requested state without touching any device."""

    simulated = True

    def __init__(self, *, name: str, kind: str, layer: str) -> None:
        self.name = name
        self.kind = kind
        self.layer = layer

    def health(self) -> HealthStatus:
        return HealthStatus(
            name=self.name,
            kind=self.kind,
            layer=self.layer,
            mode=self.mode,
            enabled=True,
            status="simulated",
            detail="Simulation adapter: actions are recorded as intent only and change nothing on the network.",
        )

    def apply(self, target: str, *, reason: str) -> IntegrationResult:
        logger.info("SIMULATED enforcement %s -> %s", self.name, target)
        return IntegrationResult(
            ok=True,
            mode="simulated",
            message=f"Simulated {self.kind} for {target}; no production change was made.",
            detail={"reason": reason, "adapter": self.name},
            latency_ms=0.0,
        )

    def revert(self, target: str) -> IntegrationResult:
        return IntegrationResult(
            ok=True,
            mode="simulated",
            message=f"Simulated revert of {self.kind} for {target}.",
            detail={"adapter": self.name},
            latency_ms=0.0,
        )


def enforcement_mode() -> str:
    return settings.enforcement_mode
