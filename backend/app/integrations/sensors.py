"""Sensor and scanner integrations.

These adapters are honest about their state:

* ``suricata``/``zeek``/``wazuh``/``osquery`` report ``configured`` only when
  their log or API location is set and readable; otherwise ``not_configured``.
* ``clamav`` performs a real TCP ``PING``/``VERSION`` handshake against
  clamd when a host is configured, so health is genuinely verified.
* ``yara`` reports the number of compiled rule files present in the rules
  directory. Scanning through ``yara`` is done by the safe scanner service,
  never by executing a sample.

No adapter inspects payload content; only metadata and signatures are read.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

from app.core.config import settings
from app.integrations.base import HealthStatus, Integration


class SuricataSensor(Integration):
    name = "Suricata IDS"
    kind = "ids"
    layer = "layer-5"

    def health(self) -> HealthStatus:
        path = settings.suricata_eve_path
        if not path:
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=False,
                status="not_configured",
                detail="Set FIRESTORM_SURICATA_EVE_PATH to the eve.json location to enable live ingest.",
            )
        eve = Path(path)
        if not eve.exists():
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True,
                status="unavailable", detail=f"eve.json not found at {eve}",
            )
        age = time.time() - eve.stat().st_mtime
        status = "healthy" if age < 300 else "degraded"
        return HealthStatus(
            name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True, status=status,
            detail=f"eve.json last modified {int(age)}s ago ({eve.stat().st_size} bytes)",
        )


class ZeekSensor(Integration):
    name = "Zeek NSM"
    kind = "nsm"
    layer = "layer-1"

    def health(self) -> HealthStatus:
        path = settings.zeek_log_dir
        if not path:
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=False,
                status="not_configured",
                detail="Set FIRESTORM_ZEEK_LOG_DIR to the Zeek log directory to enable flow ingest.",
            )
        directory = Path(path)
        if not directory.is_dir():
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True,
                status="unavailable", detail=f"log directory not found at {directory}",
            )
        logs = sorted(p.name for p in directory.glob("*.log"))[:5]
        return HealthStatus(
            name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True, status="healthy",
            detail=f"log directory readable; sample logs: {', '.join(logs) or 'none yet'}",
        )


class WazuhAgent(Integration):
    name = "Wazuh manager"
    kind = "endpoint"
    layer = "layer-5"

    def health(self) -> HealthStatus:
        if not (settings.wazuh_endpoint and settings.wazuh_token):
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=False,
                status="not_configured",
                detail="Set FIRESTORM_WAZUH_ENDPOINT and FIRESTORM_WAZUH_TOKEN for endpoint telemetry and isolation.",
            )
        from app.integrations.edr import WazuhActiveResponse

        result = WazuhActiveResponse(endpoint=settings.wazuh_endpoint, token=settings.wazuh_token).health()
        result.name = self.name
        result.kind = self.kind
        result.layer = self.layer
        return result


class OsqueryAgent(Integration):
    name = "OSQuery fleet"
    kind = "inventory"
    layer = "layer-3"

    def health(self) -> HealthStatus:
        endpoint = settings.osquery_endpoint
        if not endpoint:
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=False,
                status="not_configured",
                detail="Set FIRESTORM_OSQUERY_ENDPOINT to the osquery TLS endpoint to enable posture collection.",
            )
        return HealthStatus(
            name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True, status="degraded",
            detail=f"Endpoint configured ({endpoint}); certificate pinning and query allowlist must be verified.",
        )


class ClamAvScanner(Integration):
    name = "ClamAV"
    kind = "antivirus"
    layer = "layer-4"

    def health(self) -> HealthStatus:
        host = settings.clamav_host
        if not host:
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=False,
                status="not_configured",
                detail="Set FIRESTORM_CLAMAV_HOST to enable real malware scanning of authorised files.",
            )
        start = time.perf_counter()
        try:
            with socket.create_connection((host, settings.clamav_port), timeout=3) as sock:
                sock.sendall(b"zVERSION\0")
                reply = sock.recv(512).decode("utf-8", "replace").strip("\0 ")
            latency = (time.perf_counter() - start) * 1000
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True, status="healthy",
                detail=f"clamd responded: {reply}", latency_ms=round(latency, 1),
            )
        except OSError as exc:
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True,
                status="unavailable", detail=f"clamd unreachable: {type(exc).__name__}",
            )


class YaraScanner(Integration):
    name = "YARA rules"
    kind = "pattern"
    layer = "layer-4"

    def health(self) -> HealthStatus:
        directory = settings.yara_rules_dir
        if not directory:
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=False,
                status="not_configured",
                detail="Set FIRESTORM_YARA_RULES_DIR to a directory of reviewed .yar rule files.",
            )
        path = Path(directory)
        if not path.is_dir():
            return HealthStatus(
                name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True,
                status="unavailable", detail=f"rules directory not found at {path}",
            )
        rules = [p for p in path.rglob("*.yar*") if p.is_file()]
        return HealthStatus(
            name=self.name, kind=self.kind, layer=self.layer, mode="live", enabled=True,
            status="healthy" if rules else "degraded",
            detail=f"{len(rules)} rule file(s) in {path}",
        )
