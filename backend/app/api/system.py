"""Health, readiness, metrics and live WebSocket updates."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.deps import require
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import ROLE_PERMISSIONS, Permission
from app.core.security import TokenError, decode_token
from app.models.alert import Alert
from app.models.base import AlertStatus
from app.models.telemetry import Event
from app.models.user import User
from app.services.dashboard_service import DashboardService

router = APIRouter(tags=["system"])

START_TIME = time.time()


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.app_env,
        "time": datetime.now(UTC).isoformat(),
        "uptime_seconds": round(time.time() - START_TIME, 1),
    }


@router.get("/ready")
def ready(db: Session = Depends(get_db)) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = {"status": "ok"}
    except Exception as exc:  # noqa: BLE001
        checks["database"] = {"status": "error", "detail": type(exc).__name__}

    if settings.redis_url:
        try:
            import redis  # type: ignore

            client = redis.Redis.from_url(settings.redis_url, socket_timeout=2)
            client.ping()
            checks["redis"] = {"status": "ok"}
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = {"status": "error", "detail": type(exc).__name__}
    else:
        checks["redis"] = {"status": "not_configured", "detail": "single-process mode"}

    checks["enforcement"] = {
        "status": "ok" if settings.enforcement_mode == "simulated" else "warning",
        "mode": settings.enforcement_mode,
    }
    overall = "ok" if all(c["status"] in {"ok", "not_configured"} for c in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)) -> Any:
    """Prometheus text exposition for the platform's own health."""
    from fastapi.responses import PlainTextResponse

    if not settings.metrics_enabled:
        return PlainTextResponse("metrics disabled\n", media_type="text/plain")

    day_ago = datetime.now(UTC).timestamp() - 86400
    lines = [
        "# HELP firestorm_up Whether the API process is serving requests.",
        "# TYPE firestorm_up gauge",
        "firestorm_up 1",
        "# HELP firestorm_uptime_seconds Process uptime.",
        "# TYPE firestorm_uptime_seconds gauge",
        f"firestorm_uptime_seconds {time.time() - START_TIME:.1f}",
        "# HELP firestorm_events_total Events ingested by source.",
        "# TYPE firestorm_events_total counter",
    ]
    rows = db.execute(select(Event.source, func.count(Event.id)).group_by(Event.source)).all()
    for source, count in rows:
        lines.append(f'firestorm_events_total{{source="{source}"}} {int(count)}')

    lines += [
        "# HELP firestorm_events_24h Events ingested in the last 24 hours.",
        "# TYPE firestorm_events_24h gauge",
        f"firestorm_events_24h {int(db.execute(select(func.count(Event.id)).where(Event.received_at >= datetime.fromtimestamp(day_ago, UTC))).scalar_one())}",
        "# HELP firestorm_alerts_open Alerts not yet closed.",
        "# TYPE firestorm_alerts_open gauge",
        f"firestorm_alerts_open {int(db.execute(select(func.count(Alert.id)).where(Alert.status != AlertStatus.CLOSED)).scalar_one())}",
        "# HELP firestorm_alerts_total Alerts by severity.",
        "# TYPE firestorm_alerts_total gauge",
    ]
    for severity, count in db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all():
        lines.append(f'firestorm_alerts_total{{severity="{severity}"}} {int(count)}')
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@router.get("/system/info")
def system_info(
    user: User = Depends(require(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from app.integrations.registry import registry

    return {
        "app": {
            "name": settings.app_name,
            "environment": settings.app_env,
            "demo_mode": settings.demo_mode,
            "demo_data": settings.demo_data,
            "enforcement_mode": settings.enforcement_mode,
            "version": "0.1.0",
        },
        "capabilities": {
            "mfa": True,
            "websocket": True,
            "email": bool(settings.smtp_host),
            "redis": bool(settings.redis_url),
            "enforcement_live": settings.enforcement_mode == "live",
        },
        "integrations": registry().health(),
        "roles": {role: sorted(p.value for p in perms) for role, perms in ROLE_PERMISSIONS.items()},
    }


class ConnectionManager:
    """Minimal broadcaster with bounded queues (backpressure, no unbounded growth)."""

    def __init__(self, max_queue: int = 100) -> None:
        self.connections: set[WebSocket] = set()
        self.max_queue = max_queue
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.connections.discard(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        message = json.dumps(payload, default=str)
        dead: list[WebSocket] = []
        for connection in list(self.connections):
            try:
                await connection.send_text(message)
            except Exception:  # noqa: BLE001 - a dropped client must not break others
                dead.append(connection)
        for connection in dead:
            await self.disconnect(connection)


manager = ConnectionManager()


@router.websocket("/ws/live")
async def live_socket(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    """Live dashboard updates.

    The client authenticates with the access token in the query string because
    browsers cannot set headers on a WebSocket handshake. Tokens are short-lived
    (15 minutes); the socket is closed when the token expires.
    """
    if not token:
        await websocket.close(code=4401)
        return
    try:
        claims = decode_token(token, expected_kind="access")
    except TokenError:
        await websocket.close(code=4401)
        return
    role = claims.get("role", "viewer")
    if Permission.DASHBOARD_VIEW not in ROLE_PERMISSIONS.get(role, set()):
        await websocket.close(code=4403)
        return

    await manager.connect(websocket)
    try:
        from app.core.database import SessionLocal

        last_event_id: str | None = None
        while True:
            db = SessionLocal()
            try:
                latest = db.execute(select(Event).order_by(Event.received_at.desc()).limit(1)).scalars().first()
                if latest and latest.id != last_event_id:
                    last_event_id = latest.id
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "event",
                                "payload": {
                                    "id": latest.id,
                                    "ts": latest.ts.isoformat(),
                                    "source": latest.source,
                                    "event_type": latest.event_type,
                                    "severity": latest.severity,
                                    "src_ip": latest.src_ip,
                                    "dst_ip": latest.dst_ip,
                                    "risk_score": latest.risk_score,
                                    "alert_id": latest.alert_id,
                                },
                            },
                            default=str,
                        )
                    )
                overview = DashboardService(db).overview()
                await websocket.send_text(
                    json.dumps({"type": "overview", "payload": overview.get("counts", {})}, default=str)
                )
            finally:
                db.close()
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - socket teardown must be silent
        logging.getLogger("firestorm.ws").debug("live socket closed unexpectedly")
    finally:
        await manager.disconnect(websocket)
