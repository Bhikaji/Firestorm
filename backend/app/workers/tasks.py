"""Background maintenance tasks.

Runnable in three ways:

* **inline** - ``python -m app.workers.tasks <task>`` for a single node;
* **Celery** - ``celery -A app.workers.celery_app worker`` when a broker is set;
* **scheduler** - any external scheduler calling the module entry point.

All tasks are idempotent and safe to run concurrently (they operate on rows,
not on in-memory state).
"""

from __future__ import annotations

import argparse
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from app.core.config import settings
from app.core.database import session_scope
from app.models.alert import Alert, Suppression
from app.models.base import AlertStatus
from app.models.policy import Notification, Policy
from app.models.telemetry import Event
from app.services.notification_service import NotificationService
from app.services.threat_intel import ThreatIntelService

logger = logging.getLogger("firestorm.workers")


def _now() -> datetime:
    return datetime.now(UTC)


def retention_policy() -> dict:
    with session_scope() as db:
        row = db.execute(select(Policy).where(Policy.key == "ingest.retention")).scalars().first()
        return row.config if row and row.enabled else {"events_days": 90, "alerts_days": 365}


def apply_retention() -> dict:
    """Delete telemetry and closed alerts past their retention window."""
    config = retention_policy()
    now = _now()
    events_cutoff = now - timedelta(days=int(config.get("events_days", 90)))
    alerts_cutoff = now - timedelta(days=int(config.get("alerts_days", 365)))

    with session_scope() as db:
        events = db.execute(
            delete(Event).where(Event.ts < events_cutoff, Event.alert_id.is_(None))
        ).rowcount
        alerts = db.execute(
            delete(Alert).where(
                Alert.last_seen < alerts_cutoff,
                Alert.status == AlertStatus.CLOSED,
                Alert.incident_id.is_(None),
            )
        ).rowcount
        suppress = db.execute(
            delete(Suppression).where(Suppression.expires_at < now - timedelta(days=30))
        ).rowcount
        logger.info("retention applied", extra={"path": "retention_policy"})
    return {"events_deleted": events, "alerts_deleted": alerts, "suppressions_deleted": suppress}


def dispatch_notifications() -> dict:
    with session_scope() as db:
        result = NotificationService(db).deliver_pending()
    return result


def expire_indicators() -> dict:
    with session_scope() as db:
        expired = ThreatIntelService(db).expire_stale()
    return {"expired": expired}


def close_stale_notifications() -> dict:
    """Mark notifications that exhausted retries as failed (never as delivered)."""
    with session_scope() as db:
        rows = (
            db.execute(
                select(Notification).where(
                    Notification.status == "retrying",
                    Notification.attempts >= settings.notification_max_attempts,
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            row.status = "failed"
    return {"failed": len(rows)}


TASKS = {
    "retention": apply_retention,
    "notifications": dispatch_notifications,
    "indicators": expire_indicators,
    "close_stale_notifications": close_stale_notifications,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="FIRESTORM maintenance tasks")
    parser.add_argument("task", choices=[*TASKS.keys(), "all"])
    args = parser.parse_args()
    names = list(TASKS) if args.task == "all" else [args.task]
    for name in names:
        print(name, "->", TASKS[name]())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
