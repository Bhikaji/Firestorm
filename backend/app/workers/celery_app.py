"""Optional Celery application.

Celery is only required when ``FIRESTORM_CELERY_BROKER_URL`` is configured. In
single-node mode the same functions run inline or via cron/systemd timers, so a
broker is never a hard dependency.
"""

from __future__ import annotations

from app.core.config import settings

try:  # pragma: no cover - optional dependency
    from celery import Celery
except ImportError:  # pragma: no cover
    Celery = None  # type: ignore[assignment]


if Celery is not None:  # pragma: no cover - requires a broker
    celery_app = Celery(
        "firestorm",
        broker=settings.celery_broker_url or settings.redis_url or "redis://localhost:6379/0",
        backend=settings.celery_result_backend or settings.redis_url or "redis://localhost:6379/0",
    )
    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        worker_max_tasks_per_child=200,
        task_acks_late=True,
        broker_connection_retry_on_startup=True,
    )

    @celery_app.task(name="firestorm.retention")
    def retention_task() -> dict:
        from app.workers.tasks import apply_retention

        return apply_retention()

    @celery_app.task(name="firestorm.notifications")
    def notification_task() -> dict:
        from app.workers.tasks import dispatch_notifications

        return dispatch_notifications()

    @celery_app.task(name="firestorm.indicators")
    def indicator_task() -> dict:
        from app.workers.tasks import expire_indicators

        return expire_indicators()

    celery_app.conf.beat_schedule = {
        "notifications-every-minute": {"task": "firestorm.notifications", "schedule": 60.0},
        "retention-daily": {"task": "firestorm.retention", "schedule": 86400.0},
        "indicators-hourly": {"task": "firestorm.indicators", "schedule": 3600.0},
    }
else:  # pragma: no cover
    celery_app = None
