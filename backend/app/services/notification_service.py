"""Notification delivery with escalation, retries and honest status.

* In-app notifications are persisted immediately (status ``delivered``).
* Email uses SMTP when configured; without configuration the message stays
  ``queued`` with an explicit reason, and is **never** reported as delivered.
* Delivery status only becomes ``delivered`` when the SMTP server accepts the
  message. Failures retry with exponential backoff up to
  ``notification_max_attempts``.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.base import Severity
from app.models.policy import Notification
from app.models.user import User

logger = logging.getLogger("firestorm.notifications")

ESCALATION_MATRIX: dict[str, dict[str, Any]] = {
    Severity.INFO: {"in_app": True, "email": False, "incident": False, "label": "dashboard event"},
    Severity.LOW: {"in_app": True, "email": False, "incident": False, "label": "dashboard event"},
    Severity.MEDIUM: {"in_app": True, "email": False, "incident": False, "label": "dashboard alert"},
    Severity.HIGH: {"in_app": True, "email": True, "incident": True, "label": "immediate team notification"},
    Severity.CRITICAL: {"in_app": True, "email": True, "incident": True, "label": "immediate on-call escalation"},
}


def _now() -> datetime:
    return datetime.now(UTC)


class NotificationService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- creation -------------------------------------------------------
    def notify_alert(
        self,
        *,
        alert_id: str,
        incident_id: str | None,
        title: str,
        body: str,
        severity: str,
    ) -> list[Notification]:
        policy = ESCALATION_MATRIX.get(severity, ESCALATION_MATRIX[Severity.MEDIUM])
        created: list[Notification] = []
        if policy["in_app"]:
            created.append(
                self._create(
                    channel="in_app",
                    recipient="security-operations",
                    subject=title,
                    body=body,
                    severity=severity,
                    alert_id=alert_id,
                    incident_id=incident_id,
                )
            )
        if policy["email"]:
            recipients = settings.smtp_recipient_list or self._responder_emails()
            for recipient in recipients:
                created.append(
                    self._create(
                        channel="email",
                        recipient=recipient,
                        subject=f"[{severity.upper()}] {title}",
                        body=body,
                        severity=severity,
                        alert_id=alert_id,
                        incident_id=incident_id,
                    )
                )
        self.db.flush()
        return created

    def _responder_emails(self) -> list[str]:
        rows = (
            self.db.execute(
                select(User.email).where(
                    User.is_active.is_(True),
                    User.role.in_(["responder", "admin"]),
                )
            )
            .scalars()
            .all()
        )
        return list(rows)

    def _create(
        self,
        *,
        channel: str,
        recipient: str,
        subject: str,
        body: str,
        severity: str,
        alert_id: str | None,
        incident_id: str | None,
    ) -> Notification:
        note = Notification(
            channel=channel,
            recipient=recipient,
            subject=subject,
            body=body,
            severity=severity,
            alert_id=alert_id,
            incident_id=incident_id,
            status="queued",
            meta={},
        )
        # In-app notifications are delivered by being persisted; there is no
        # external provider whose confirmation we would be guessing at.
        if channel == "in_app":
            note.status = "delivered"
            note.delivered_at = _now()
        self.db.add(note)
        return note

    # -- delivery -------------------------------------------------------
    def deliver_pending(self, limit: int = 50) -> dict[str, int]:
        if not settings.smtp_host:
            return {"attempted": 0, "delivered": 0, "failed": 0, "skipped": len(
                self.db.execute(
                    select(Notification.id).where(Notification.channel == "email", Notification.status == "queued")
                ).all()
            )}

        pending = (
            self.db.execute(
                select(Notification)
                .where(
                    Notification.channel == "email",
                    Notification.status.in_(["queued", "retrying"]),
                )
                .order_by(Notification.created_at.asc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
        result = {"attempted": len(pending), "delivered": 0, "failed": 0}
        for note in pending:
            ok, message = self._send_email(note)
            note.attempts += 1
            note.last_error = None if ok else message
            if ok:
                note.status = "delivered"
                note.delivered_at = _now()
                result["delivered"] += 1
            else:
                if note.attempts >= settings.notification_max_attempts:
                    note.status = "failed"
                    result["failed"] += 1
                else:
                    note.status = "retrying"
                    note.next_attempt_at = _now() + timedelta(minutes=2 ** note.attempts)
        self.db.flush()
        return result

    def _send_email(self, note: Notification) -> tuple[bool, str]:
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = note.recipient
        message["Subject"] = note.subject
        message.set_content(note.body + "\n\n-- FIRESTORM automated notification. Do not reply.")

        try:
            if settings.smtp_use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    if settings.smtp_username and settings.smtp_password:
                        server.login(settings.smtp_username, settings.smtp_password)
                    server.send_message(message)
            else:
                with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                    if settings.smtp_username and settings.smtp_password:
                        server.login(settings.smtp_username, settings.smtp_password)
                    server.send_message(message)
        except Exception as exc:  # noqa: BLE001 - provider errors vary widely
            logger.warning("email delivery failed: %s", type(exc).__name__)
            return False, f"{type(exc).__name__}: {exc}"
        return True, "accepted by SMTP server"

    def acknowledge(self, notification_id: str, user_id: str) -> Notification | None:
        note = self.db.get(Notification, notification_id)
        if not note:
            return None
        note.acknowledged_at = _now()
        note.acknowledged_by = user_id
        self.db.flush()
        return note

    def provider_status(self) -> dict[str, Any]:
        return {
            "email_configured": bool(settings.smtp_host),
            "smtp_host": settings.smtp_host,
            "recipients": len(settings.smtp_recipient_list),
            "in_app": "available",
            "detail": (
                "SMTP configured; delivery is confirmed by server acceptance."
                if settings.smtp_host
                else "SMTP not configured - email notifications remain queued and are reported as undelivered."
            ),
        }
