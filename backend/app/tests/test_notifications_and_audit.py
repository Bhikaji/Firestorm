"""Notification honesty/retry behaviour and audit-chain integrity."""

from __future__ import annotations

import uuid

from sqlalchemy import select, update

from app.core.database import SessionLocal
from app.models.base import Severity
from app.models.policy import AuditLog, Notification
from app.services.audit_service import AuditService
from app.services.notification_service import ESCALATION_MATRIX, NotificationService


def test_escalation_matrix_matches_requirements():
    assert ESCALATION_MATRIX[Severity.INFO]["email"] is False
    assert ESCALATION_MATRIX[Severity.MEDIUM]["email"] is False
    assert ESCALATION_MATRIX[Severity.HIGH]["email"] is True
    assert ESCALATION_MATRIX[Severity.CRITICAL]["email"] is True
    assert ESCALATION_MATRIX[Severity.CRITICAL]["incident"] is True


def test_in_app_notification_is_delivered_immediately():
    db = SessionLocal()
    try:
        service = NotificationService(db)
        created = service.notify_alert(
            alert_id=str(uuid.uuid4()),
            incident_id=None,
            title="Test alert",
            body="Synthetic body",
            severity=Severity.MEDIUM,
        )
        db.commit()
        in_app = [n for n in created if n.channel == "in_app"]
        assert in_app and in_app[0].status == "delivered"
        assert in_app[0].delivered_at is not None
    finally:
        db.close()


def test_email_is_not_claimed_delivered_without_smtp():
    db = SessionLocal()
    try:
        service = NotificationService(db)
        created = service.notify_alert(
            alert_id=str(uuid.uuid4()),
            incident_id=None,
            title="Critical alert",
            body="Synthetic body",
            severity=Severity.CRITICAL,
        )
        db.commit()
        db.refresh(created[0])
        result = service.deliver_pending()
        db.commit()
        email_rows = db.execute(select(Notification).where(Notification.channel == "email")).scalars().all()
        for row in email_rows:
            assert row.status != "delivered"
        assert result["delivered"] == 0
    finally:
        db.close()


def test_delivery_retries_and_then_fails(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "smtp_host", "smtp.invalid")
    monkeypatch.setattr(settings, "notification_max_attempts", 2)
    db = SessionLocal()
    try:
        service = NotificationService(db)
        note = Notification(
            channel="email",
            recipient="soc@example.test",
            subject="Retry test",
            body="body",
            severity="high",
            status="queued",
        )
        db.add(note)
        db.commit()

        monkeypatch.setattr(NotificationService, "_send_email", lambda self, n: (False, "connection refused"))
        first = service.deliver_pending(limit=100)
        db.commit()
        db.refresh(note)
        assert note.attempts == 1
        assert note.status == "retrying"
        assert note.next_attempt_at is not None

        service.deliver_pending(limit=100)
        db.commit()
        db.refresh(note)
        assert note.attempts == 2
        assert note.status == "failed"
        assert "refused" in (note.last_error or "")
        assert first["failed"] >= 0
    finally:
        db.close()


def test_audit_chain_detects_tampering():
    db = SessionLocal()
    try:
        audit = AuditService(db)
        audit.record(action="test.action", actor_email="tester@example.test", detail={"step": 1})
        audit.record(action="test.action", actor_email="tester@example.test", detail={"step": 2})
        db.commit()
        assert audit.verify_chain()["valid"] is True

        row = db.execute(select(AuditLog).order_by(AuditLog.ts.desc()).limit(1)).scalars().first()
        db.execute(update(AuditLog).where(AuditLog.id == row.id).values(action="tampered.action"))
        db.commit()
        result = AuditService(db).verify_chain()
        assert result["valid"] is False
    finally:
        db.close()


def test_sanitizer_removes_control_characters():
    from app.core.logging import sanitize

    payload = "line1\r\nFAKE LOG ENTRY \x1b[31m"
    cleaned = sanitize(payload)
    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert "\x1b" not in cleaned
    assert sanitize({"password": "hunter2"})["password"] == "[redacted]"
    assert len(sanitize("x" * 5000)) == 512
