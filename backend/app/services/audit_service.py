"""Tamper-evident audit logging.

Each entry stores a SHA-256 over its canonical fields plus the previous
entry's hash. Editing or deleting an entry breaks the chain, which
``verify_chain`` detects. This is an integrity signal, not a substitute for
WORM storage or off-host log shipping (both documented in the security model).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import sanitize
from app.models.policy import AuditLog


def _canonical(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def _digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _last_hash(self) -> str | None:
        row = self.db.execute(select(AuditLog.entry_hash).order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(1)).first()
        return row[0] if row else None

    def record(
        self,
        *,
        action: str,
        actor_email: str = "system",
        actor_id: str | None = None,
        actor_role: str = "system",
        object_type: str = "",
        object_id: str | None = None,
        outcome: str = "success",
        detail: dict[str, Any] | None = None,
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> AuditLog:
        ts = datetime.now(UTC)
        previous = self._last_hash()
        safe_detail = sanitize(detail or {})
        body = {
            "ts": ts.isoformat(),
            "actor_id": actor_id,
            "actor_email": actor_email,
            "actor_role": actor_role,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "outcome": outcome,
            "detail": safe_detail,
            "client_ip": client_ip,
            "request_id": request_id,
            "previous_hash": previous,
        }
        entry = AuditLog(
            ts=ts,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            action=action,
            object_type=object_type,
            object_id=object_id,
            outcome=outcome,
            detail=safe_detail,
            client_ip=client_ip,
            request_id=request_id,
            previous_hash=previous,
            entry_hash=_digest(_canonical(body)),
        )
        self.db.add(entry)
        self.db.flush()
        return entry

    def verify_chain(self, limit: int = 10_000) -> dict[str, Any]:
        rows = (
            self.db.execute(select(AuditLog).order_by(AuditLog.ts.asc(), AuditLog.id.asc()).limit(limit))
            .scalars()
            .all()
        )
        previous: str | None = None
        for row in rows:
            body = {
                "ts": row.ts.isoformat(),
                "actor_id": row.actor_id,
                "actor_email": row.actor_email,
                "actor_role": row.actor_role,
                "action": row.action,
                "object_type": row.object_type,
                "object_id": row.object_id,
                "outcome": row.outcome,
                "detail": row.detail,
                "client_ip": row.client_ip,
                "request_id": row.request_id,
                "previous_hash": previous,
            }
            expected = _digest(_canonical(body))
            if row.previous_hash != previous or expected != row.entry_hash:
                return {
                    "valid": False,
                    "checked": len(rows),
                    "broken_at": row.id,
                    "message": "audit chain integrity check failed",
                }
            previous = row.entry_hash
        return {"valid": True, "checked": len(rows), "broken_at": None, "message": "audit chain intact"}
