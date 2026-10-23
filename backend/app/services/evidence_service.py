"""Evidence collection with hashing and chain-of-custody.

Evidence bodies are canonicalised to JSON, hashed with SHA-256, and written to
``FIRESTORM_EVIDENCE_DIR`` (default ``./data/evidence``). Bodies are only
written to disk when the directory is writable; the hash and metadata are
always stored so integrity can be re-verified even if the blob is archived
elsewhere.

Sensitive content: evidence is restricted to roles with ``incident:read`` and
every collection action is audited. Email samples and file hashes are stored as
metadata only by default - raw message bodies require an explicit
``content`` payload from an authorised analyst.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFound, ValidationFailed
from app.models.incident import Evidence, IncidentTimelineEvent
from app.models.telemetry import Event
from app.models.user import User
from app.services.audit_service import AuditService


def _canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class EvidenceService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)
        self.root = Path(os.environ.get("FIRESTORM_EVIDENCE_DIR", "./data/evidence"))

    def collect(
        self,
        *,
        actor: User,
        kind: str,
        label: str,
        incident_id: str | None,
        alert_id: str | None = None,
        event_ids: list[str] | None = None,
        file_hash: str | None = None,
        content: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        if not (incident_id or alert_id):
            raise ValidationFailed("evidence must be linked to an incident or an alert")

        bundle: dict[str, Any] = {
            "kind": kind,
            "label": label,
            "collected_at": datetime.now(UTC).isoformat(),
            "alert_id": alert_id,
            "incident_id": incident_id,
            "metadata": metadata or {},
        }
        if file_hash:
            bundle["file_hash"] = file_hash.lower()
        if content:
            bundle["content"] = content
        if event_ids:
            rows = self.db.execute(select(Event).where(Event.id.in_(event_ids[:200]))).scalars().all()
            if not rows:
                raise NotFound("none of the requested events exist")
            bundle["events"] = [
                {
                    "id": e.id,
                    "ts": e.ts.isoformat(),
                    "source": e.source,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "src_port": e.src_port,
                    "dst_port": e.dst_port,
                    "dns_query": e.dns_query,
                    "file_hash": e.file_hash,
                    "signature": e.signature,
                }
                for e in rows
            ]

        body = _canonical(bundle)
        digest = hashlib.sha256(body).hexdigest()
        storage_path = self._persist(digest, body)

        evidence = Evidence(
            incident_id=incident_id,
            alert_id=alert_id,
            kind=kind,
            label=label,
            sha256=digest,
            size_bytes=len(body),
            storage_path=storage_path,
            collected_by=actor.email,
            source="firestorm",
            custody=[
                {
                    "ts": datetime.now(UTC).isoformat(),
                    "actor": actor.email,
                    "action": "collected",
                    "sha256": digest,
                }
            ],
            metadata_json=metadata or {},
            sealed=True,
        )
        self.db.add(evidence)
        self.db.flush()

        if incident_id:
            self.db.add(
                IncidentTimelineEvent(
                    incident_id=incident_id,
                    ts=datetime.now(UTC),
                    kind="evidence",
                    actor=actor.email,
                    message=f"Collected evidence '{label}' (sha256 {digest[:16]}...)",
                    payload={"evidence_id": evidence.id, "kind": kind},
                )
            )
        self.audit.record(
            action="evidence.collected",
            actor_id=actor.id,
            actor_email=actor.email,
            actor_role=actor.role,
            object_type="evidence",
            object_id=evidence.id,
            detail={"incident_id": incident_id, "alert_id": alert_id, "sha256": digest, "kind": kind},
        )
        self.db.flush()
        return evidence

    def _persist(self, digest: str, body: bytes) -> str | None:
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            target = self.root / f"{digest}.json"
            if not target.exists():
                target.write_bytes(body)
            return str(target)
        except OSError:
            # Read-only deployments keep the hash and metadata only.
            return None

    def verify(self, evidence_id: str) -> dict[str, Any]:
        record = self.db.get(Evidence, evidence_id)
        if not record:
            raise NotFound("evidence not found")
        if not record.storage_path or not Path(record.storage_path).exists():
            return {
                "id": record.id,
                "verified": None,
                "detail": "blob is not stored locally; compare the recorded SHA-256 with the archived copy",
                "sha256": record.sha256,
            }
        body = Path(record.storage_path).read_bytes()
        actual = hashlib.sha256(body).hexdigest()
        return {
            "id": record.id,
            "verified": actual == record.sha256,
            "detail": "content matches recorded hash" if actual == record.sha256 else "hash mismatch - treat evidence as tampered",
            "sha256": record.sha256,
            "actual_sha256": actual,
        }
