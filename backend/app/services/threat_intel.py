"""Threat-intelligence lookups.

The default provider is a local, database-backed indicator set so the platform
is fully functional offline. ``FeedProvider`` subclasses are the extension
point for commercial or community feeds; a network fetch is only attempted
when credentials and an endpoint URL are configured, and every fetched feed is
verified before import (see ``docs/security-model.md``).

Nothing in this module ever claims an indicator match proves attribution.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.policy import ThreatIndicator

logger = logging.getLogger("firestorm.threat_intel")


@dataclass(frozen=True)
class IndicatorMatch:
    indicator: str
    indicator_type: str
    category: str
    confidence: int
    severity: str
    source: str
    description: str | None


class ThreatIntelService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def lookup_ip(self, ip: str | None) -> IndicatorMatch | None:
        if not ip:
            return None
        return self._first(ip, "ip")

    def lookup_domain(self, domain: str | None) -> IndicatorMatch | None:
        if not domain:
            return None
        normalised = domain.strip().lower().rstrip(".")
        match = self._first(normalised, "domain")
        if match:
            return match
        # Also match parent domains so sub.example-bad.tld hits example-bad.tld.
        parts = normalised.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            parent_match = self._first(parent, "domain")
            if parent_match:
                return parent_match
        return None

    def lookup_hash(self, file_hash: str | None) -> IndicatorMatch | None:
        if not file_hash:
            return None
        return self._first(file_hash.lower(), "sha256")

    def lookup_url(self, url: str | None) -> IndicatorMatch | None:
        if not url:
            return None
        return self._first(url.strip().lower(), "url")

    def is_external(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )

    def _first(self, value: str, kind: str) -> IndicatorMatch | None:
        now = datetime.now(UTC)
        stmt = (
            select(ThreatIndicator)
            .where(
                ThreatIndicator.indicator == value,
                ThreatIndicator.indicator_type == kind,
                ThreatIndicator.active.is_(True),
                or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now),
            )
            .limit(1)
        )
        row = self.db.execute(stmt).scalars().first()
        if not row:
            return None
        return IndicatorMatch(
            indicator=row.indicator,
            indicator_type=row.indicator_type,
            category=row.category,
            confidence=row.confidence,
            severity=row.severity,
            source=row.source,
            description=row.description,
        )

    def active_count(self) -> int:
        now = datetime.now(UTC)
        return len(
            self.db.execute(
                select(ThreatIndicator.id).where(
                    ThreatIndicator.active.is_(True),
                    or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > now),
                )
            ).all()
        )

    def expire_stale(self) -> int:
        now = datetime.now(UTC)
        rows = (
            self.db.execute(
                select(ThreatIndicator).where(
                    ThreatIndicator.active.is_(True),
                    ThreatIndicator.expires_at.is_not(None),
                    ThreatIndicator.expires_at < now,
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            row.active = False
        self.db.flush()
        return len(rows)


class FeedProvider:
    """Base class for an external indicator feed.

    Subclasses must set ``name`` and implement ``fetch``. ``fetch`` returns
    normalised tuples; verification (signature or checksum) is done by the
    caller before ``ThreatIntelService.import_indicators`` is invoked.
    """

    name = "base"
    signed = False

    def fetch(self) -> list[dict]:
        raise NotImplementedError

    def health(self) -> tuple[bool, str]:
        return False, "feed provider not configured"


class ManualFeed(FeedProvider):
    """Operator-supplied indicators (always available, never remote)."""

    name = "manual"

    def __init__(self, indicators: list[dict]) -> None:
        self._indicators = indicators

    def fetch(self) -> list[dict]:
        return list(self._indicators)

    def health(self) -> tuple[bool, str]:
        return True, f"manual feed ready ({len(self._indicators)} indicators)"


def import_indicators(db: Session, indicators: list[dict], *, source: str, ttl_days: int = 30) -> int:
    """Upsert indicators. Unknown types are rejected rather than guessed."""
    allowed = {"ip", "domain", "sha256", "url"}
    imported = 0
    now = datetime.now(UTC)
    for item in indicators:
        kind = item.get("type", "").lower()
        value = (item.get("value") or "").strip()
        if kind not in allowed or not value:
            continue
        row = db.execute(select(ThreatIndicator).where(ThreatIndicator.indicator == value)).scalars().first()
        expires = item.get("expires_at") or now + timedelta(days=ttl_days)
        if row is None:
            row = ThreatIndicator(
                indicator=value,
                indicator_type=kind,
                category=item.get("category", "unknown"),
                confidence=int(item.get("confidence", 50)),
                severity=item.get("severity", "medium"),
                source=item.get("source", source),
                description=item.get("description"),
                expires_at=expires,
                active=True,
            )
            db.add(row)
        else:
            row.category = item.get("category", row.category)
            row.confidence = int(item.get("confidence", row.confidence))
            row.severity = item.get("severity", row.severity)
            row.source = item.get("source", row.source)
            row.description = item.get("description", row.description)
            row.expires_at = expires
            row.active = True
        imported += 1
    db.flush()
    return imported
