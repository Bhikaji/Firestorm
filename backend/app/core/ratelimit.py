"""In-process sliding-window rate limiting.

Suitable for a single API process and for tests. In a horizontally scaled
deployment set ``FIRESTORM_REDIS_URL`` and swap the store for Redis (see
``docs/architecture.md``); the interface is intentionally tiny so the
replacement is drop-in.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from app.core.errors import RateLimited


class SlidingWindowLimiter:
    def __init__(self, *, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, *, cost: int = 1) -> None:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) + cost > self.limit:
                retry = int(self.window - (now - bucket[0])) + 1 if bucket else self.window
                retry = max(retry, 1)
                raise RateLimited(
                    f"too many requests; try again in {retry} second{'s' if retry != 1 else ''}",
                    details={"retry_after_seconds": retry, "limit": self.limit, "window_seconds": self.window},
                )
            for _ in range(cost):
                bucket.append(now)

    def refund(self, key: str, *, cost: int = 1) -> None:
        """Give back consumed slots after a request proved itself legitimate.

        A successful sign-in is not an attack. If successes counted against the
        brute-force budget, an office behind a single NAT address would lock
        itself out after a handful of normal logins. Only failures keep their
        slot, so repeated wrong passwords still exhaust the limit quickly.
        """
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return
            for _ in range(min(cost, len(bucket))):
                bucket.pop()
            if not bucket:
                self._hits.pop(key, None)

    def remaining(self, key: str) -> int:
        """Slots left in the current window (diagnostics and headers)."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return self.limit
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return max(self.limit - len(bucket), 0)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _trusted_proxies() -> set[str]:
    from app.core.config import settings

    configured = {item.strip() for item in (settings.trusted_proxies or "").split(",") if item.strip()}
    return _LOOPBACK | configured


def client_key(request) -> str:
    """Best-effort client identity for rate limiting.

    ``X-Forwarded-For`` is only honoured when the request actually came from a
    trusted proxy (loopback by default, plus ``FIRESTORM_TRUSTED_PROXIES``).
    Otherwise any client could invent an address and dodge every limit.
    """
    peer = request.client.host if request.client else "unknown"
    if peer in _trusted_proxies():
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            candidate = forwarded.split(",")[0].strip()
            if candidate:
                return candidate
    return peer
