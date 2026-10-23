"""Rate limiting behaviour.

The login budget exists to slow credential guessing. It must bite on repeated
failures, and it must not punish legitimate sign-ins - an office behind one NAT
address would otherwise lock itself out during a normal shift.
"""

from __future__ import annotations

import pytest

from app.core.errors import RateLimited
from app.core.ratelimit import SlidingWindowLimiter
from app.tests.conftest import PASSWORDS, ensure_user, login


def test_limiter_blocks_and_reports_wait_time():
    limiter = SlidingWindowLimiter(limit=2, window_seconds=60)
    limiter.check("ip")
    limiter.check("ip")
    with pytest.raises(RateLimited) as excinfo:
        limiter.check("ip")
    error = excinfo.value
    assert error.status_code == 429
    assert error.details["retry_after_seconds"] >= 1
    assert "try again in" in error.message


def test_refund_returns_a_slot():
    limiter = SlidingWindowLimiter(limit=1, window_seconds=60)
    limiter.check("ip")
    with pytest.raises(RateLimited):
        limiter.check("ip")
    limiter.refund("ip")
    limiter.check("ip")  # allowed again


def test_refund_on_empty_bucket_is_a_no_op():
    limiter = SlidingWindowLimiter(limit=3, window_seconds=60)
    limiter.refund("never-seen")  # must not raise
    limiter.check("never-seen")


def test_successful_logins_do_not_consume_the_budget(client):
    from app.api import deps

    email = "analyst@example.com"
    ensure_user(email, PASSWORDS[email][0], PASSWORDS[email][1])

    limiter = deps.login_limiter
    original_limit = limiter.limit
    limiter.reset()
    limiter.limit = 1
    try:
        for _ in range(3):
            assert login(client, email)["role"] == "analyst"

        # Failures keep their slot, so guessing is still throttled.
        wrong = {"email": email, "password": "definitely-wrong-password"}
        assert client.post("/api/v1/auth/login", json=wrong).status_code == 401
        blocked = client.post("/api/v1/auth/login", json=wrong)
        assert blocked.status_code == 429
        body = blocked.json()["error"]
        assert body["code"] == "rate_limited"
        assert body["details"]["retry_after_seconds"] >= 1
    finally:
        limiter.limit = original_limit
        limiter.reset()


def test_bad_passwords_for_one_account_do_not_block_another(client):
    """Colleagues sharing a NAT address must not lock each other out."""
    from app.api import deps

    victim = "analyst@example.com"
    colleague = "admin@example.com"
    ensure_user(victim, PASSWORDS[victim][0], PASSWORDS[victim][1])
    ensure_user(colleague, PASSWORDS[colleague][0], PASSWORDS[colleague][1])

    limiter = deps.account_limiter
    original_limit = limiter.limit
    limiter.reset()
    limiter.limit = 2
    try:
        wrong = {"email": victim, "password": "wrong-password-here"}
        assert client.post("/api/v1/auth/login", json=wrong).status_code == 401
        assert client.post("/api/v1/auth/login", json=wrong).status_code == 401
        assert client.post("/api/v1/auth/login", json=wrong).status_code == 429

        # The other account is untouched by the first account's failures.
        assert login(client, colleague)["role"] == "admin"
    finally:
        limiter.limit = original_limit
        limiter.reset()


def test_forwarded_header_is_ignored_from_untrusted_peers():
    """A client must not be able to spoof its address to dodge rate limits."""

    class FakeRequest:
        def __init__(self, peer: str, forwarded: str | None = None) -> None:
            self.client = type("C", (), {"host": peer})()
            self.headers = {"x-forwarded-for": forwarded} if forwarded else {}

    from app.core.ratelimit import client_key

    # Direct internet client: the header is ignored, the socket address wins.
    assert client_key(FakeRequest("198.51.100.7", "1.2.3.4")) == "198.51.100.7"
    # Local reverse proxy: the header is the client's real address.
    assert client_key(FakeRequest("127.0.0.1", "203.0.113.9, 127.0.0.1")) == "203.0.113.9"
    # No header at all.
    assert client_key(FakeRequest("127.0.0.1")) == "127.0.0.1"
