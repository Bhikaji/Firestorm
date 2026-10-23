"""Malformed, oversized and hostile input must fail safely."""

from __future__ import annotations

import uuid

INGEST = {"X-API-Key": "e2e-ingest-key"}


def test_event_type_pattern_rejects_injection(client):
    payload = {
        "source": "zeek",
        "event_type": "flow\nFAKE LOG ENTRY",
        "severity": "info",
    }
    response = client.post("/api/v1/telemetry/events", json=payload, headers=INGEST)
    assert response.status_code == 422


def test_oversized_field_is_rejected(client):
    payload = {
        "source": "zeek",
        "event_type": "flow",
        "dns_query": "a" * 5000,
    }
    response = client.post("/api/v1/telemetry/events", json=payload, headers=INGEST)
    assert response.status_code == 422


def test_oversized_request_body_is_rejected(client):
    huge = {"source": "zeek", "event_type": "flow", "raw": {"blob": "x" * 2_100_000}}
    response = client.post("/api/v1/telemetry/events", json=huge, headers=INGEST)
    assert response.status_code in {413, 422}


def test_sql_metacharacters_are_stored_literally(client, admin_headers):
    hostile = "'; DROP TABLE alerts; --"
    asset = client.post(
        "/api/v1/assets",
        headers=admin_headers,
        json={
            "hostname": f"host-{uuid.uuid4().hex[:6]}",
            "ip_address": f"10.77.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}",
            "owner": hostile,
        },
    )
    assert asset.status_code == 201
    fetched = client.get(f"/api/v1/assets/{asset.json()['id']}", headers=admin_headers)
    assert fetched.status_code == 200
    assert fetched.json()["owner"] == hostile

    search = client.get("/api/v1/assets", headers=admin_headers, params={"q": "DROP TABLE"})
    assert search.status_code == 200
    assert search.json()["total"] >= 1

    alerts = client.get("/api/v1/alerts", headers=admin_headers)
    assert alerts.status_code == 200


def test_invalid_uuid_and_unknown_ids_return_404(client, admin_headers):
    assert client.get("/api/v1/incidents/not-a-real-id", headers=admin_headers).status_code == 404
    assert client.get(f"/api/v1/assets/{uuid.uuid4()}", headers=admin_headers).status_code == 404


def test_negative_and_out_of_range_values_rejected(client):
    for payload in (
        {"source": "zeek", "event_type": "flow", "dst_port": -1},
        {"source": "zeek", "event_type": "flow", "dst_port": 70000},
        {"source": "zeek", "event_type": "flow", "bytes_out": -5},
    ):
        response = client.post("/api/v1/telemetry/events", json=payload, headers=INGEST)
        assert response.status_code == 422, payload


def test_security_headers_present(client):
    response = client.get("/api/v1/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "X-Request-ID" in response.headers


def test_login_response_does_not_leak_password_hash(client):
    email = f"leak-{uuid.uuid4().hex[:8]}@example.com"
    from tests.conftest import ensure_account

    ensure_account(email, "viewer")
    response = client.post("/api/v1/auth/login", json={"email": email, "password": "Integration-Passw0rd!42"})
    assert response.status_code == 200
    body = response.text.lower()
    assert "password_hash" not in body
    assert "$2b$" not in body
    assert "mfa_secret" not in body
