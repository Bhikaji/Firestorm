"""Authorisation matrix: every privileged endpoint must reject under-privileged roles."""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import ensure_account, headers, login

ACTION_BODY = {
    "action_type": "block_ip",
    "target": "203.0.113.250",
    "reason": "authorization matrix probe",
}

SENSITIVE_ENDPOINTS = [
    ("GET", "/api/v1/audit", {"viewer", "analyst"}, None),
    ("GET", "/api/v1/users", {"viewer", "analyst", "responder"}, None),
    ("POST", "/api/v1/actions", {"viewer"}, ACTION_BODY),
    ("POST", "/api/v1/actions/does-not-exist/approve", {"viewer", "analyst", "responder"}, {}),
    ("PATCH", "/api/v1/policies/risk.thresholds", {"viewer", "analyst", "responder"}, {"config": {}}),
    (
        "POST",
        "/api/v1/admission-rules",
        {"viewer", "analyst", "responder"},
        {"name": "probe rule", "condition": {}, "outcome": "deny"},
    ),
    ("POST", "/api/v1/assets", {"viewer", "analyst"}, {"hostname": "probe", "ip_address": "10.9.9.9"}),
    (
        "POST",
        "/api/v1/users",
        {"viewer", "analyst", "responder"},
        {"email": "probe@example.com", "full_name": "Probe", "role": "viewer", "password": "Probe-Passw0rd!123"},
    ),
    ("POST", "/api/v1/integrations/test", {"viewer", "analyst"}, {}),
    (
        "POST",
        "/api/v1/actions/emergency-release",
        {"viewer", "analyst", "responder"},
        {"note": "authorization matrix probe"},
    ),
]


@pytest.mark.parametrize("method,path,denied_roles,body", SENSITIVE_ENDPOINTS)
def test_roles_are_denied(client, method, path, denied_roles, body):
    for role in sorted(denied_roles):
        email = f"sec-{role}-{uuid.uuid4().hex[:8]}@example.com"
        ensure_account(email, role)
        token = login(client, email)
        response = client.request(method, path, headers=headers(token), json=body)
        assert response.status_code == 403, f"{role} unexpectedly allowed on {method} {path}: {response.text}"


def test_unauthenticated_access_is_rejected(client):
    for _, path, _, _ in SENSITIVE_ENDPOINTS:
        response = client.get(path)
        assert response.status_code in {401, 405}, path


def test_expired_and_tampered_tokens_rejected(client):
    email = f"sec-token-{uuid.uuid4().hex[:8]}@example.com"
    ensure_account(email, "viewer")
    token = login(client, email)
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    assert client.get("/api/v1/alerts", headers=headers(tampered)).status_code == 401

    import jwt

    forged = jwt.encode(
        {"sub": "attacker", "role": "admin", "type": "access", "jti": "x", "iat": 0, "nbf": 0, "exp": 9999999999, "iss": "firestorm"},
        "wrong-secret-key-that-is-not-the-real-one",
        algorithm="HS256",
    )
    assert client.get("/api/v1/alerts", headers=headers(forged)).status_code == 401


def test_role_change_invalidates_existing_token(client, admin_headers):
    email = f"sec-rolechange-{uuid.uuid4().hex[:8]}@example.com"
    ensure_account(email, "viewer")
    token = login(client, email)
    assert client.get("/api/v1/alerts", headers=headers(token)).status_code == 200

    users = client.get("/api/v1/users", headers=admin_headers).json()["items"]
    target = next(user for user in users if user["email"] == email)
    updated = client.patch(f"/api/v1/users/{target['id']}", headers=admin_headers, json={"role": "analyst"})
    assert updated.status_code == 200

    # The old token carries the old role claim; it must no longer be accepted.
    assert client.get("/api/v1/alerts", headers=headers(token)).status_code == 401
