"""Authentication and authorisation behaviour."""

from __future__ import annotations

from app.tests.conftest import PASSWORDS, auth_headers, ensure_user, login


def test_login_returns_tokens_and_permissions(client):
    data = login(client, "analyst@example.com")
    assert data["role"] == "analyst"
    assert data["expires_in"] == 15 * 60

    me = client.get("/api/v1/auth/me", headers=auth_headers(data["access_token"]))
    assert me.status_code == 200
    permissions = me.json()["permissions"]
    assert "alert:triage" in permissions
    assert "action:approve" not in permissions


def test_wrong_password_is_rejected_without_leaking_account_existence(client):
    ensure_user("viewer@example.com", "viewer", PASSWORDS["viewer@example.com"][1])
    bad_password = client.post(
        "/api/v1/auth/login", json={"email": "viewer@example.com", "password": "wrong-password-123"}
    )
    unknown_user = client.post(
        "/api/v1/auth/login", json={"email": "ghost@example.com", "password": "wrong-password-123"}
    )
    assert bad_password.status_code == 401
    assert unknown_user.status_code == 401
    assert bad_password.json()["error"]["message"] == unknown_user.json()["error"]["message"]


def test_missing_token_is_unauthorized(client):
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401


def test_invalid_token_is_unauthorized(client):
    response = client.get("/api/v1/alerts", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401


def test_viewer_cannot_execute_response_actions(client, viewer_headers):
    response = client.post(
        "/api/v1/actions",
        headers=viewer_headers,
        json={"action_type": "block_ip", "target": "203.0.113.10", "reason": "attempted action by viewer"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_viewer_cannot_read_audit_log(client, viewer_headers):
    response = client.get("/api/v1/audit", headers=viewer_headers)
    assert response.status_code == 403


def test_analyst_can_read_but_not_approve(client, analyst_headers):
    assert client.get("/api/v1/incidents", headers=analyst_headers).status_code == 200
    response = client.post("/api/v1/actions/does-not-exist/approve", headers=analyst_headers, json={})
    assert response.status_code == 403


def test_refresh_rotation_and_reuse_detection(client):
    data = login(client, "responder@example.com")
    first = client.post("/api/v1/auth/refresh", json={"refresh_token": data["refresh_token"]})
    assert first.status_code == 200
    rotated = first.json()["refresh_token"]
    assert rotated != data["refresh_token"]

    reuse = client.post("/api/v1/auth/refresh", json={"refresh_token": data["refresh_token"]})
    assert reuse.status_code == 401
    assert "reuse" in reuse.json()["error"]["message"]

    after_reuse = client.post("/api/v1/auth/refresh", json={"refresh_token": rotated})
    assert after_reuse.status_code == 401


def test_logout_revokes_refresh_tokens(client):
    data = login(client, "responder@example.com")
    headers = auth_headers(data["access_token"])
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": data["refresh_token"]})
    assert refresh.status_code == 401


def test_password_change_enforces_policy(client):
    ensure_user("analyst@example.com", "analyst", PASSWORDS["analyst@example.com"][1])
    data = login(client, "analyst@example.com")
    headers = auth_headers(data["access_token"])
    weak = client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={"current_password": PASSWORDS["analyst@example.com"][1], "new_password": "short"},
    )
    assert weak.status_code in {401, 422}
    strong = client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={
            "current_password": PASSWORDS["analyst@example.com"][1],
            "new_password": "New-Analyst-Passw0rd!7",
        },
    )
    assert strong.status_code == 200
    # Restore the original password for other tests.
    db_login = client.post(
        "/api/v1/auth/login", json={"email": "analyst@example.com", "password": "New-Analyst-Passw0rd!7"}
    )
    restore = client.post(
        "/api/v1/auth/password",
        headers=auth_headers(db_login.json()["access_token"]),
        json={
            "current_password": "New-Analyst-Passw0rd!7",
            "new_password": PASSWORDS["analyst@example.com"][1],
        },
    )
    assert restore.status_code == 200


def test_mfa_enrolment_requires_valid_code(client):
    ensure_user("viewer@example.com", "viewer", PASSWORDS["viewer@example.com"][1])
    data = login(client, "viewer@example.com")
    headers = auth_headers(data["access_token"])
    setup = client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    assert "otpauth://" in setup.json()["provisioning_uri"]
    bad = client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": "000000"})
    assert bad.status_code == 401


def test_admin_user_creation_requires_strong_password(client, admin_headers):
    weak = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"email": "new@example.com", "full_name": "New User", "role": "viewer", "password": "password"},
    )
    assert weak.status_code == 422

    strong = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "new-analyst@example.com",
            "full_name": "New Analyst",
            "role": "analyst",
            "password": "Str0ng-New-Passw0rd!",
        },
    )
    assert strong.status_code == 201
    assert strong.json()["must_change_password"] is True
