"""Test harness.

Environment is configured *before* application import so settings resolve to a
throwaway SQLite database, test secret key and no external integrations.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

import pytest

TEMP_DIR = tempfile.mkdtemp(prefix="firestorm-tests-")
DB_PATH = Path(TEMP_DIR) / "test.db"

os.environ.update(
    {
        "FIRESTORM_APP_ENV": "test",
        "FIRESTORM_DATABASE_URL": f"sqlite:///{DB_PATH}",
        "FIRESTORM_SECRET_KEY": "test-secret-key-that-is-long-enough-1234567890",
        "FIRESTORM_DEMO_DATA": "false",
        "FIRESTORM_DEMO_TRAFFIC": "false",
        "FIRESTORM_ENFORCEMENT_MODE": "simulated",
        "FIRESTORM_INGEST_API_KEY": "test-ingest-key",
        "FIRESTORM_LOG_JSON": "false",
        "FIRESTORM_RATE_LIMIT_PER_MINUTE": "100000",
        "FIRESTORM_LOGIN_ATTEMPTS_PER_15MIN": "1000",
        "FIRESTORM_SMTP_HOST": "",
        "FIRESTORM_REQUIRE_APPROVAL_FOR_CONTAINMENT": "true",
    }
)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.database import Base, SessionLocal, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _schema():
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


PASSWORDS = {
    "admin@example.com": ("admin", "Admin-Passw0rd!2026"),
    "responder@example.com": ("responder", "Responder-Passw0rd!2026"),
    "analyst@example.com": ("analyst", "Analyst-Passw0rd!2026"),
    "viewer@example.com": ("viewer", "Viewer-Passw0rd!2026"),
}


def ensure_user(email: str, role: str, password: str) -> User:
    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.email == email)).scalars().first()
        if user is None:
            user = User(
                email=email,
                full_name=f"Test {role.title()}",
                role=role,
                password_hash=hash_password(password),
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return user
    finally:
        db.close()


def login(client: TestClient, email: str) -> dict:
    role, password = PASSWORDS[email]
    ensure_user(email, role, password)
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_headers(client) -> dict[str, str]:
    return auth_headers(login(client, "admin@example.com")["access_token"])


@pytest.fixture()
def responder_headers(client) -> dict[str, str]:
    return auth_headers(login(client, "responder@example.com")["access_token"])


@pytest.fixture()
def analyst_headers(client) -> dict[str, str]:
    return auth_headers(login(client, "analyst@example.com")["access_token"])


@pytest.fixture()
def viewer_headers(client) -> dict[str, str]:
    return auth_headers(login(client, "viewer@example.com")["access_token"])


@pytest.fixture()
def ingest_headers() -> dict[str, str]:
    return {"X-API-Key": "test-ingest-key"}


@pytest.fixture()
def unique_ip() -> str:
    """Documentation-range IP unique per test to isolate correlation windows."""
    suffix = uuid.uuid4().int % 250 + 1
    return f"198.51.100.{suffix}"
