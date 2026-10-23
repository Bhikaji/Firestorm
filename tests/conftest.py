"""Fixtures for repository-level integration, security and performance tests.

These tests exercise the running FastAPI application in-process with an
isolated SQLite database. They deliberately use only synthetic data.
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

TEMP_DIR = tempfile.mkdtemp(prefix="firestorm-e2e-")

os.environ.update(
    {
        "FIRESTORM_APP_ENV": "test",
        "FIRESTORM_DATABASE_URL": f"sqlite:///{Path(TEMP_DIR) / 'e2e.db'}",
        "FIRESTORM_SECRET_KEY": "e2e-secret-key-that-is-long-enough-0123456789",
        "FIRESTORM_DEMO_DATA": "false",
        "FIRESTORM_DEMO_TRAFFIC": "false",
        "FIRESTORM_ENFORCEMENT_MODE": "simulated",
        "FIRESTORM_INGEST_API_KEY": "e2e-ingest-key",
        "FIRESTORM_LOG_JSON": "false",
        "FIRESTORM_RATE_LIMIT_PER_MINUTE": "1000000",
        "FIRESTORM_LOGIN_ATTEMPTS_PER_15MIN": "1000",
        "FIRESTORM_SMTP_HOST": "",
    }
)

from app.core.database import Base, SessionLocal, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

PASSWORD = "Integration-Passw0rd!42"
ROLES = ["admin", "responder", "analyst", "viewer"]


@pytest.fixture(scope="session", autouse=True)
def schema():
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="session", autouse=True)
def seed_indicators(schema):
    """Install a synthetic threat indicator so detection tests are deterministic."""
    from app.services.threat_intel import import_indicators

    db = SessionLocal()
    try:
        import_indicators(
            db,
            [
                {
                    "type": "ip",
                    "value": "203.0.113.66",
                    "category": "c2",
                    "confidence": 95,
                    "severity": "critical",
                    "source": "e2e-lab",
                    "description": "Synthetic C2 indicator for integration tests.",
                },
                {
                    "type": "sha256",
                    "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    "category": "malware",
                    "confidence": 90,
                    "severity": "high",
                    "source": "e2e-lab",
                    "description": "EICAR test hash.",
                },
            ],
            source="e2e-lab",
            ttl_days=365,
        )
        db.commit()
    finally:
        db.close()


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


def ensure_account(email: str, role: str, password: str = PASSWORD) -> None:
    db = SessionLocal()
    try:
        existing = db.execute(select(User).where(User.email == email)).scalars().first()
        if existing is None:
            db.add(
                User(
                    email=email,
                    full_name=f"E2E {role.title()}",
                    role=role,
                    password_hash=hash_password(password),
                )
            )
            db.commit()
    finally:
        db.close()


def login(client: TestClient, email: str, password: str = PASSWORD) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_email() -> str:
    email = f"e2e-admin-{uuid.uuid4().hex[:8]}@example.com"
    ensure_account(email, "admin")
    return email


@pytest.fixture()
def admin_headers(client, admin_email) -> dict[str, str]:
    return headers(login(client, admin_email))
