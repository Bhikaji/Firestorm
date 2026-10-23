"""Database engine, session factory and declarative base."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base shared by every model."""


def _create_engine() -> Engine:
    url = settings.database_url
    kwargs: dict[str, Any] = {"echo": settings.db_echo, "pool_pre_ping": True, "future": True}
    if url.startswith("sqlite"):
        # Ensure the parent directory exists for file-backed SQLite databases.
        path = url.split("sqlite:///", 1)[-1]
        if path and path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 15}
    else:
        kwargs.update(pool_size=10, max_overflow=20, pool_recycle=1800)
    return create_engine(url, **kwargs)


engine = _create_engine()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # pragma: no cover - driver hook
    if settings.database_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute(f"PRAGMA busy_timeout={settings.sqlite_busy_timeout_ms}")
        cursor.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a session and guarantees cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for background tasks and scripts."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Create tables directly (development/test convenience).

    Production deployments use Alembic migrations instead; see
    ``docs/installation.md``.
    """
    from app import models  # noqa: F401  (registers metadata)

    Base.metadata.create_all(bind=engine)
