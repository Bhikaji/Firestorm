#!/usr/bin/env python3
"""Create the database schema, seed policies and (in demo mode) lab data.

Usage:
    python scripts/bootstrap.py            # schema + policies + demo data
    python scripts/bootstrap.py --no-demo  # schema + policies only
    python scripts/bootstrap.py --reset    # destructive: drop all tables first

Set FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD before running in any shared
environment; otherwise a strong one-time password is generated and printed
once.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings  # noqa: E402
from app.core.database import Base, engine, init_db, session_scope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the FIRESTORM database")
    parser.add_argument("--no-demo", action="store_true", help="skip demo/lab data")
    parser.add_argument("--reset", action="store_true", help="DESTRUCTIVE: drop all tables first")
    args = parser.parse_args()

    if args.reset:
        if settings.is_production:
            print("Refusing to reset a production database. Set FIRESTORM_APP_ENV=development to override.")
            return 2
        confirm = os.environ.get("FIRESTORM_RESET_CONFIRM", "")
        if confirm != "yes":
            print("Refusing to drop tables: set FIRESTORM_RESET_CONFIRM=yes to confirm.")
            return 2
        import app.models  # noqa: F401

        Base.metadata.drop_all(bind=engine)
        print("Dropped all tables.")

    init_db()
    print("Schema ready.")

    if args.no_demo:
        settings.demo_data = False

    from app.services.seed import seed_all

    with session_scope() as db:
        counts = seed_all(db)

    print("Seeding complete:", counts)
    print()
    print("Sign in at the dashboard with the administrator account:")
    print(f"  email: {settings.bootstrap_admin_email}")
    if settings.bootstrap_admin_password:
        print("  password: (from FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD)")
    else:
        print("  password: printed above when the admin account was first created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
