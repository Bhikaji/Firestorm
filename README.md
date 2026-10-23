# FIRESTORM

**A defensive, explainable security operations platform for networks you own.**

FIRESTORM ingests network and endpoint telemetry, detects threats with
deterministic rules, scores risk on a 0–100 scale it can justify line by line,
runs incidents with evidence and chain of custody, and contains compromised
devices through approvals that a human must actually grant.

> **Authorisation required.** Use FIRESTORM only on networks, devices and data
> you own or are contracted in writing to protect. It performs no offensive
> actions, no counter-attacks, no exploitation and no scanning of external
> systems. Enforcement is out-of-band (firewall/NAC/EDR) and off by default.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Layer 8  SOC & recovery        incidents · evidence · audit · reports   │
│  Layer 7  Automated containment  approvals · four-eyes · reversible      │
│  Layer 6  East-west movement     internal telemetry · lateral analytics  │
│  Layer 5  IDS/IPS                13 deterministic detection rules        │
│  Layer 4  Malware scanning       signatures · hashes · ClamAV · YARA     │
│  Layer 3  Pre-access posture     posture score · fail-closed admission   │
│  Layer 2  Device identity        inventory · enrolment · multi-signal    │
│  Layer 1  Network visibility     flows · DNS · TLS metadata · sensors    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## What works today

| Area | State |
| --- | --- |
| Telemetry ingest (single + batch, idempotent, authenticated) | ✅ tested |
| 13-rule detection engine with weighted, explained signals | ✅ tested |
| Risk engine, bands 0–19 / 20–39 / 40–59 / 60–79 / 80–100 | ✅ tested |
| Alerts, dedupe, triage, time-boxed suppressions | ✅ tested |
| Incidents, notes, correlations, state machine | ✅ tested |
| Evidence hashing, custody, re-verification | ✅ tested |
| Containment workflow with four-eyes approval and revert | ✅ tested |
| Business-critical allowlist, emergency release | ✅ tested |
| RBAC, MFA, token rotation, lockout, rate limits, audit chain | ✅ tested |
| Dashboards, 8-layer health, reports, CSV export | ✅ tested |
| Email delivery | 🟡 needs SMTP to verify |
| Live appliances (pfSense, UniFi, LDAP, Wazuh, ClamAV, YARA…) | ⛔ awaiting integration |
| Enforcement | 🔵 simulated by default; nothing changes on the network |

Full matrix, including gaps and non-goals: **[docs/feature-status.md](docs/feature-status.md)**.
Nothing in this repository claims a live integration works without a real
service answering.

---

## Quickstart — local (SQLite, no optional services)

Requires Python 3.12 (3.11 also works) and Node 20+.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements-dev.txt

cp .env.example .env
python -c "import secrets; print('FIRESTORM_SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "import secrets; print('FIRESTORM_INGEST_API_KEY=' + secrets.token_urlsafe(32))"
# edit .env:
#   FIRESTORM_DATABASE_URL=sqlite:///./data/firestorm.db
#   FIRESTORM_APP_ENV=development
#   FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD=<strong password>
#   FIRESTORM_DEMO_DATA=true   # optional: labelled demonstration data

cd backend
../.venv/bin/python scripts/bootstrap.py      # schema, policies, demo data
../.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Second terminal:

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 — proxies /api to :8000
```

### Sign in

The administrator comes from `.env`
(`FIRESTORM_BOOTSTRAP_ADMIN_EMAIL` / `FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD`).
With the `.env` shipped in this checkout (development only):

| Role | Email | Password |
| --- | --- | --- |
| Admin | `admin@firestorm.example.com` | `Firestorm-Admin!2026` |
| Analyst | `analyst@firestorm.example.com` | `Firestorm-Demo!2026` |
| Responder | `responder@firestorm.example.com` | `Firestorm-Demo!2026` |
| Viewer | `viewer@firestorm.example.com` | `Firestorm-Demo!2026` |
| Approver | `approver@firestorm.example.com` | `Firestorm-Demo!2026` |

> These are **development credentials** for the local SQLite lab. The demo role
> accounts are flagged `must_change_password`. Never reuse these values, and
> never deploy with the sample `.env` — regenerate `FIRESTORM_SECRET_KEY`,
> `FIRESTORM_INGEST_API_KEY` and every password. `.env` is git-ignored.

---

## Quickstart — containers

```bash
cp .env.example .env
# set POSTGRES_PASSWORD, GRAFANA_PASSWORD, FIRESTORM_SECRET_KEY, FIRESTORM_INGEST_API_KEY,
# FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD; leave FIRESTORM_ENFORCEMENT_MODE=simulated
docker compose up --build -d
docker compose exec api python scripts/bootstrap.py
```

| Service | URL |
| --- | --- |
| FIRESTORM console | http://localhost:8080 |
| API docs (OpenAPI) | http://localhost:8000/api/docs |
| Prometheus | http://127.0.0.1:9090 |
| Grafana | http://127.0.0.1:3000 |

The console must sit behind an authenticating proxy if it is reachable from
outside your management network. See **[docs/installation.md](docs/installation.md)**
for bare-metal, systemd, Kubernetes and integration configuration.

---

## Repository layout

```
backend/
  app/api/          routers: auth, telemetry, alerts, assets, incidents, reports, system
  app/core/         config, database, security, permissions, rate limiting, errors, logging
  app/models/       SQLAlchemy models (users, assets, telemetry, alerts, incidents, audit)
  app/schemas/      Pydantic request/response models
  app/services/     detection rules, risk engine, posture/admission, response engine,
                    evidence, audit chain, notifications, reports, dashboard
  app/integrations/ sensor and enforcement adapters (simulated + live)
  app/workers/      retention, dispatch, indicator expiry (inline, Celery or systemd)
  app/tests/        63 backend tests
  migrations/       Alembic (head c7e5e3c7e401)
  scripts/          bootstrap.py
frontend/           React 18 + TypeScript + Vite + Tailwind SPA ("FIRESTORM COMMAND")
tests/              integration, security and performance tests (26)
infra/              Dockerfiles, nginx, Prometheus/Grafana/OTel, systemd, Kubernetes, backup
docs/               architecture, installation, security model, runbook, DR, API, status
```

---

## Everyday commands

```bash
# Tests
cd backend && ../.venv/bin/python -m pytest -q                  # 63 backend tests
cd .. && PYTHONPATH=backend .venv/bin/python -m pytest tests -q # 26 repo-level tests

# Lint / types
.venv/bin/ruff check backend tests
.venv/bin/mypy backend/app                                       # configured, advisory

# Frontend
cd frontend && npm run typecheck && npm run build

# Migrations
cd backend && ../.venv/bin/alembic upgrade head
cd backend && ../.venv/bin/alembic downgrade -1 && ../.venv/bin/alembic upgrade head

# Backup (encrypted, verified)
BACKUP_DIR=/var/backups/firestorm BACKUP_PASSPHRASE_FILE=/etc/firestorm/backup.key \
FIRESTORM_DATABASE_URL="$FIRESTORM_DATABASE_URL" \
./infra/deployment/scripts/backup.sh
```

### Send a test event

```bash
curl -sX POST http://localhost:8000/api/v1/telemetry/events \
  -H "X-API-Key: $FIRESTORM_INGEST_API_KEY" -H 'Content-Type: application/json' \
  -d '{"source":"ops-selftest","event_type":"dns_query","severity":"high",
       "src_ip":"10.20.4.31","dns_query":"c2.synthetic-lab.example",
       "external_id":"selftest-1"}'
# → {"accepted":1,"duplicates":0,"rejected":0,"alerts_created":1,"errors":[]}
```

---

## Design commitments

* **Explainable, not magic.** Risk is arithmetic over named signals; every score
  returns its contributions, confidence and band. No opaque model can isolate a
  host.
* **Fail closed.** Unknown devices get restricted access, not trust. Unknown
  integration state is reported, not assumed healthy.
* **Human authority.** Destructive actions need an approver who is not the
  requester; guaranteed for account suspension. Business-critical assets are
  exempt from automation, and every change is reversible and recorded.
* **Evidence you can trust.** Canonical JSON, SHA-256 at collection, append-only
  custody entries, a hash-chained audit log with a verification endpoint.
* **Honest interfaces.** Real empty/loading/error/stale states. Demo data is
  labelled. Simulated enforcement says `mode: simulated`. Email is not
  "delivered" until the SMTP server accepts it.
* **Boring, maintained components.** bcrypt, PyJWT, SQLAlchemy, FastAPI, ClamAV,
  YARA, Zeek/Suricata — no hand-rolled cryptography, AV engine or packet parser.

---

## Documentation

| Document | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, data model, rules R-0001…R-0013, response state machine |
| [Installation](docs/installation.md) | Local, Compose, systemd, Kubernetes, configuration reference |
| [API reference](docs/api.md) | Every endpoint, auth, errors, pagination, cURL cookbook |
| [Security model](docs/security-model.md) | Assets, trust boundaries, STRIDE, RBAC, limitations |
| [Incidents & evidence](docs/incidents-and-evidence.md) | Lifecycle, custody, approval policy, reports |
| [Incident response](docs/incident-response.md) | Analyst playbook: triage, containment, recovery, review |
| [Operations runbook](docs/operations-runbook.md) | Health checks, failure playbooks, integrations, escalation |
| [Disaster recovery](docs/disaster-recovery.md) | Backups, restore rehearsal, partial failures |
| [Feature status](docs/feature-status.md) | Implemented / partial / simulated / awaiting integration |

---

## Scope and limits

Defensive monitoring only, on authorised networks. No offensive tooling, no
external scanning, no counter-attack, no malware execution. Out of scope:
inline packet blocking, sandbox detonation, SSO, multi-tenancy, high
availability, and attribution. See
[docs/security-model.md §10](docs/security-model.md#10-known-limitations).
