# Installation

Two supported paths: a local development setup (SQLite, no optional services)
and a containerised lab/production stack (PostgreSQL, Redis, Prometheus,
Grafana). Both require Python 3.12 (3.11 also works; containers and CI use 3.12) and Node 20+.

> **Authorisation first.** Do not point FIRESTORM at a network you do not own or
> have written authorisation to monitor. The platform will happily ingest
> telemetry it is given — authorisation is an organisational control, not a
> technical feature.

---

## 1. Local development (5 minutes)

```bash
git clone <your-fork> Firestorm && cd Firestorm

python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements-dev.txt

cp .env.example .env
# Generate real values - never keep the placeholders:
python -c "import secrets; print('FIRESTORM_SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "import secrets; print('FIRESTORM_INGEST_API_KEY=' + secrets.token_urlsafe(32))"
# Edit .env: set FIRESTORM_DATABASE_URL=sqlite:///./data/firestorm.db
#            set FIRESTORM_APP_ENV=development
#            set FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD=<strong password>
#            set FIRESTORM_DEMO_DATA=true (only for lab exploration)

cd backend
python scripts/bootstrap.py          # schema + policies + demo data
uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api to :8000
```

### Sign in

The bootstrap administrator account is created by `scripts/bootstrap.py` from
`FIRESTORM_BOOTSTRAP_ADMIN_EMAIL` / `FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD`. If no
password is configured, a strong one-time password is generated and printed
**once** to the console. Demo role accounts (analyst, responder, viewer) are
created only when `FIRESTORM_DEMO_DATA=true`, using
`FIRESTORM_DEMO_PASSWORD` if set (otherwise a random one-time password each).

Change the bootstrap password at first sign-in. The account is flagged
`must_change_password`.

### Then check the platform

```bash
curl -s localhost:8000/api/v1/health
curl -s localhost:8000/api/v1/ready
open http://localhost:5173
```

---

## 2. Docker Compose (lab / small production)

```bash
cp .env.example .env
# Set at minimum:
#   FIRESTORM_SECRET_KEY, FIRESTORM_INGEST_API_KEY,
#   POSTGRES_PASSWORD, GRAFANA_PASSWORD,
#   FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD,
#   FIRESTORM_CORS_ORIGINS and FIRESTORM_ALLOWED_HOSTS for your hostname

docker compose up --build -d
docker compose exec api python scripts/bootstrap.py     # run once
docker compose ps
```

| Service | URL | Notes |
| --- | --- | --- |
| Dashboard | `http://localhost:8080` | Behind nginx with CSP and rate limiting |
| API docs | `http://localhost:8080/api/docs` | Disable in production if policy requires |
| Prometheus | `http://127.0.0.1:9090` | Bound to loopback only |
| Grafana | `http://127.0.0.1:3000` | Bound to loopback only |

The Compose stack terminates TLS **outside** the container set. Put Caddy,
Traefik, nginx or a load balancer in front with a certificate from your CA, then
set `FIRESTORM_FORCE_HTTPS=true` and restrict `FIRESTORM_ALLOWED_HOSTS`.

The worker service runs Celery beat for retention, notification dispatch and
indicator expiry. If you prefer systemd, see
`infra/deployment/systemd/firestorm-worker.{service,timer}`.

---

## 3. Bare-metal / VM production

1. Provision PostgreSQL 15+ and create a least-privilege role:

   ```sql
   CREATE ROLE firestorm LOGIN PASSWORD '<strong>';
   CREATE DATABASE firestorm OWNER firestorm;
   REVOKE ALL ON SCHEMA public FROM PUBLIC;
   GRANT USAGE, CREATE ON SCHEMA public TO firestorm;
   ```

2. Install the application under `/opt/firestorm`, create a `firestorm` system
   user, and restrict permissions:

   ```bash
   sudo useradd --system --home /opt/firestorm --shell /usr/sbin/nologin firestorm
   sudo install -d -o firestorm -g firestorm -m 750 /opt/firestorm/{data,evidence,logs}
   sudo install -m 600 /dev/null /opt/firestorm/.env
   ```

3. Run migrations then bootstrap:

   ```bash
   cd /opt/firestorm/backend
   alembic upgrade head
   python scripts/bootstrap.py --no-demo      # production: no demo data
   ```

4. Install the service units:

   ```bash
   sudo cp infra/deployment/systemd/*.service infra/deployment/systemd/*.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now firestorm-api firestorm-worker.timer
   sudo systemctl status firestorm-api
   ```

5. Put nginx/Caddy in front using `infra/reverse-proxy/nginx.conf` as the
   template. Serve the built frontend (`cd frontend && npm ci && npm run build`,
   copy `dist/` to `/usr/share/nginx/html`).

6. Restrict network access: management console reachable only from the
   operations VLAN or via VPN/Zero Trust proxy. Never publish port 8000.

---

## 4. Kubernetes

`infra/deployment/kubernetes/firestorm.yaml` is a reference manifest with
non-root execution, read-only root filesystem, dropped capabilities, probes,
resource limits and a NetworkPolicy. Replace the placeholder secret values with
values from your secret manager (External Secrets, Vault, SOPS) — **do not**
commit real secrets, including in `stringData`.

---

## 5. Configuration reference

Every setting is an environment variable prefixed `FIRESTORM_`. Full list with
descriptions is in `.env.example`. Highlights:

| Variable | Default | Notes |
| --- | --- | --- |
| `FIRESTORM_SECRET_KEY` | empty | **Required in production.** ≥32 chars. JWT signing and token fingerprinting. |
| `FIRESTORM_DATABASE_URL` | `sqlite:///./data/firestorm.db` | Use `postgresql+psycopg://` in production. |
| `FIRESTORM_INGEST_API_KEY` | empty | When empty, the sensor ingestion endpoint is **disabled** (returns 401). |
| `FIRESTORM_ENFORCEMENT_MODE` | `simulated` | `live` requires appliance credentials; keep simulated until validated. |
| `FIRESTORM_REQUIRE_APPROVAL_FOR_CONTAINMENT` | `true` | Global approval gate. |
| `FIRESTORM_AUTO_CONTAINMENT_THRESHOLD` | `85` | Risk score below this always requires approval. |
| `FIRESTORM_CORS_ORIGINS` | localhost dev origins | Comma-separated exact origins. |
| `FIRESTORM_ALLOWED_HOSTS` | `*` | Restrict to your hostname in production. |
| `FIRESTORM_SMTP_*` | empty | Without SMTP, email notifications stay queued and are reported as undelivered. |
| `FIRESTORM_DEMO_DATA` | `true` (dev example) | Seeds synthetic lab data. Set `false` in production. |
| `FIRESTORM_DEMO_TRAFFIC` | `true` (dev example) | Enables the synthetic traffic generator. |
| `FIRESTORM_REDIS_URL` | empty | Optional cache/queue; the app runs single-process without it. |

### Integration credentials

Live adapters read these; empty values make the adapter report
`not_configured` and refuse enforcement actions:

* `FIRESTORM_FIREWALL_ENDPOINT`, `FIRESTORM_FIREWALL_TOKEN`,
  `FIRESTORM_FIREWALL_ALIAS`
* `FIRESTORM_NAC_ENDPOINT`, `FIRESTORM_NAC_TOKEN`,
  `FIRESTORM_NAC_QUARANTINE_VLAN`
* `FIRESTORM_EDR_ENDPOINT`, `FIRESTORM_EDR_TOKEN` (Wazuh active-response)
* `FIRESTORM_IDP_ENDPOINT`, `FIRESTORM_IDP_TOKEN` (SCIM-like account state)
* `FIRESTORM_SURICATA_EVE_PATH`, `FIRESTORM_ZEEK_LOG_DIR`
* `FIRESTORM_CLAMAV_HOST`, `FIRESTORM_CLAMAV_PORT`, `FIRESTORM_YARA_RULES_DIR`
* `FIRESTORM_SMTP_*` for notification delivery

Prerequisites per integration are in `docs/operations-runbook.md`.

---

## 6. Sending telemetry

Sensors authenticate with the shared ingestion key (not a user session):

```bash
curl -X POST http://localhost:8000/api/v1/telemetry/events \
  -H "X-API-Key: $FIRESTORM_INGEST_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "zeek",
    "sensor": "zeek-hq-01",
    "event_type": "flow",
    "severity": "info",
    "src_ip": "10.20.10.21",
    "dst_ip": "10.20.20.12",
    "dst_port": 443,
    "protocol": "tcp",
    "bytes_out": 4096,
    "external_id": "zeek-uid-1234"
  }'
```

Batch endpoint: `POST /api/v1/telemetry/events/batch` (≤500 events, returns
`accepted`/`duplicates`/`rejected`). Ingestion is idempotent on `external_id` or
a hash of the normalised fields, so retries are safe.

Reference collectors (ship Zeek `conn.log`, Suricata `eve.json`, Wazuh alerts)
are described in the operations runbook. They are deliberately thin: mapping
vendor fields to the ingestion schema is the only logic they contain.

---

## 7. Verification checklist after install

```bash
cd backend && pytest -q                    # unit tests
cd .. && PYTHONPATH=backend pytest tests -q # integration/security/performance
npm --prefix frontend run typecheck && npm --prefix frontend run build
```

Then in the UI:

1. **Protection layers** — every adapter should show its true state
   (`not_configured` where you have not configured it; that is expected).
2. **Event stream** — send the curl above; the event appears within seconds.
3. **Alerts** — send a `malware_detected` event and confirm an alert with a
   signal breakdown.
4. **Incidents** — open the incident created from a critical alert, collect
   evidence, verify its hash.
5. **Policies** — confirm default admission rules exist; admission fails closed.
6. **Audit trail** — run chain verification.

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Ingestion returns 401 | `FIRESTORM_INGEST_API_KEY` unset or mismatched | Set it and restart; use the same value in the collector |
| Login rejected with 422 | Email fails format validation | Use a full address; login accepts reserved TLDs such as `.local` |
| Dashboard empty, no errors | No telemetry ingested | Check sensor coverage and the event stream |
| Browser console shows CORS errors | `FIRESTORM_CORS_ORIGINS` missing your origin | Add the exact scheme+host+port |
| Live updates say "polling" | WebSocket blocked by proxy | Allow upgrade on `/api/v1/ws/` |
| Email notifications stay `queued` | SMTP not configured | Configure `FIRESTORM_SMTP_*`; delivery is only claimed on server acceptance |
| Actions fail with "not configured" | Live mode without credentials | Configure the adapter or return to `simulated` |
| 429 responses | Rate limit exceeded | Raise `FIRESTORM_RATE_LIMIT_PER_MINUTE` or investigate the client |
