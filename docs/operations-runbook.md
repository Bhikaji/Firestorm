# Operations runbook

Everything an on-call operator needs: what healthy looks like, how to verify it,
what to do when it is not, and which integrations must be enabled before the
platform's claims are true.

---

## 1. Service map

| Component | Process | Port | Required | Failure impact |
| --- | --- | --- | --- | --- |
| API | uvicorn `app.main:app` | 8000 (internal) | Yes | No UI, no ingest, no response |
| Web | nginx serving the built SPA | 8080 | Yes | No human interface (API keeps working) |
| Database | PostgreSQL 16 (or SQLite in dev) | 5432 | Yes | Everything stops |
| Redis | optional | 6379 | No | Queue-based features only; API continues |
| Worker | Celery / systemd timer | — | No | Scheduled dispatch, retention, reports delayed |
| Prometheus | monitoring | 9090 (loopback) | No | No metrics/alerts |
| Grafana | monitoring | 3000 (loopback) | No | No dashboards |
| Reverse proxy | nginx + TLS | 443 | Production only | No external access |

---

## 2. Health checks

```bash
# Liveness — the process is serving
curl -fsS http://127.0.0.1:8000/api/v1/health

# Readiness — dependencies
curl -sS http://127.0.0.1:8000/api/v1/ready | jq
```

`/ready` returns HTTP 200 with a body of:
`{"status":"ok"|"degraded","checks":{"database":…,"redis":…,"enforcement":…}}`.
Gate deploys on the body's `status`, not the HTTP status code alone.

| Check | Healthy | Action when not |
| --- | --- | --- |
| `database` | `ok` | Check the DB service, credentials, connection pool; restart API after recovery |
| `redis` | `not_configured` (optional) or `ok` | If configured and failing: check the URL/password; optional features degrade |
| `enforcement` | `ok` + `mode: simulated` in lab, `warning` + `live` in production | Confirm the mode is the one you intend. Never run live in the lab |
| `uptime_seconds` | increasing | A reset means the process restarted — check logs |

### Every shift

```bash
# API + readiness
curl -s http://127.0.0.1:8000/api/v1/ready | jq -r '.status'

# Telemetry freshness: last-seen per source (staleness > 15 min is a blind spot)
TOKEN=$(curl -sX POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@firestorm.example.com","password":"…"}' | jq -r .access_token)
curl -s http://127.0.0.1:8000/api/v1/telemetry/sources -H "Authorization: Bearer $TOKEN" | jq

# Pending approvals (a growing queue means containment is blocked)
curl -s "http://127.0.0.1:8000/api/v1/actions?status=pending_approval" \
  -H "Authorization: Bearer $TOKEN" | jq '.total'

# Failed notifications
curl -s "http://127.0.0.1:8000/api/v1/notifications?status=failed" \
  -H "Authorization: Bearer $TOKEN" | jq '.total'

# Audit chain integrity (weekly and after any deploy)
curl -s http://127.0.0.1:8000/api/v1/audit/verify -H "Authorization: Bearer $TOKEN" | jq
```

### Prometheus

Scrape `/api/v1/metrics` (restrict at the proxy; it is unauthenticated by
design so Prometheus works without a token). Exposed series:
`firestorm_up`, `firestorm_uptime_seconds`, `firestorm_events_total{source}`,
`firestorm_events_24h`, `firestorm_alerts_open`,
`firestorm_alerts_total{severity}`, plus process metrics when enabled.

Bundled alerts (`infra/monitoring/alerts.yml`):

| Alert | Meaning | First response |
| --- | --- | --- |
| `FirestormApiDown` | API unreachable 2 min | Check process, DB, disk; restart; page the owner |
| `FirestormTelemetryStalled` | No events for 20 min | Check sensors, ingestion key, staleness on the Layers page |
| `FirestormAlertBacklog` | >50 open alerts for 30 min | Add triage capacity; check for a duplicate-storm or broken rule |
| `FirestormCriticalAlerts` | Unresolved critical alerts | Confirm incident ownership and escalation |

---

## 3. Routine tasks

| Task | Cadence | Command / place |
| --- | --- | --- |
| Verify readiness and telemetry freshness | Every shift | §2 |
| Review pending approvals and failed notifications | Every shift | §2 |
| Verify audit chain | Weekly + after deploy | `GET /audit/verify` |
| Test backup restore | Quarterly | `docs/disaster-recovery.md` |
| Rotate the ingestion key | Quarterly or on staff change | Update `.env`, restart API, roll sensors |
| Rotate `FIRESTORM_SECRET_KEY` | On suspected compromise | Invalidates all sessions — do it in a maintenance window |
| Review suppressions | Weekly | `/alerts/suppressions/list?active_only=true` |
| Review users, roles, inactive accounts | Monthly | `/users` |
| Dependency and image updates | Monthly | CI audit output, then rebuild |
| Retention job | Nightly | Worker / `firestorm-worker.timer` |

---

## 4. Incident: platform failures

### API will not start

1. `journalctl -u firestorm-api -n 200 --no-pager` (or `docker compose logs api`).
2. Common causes: invalid `.env` (e.g. `ENFORCEMENT_MODE` typo), database
   unreachable, migration not applied, secret key shorter than required.
3. If migrations are behind: `cd backend && ../.venv/bin/alembic upgrade head`.
4. If the DB is corrupt, follow `docs/disaster-recovery.md` rather than editing
   rows by hand.

### Dashboard loads but every panel is empty

Not a UI bug until proven otherwise. Check in order: `/ready` → `/telemetry/sources`
→ `/dashboard/overview` `generated_at`. Empty panels with a fresh timestamp and
zero events mean ingestion is broken, not rendering.

### Telemetry stopped

1. Confirm the sensor's clock and network path.
2. `curl -i -X POST …/telemetry/events -H "X-API-Key: …"` — expect `202`.
   `401` = wrong key; `429` = backpressure; `422` = schema drift.
3. Check `GET /telemetry/sources` for `last_seen` and per-source counts.
4. If only one source is stale, the problem is that sensor. If all are, suspect
   the proxy, the API or the key.

### Alerts not firing

1. Rule catalogue: `GET /alerts/rules/catalog` — is the rule enabled in policy?
2. Suppressions: an active suppression for that fingerprint/asset explains silence.
3. Dedupe: the same fingerprint within `dedupe_window_minutes` (15) bumps an
   existing alert instead of creating a new one.
4. Indicators: threat-intel matches need the indicator to exist and be active.
5. Confirm with a known-bad test event (below).

```bash
# Controlled detection test — synthetic indicator only
curl -sX POST http://127.0.0.1:8000/api/v1/telemetry/events \
  -H "X-API-Key: $FIRESTORM_INGEST_API_KEY" -H 'Content-Type: application/json' \
  -d '{"source":"ops-selftest","event_type":"dns_query","severity":"high",
       "src_ip":"10.20.4.31","dns_query":"c2.synthetic-lab.example",
       "external_id":"selftest-'"$(date +%s)"'"}'
# Expect accepted:1 and alerts_created >= 1
```

### Everyone is locked out of sign-in ("too many requests")

Two independent limits can cause this:

| Limit | Scope | Default | Reset |
| --- | --- | --- | --- |
| Login rate limit | Per client IP, failures only | 10 / 15 min | Wait for the window, or restart the API process (in-memory) |
| Account lockout | Per account | 5 failures / 15 min | Wait, or an admin clears `failed_attempts`/`locked_until` |

Check which one applies: `429` = IP rate limit, `401 account temporarily locked`
= account lockout. If everyone behind one NAT is blocked, the limit is doing its
job against a brute-force attempt — find the source before raising it. Reading
`login_attempts` shows the emails, IPs and reasons.

### Email notifications not delivered

1. `POST /api/v1/notifications/dispatch` (or wait for the worker) and read the
   response.
2. Check `.env`: `FIRESTORM_SMTP_HOST`, port, TLS mode, user/password, from address.
3. `POST /api/v1/integrations/test` → the SMTP entry reports `ok`/`degraded` with
   the transport error.
4. Many providers reject unauthenticated senders or unverified domains; confirm
   SPF/DKIM alignment for the From domain.
5. `delivered` means the SMTP server accepted the message — not that it reached
   an inbox. Check the provider's logs for bounces.

### Enforcement action failed

| Symptom | Cause | Fix |
| --- | --- | --- |
| `mode: simulated` | Adapter not configured | Expected in lab; configure and test before claiming live containment |
| `409` business-critical | Target on the allowlist/protected services | Escalate; do not bypass. Change the policy only through an approved change |
| `403` on approve | Four-eyes rule (you requested it) | A second admin approves |
| `403` on execute | Missing `action:execute` | Assign the responder role |
| adapter error | Appliance unreachable/credential expired | Fix the integration, then re-execute the approved action |
| stuck `executing` | Process died mid-execution | Inspect `enforcement_records` for the actual appliance state before retrying; execution is not blindly idempotent |

### Emergency release

Admin-only, requires a note, reverts all active containments:

```bash
curl -sX POST http://127.0.0.1:8000/api/v1/actions/emergency-release \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"note":"Network-wide outage suspected caused by containment; IC approved release"}' | jq
```

Record the outcome in the incident. Verify on the appliance that state actually
changed; the API records intent and adapter responses, not physical truth.

---

## 5. Integration prerequisites

Enable in this order, verifying each with `POST /integrations/test`.

| Layer | Integration | Required configuration | What it unlocks |
| --- | --- | --- | --- |
| 1 | Zeek / sensor | `FIRESTORM_ZEEK_LOG_DIR`, sensor shipper, `X-API-Key` | Flow, DNS, TLS metadata |
| 1 | Syslog/webhook collector | Endpoint + token | Firewall, DNS, proxy logs |
| 2 | Inventory import | CSV/API import, agent enrolment secret | Device identity beyond IP/MAC |
| 3 | Posture agent | Agent package, enrolment, report endpoint | Admission decisions |
| 3 | Malware/EDR scanner | `FIRESTORM_EDR_*` | Scan results, isolation capability |
| 4 | Threat intel | Feed URL/key, refresh interval | Indicator matching (bundled data is synthetic) |
| 5 | Firewall | `FIRESTORM_FIREWALL_*` | `block_ip` |
| 5 | NAC | `FIRESTORM_NAC_*` | `quarantine_asset` |
| 5 | Identity provider | `FIRESTORM_IDP_*` | `disable_account` |
| 5 | DNS control | `FIRESTORM_DNS_*` | `sinkhole_domain` |
| 6 | East-west telemetry | Span/mirror port or host agent | Lateral-movement detection |
| 7 | Approvals | Staffing: ≥2 admins, ≥1 responder | Four-eyes containment |
| 8 | SMTP | `FIRESTORM_SMTP_*` | Escalation email |
| 8 | SIEM export | Syslog/webhook target | Off-host retention of audit and alerts |

An integration that is not configured reports `not_configured` and refuses to
act — it never reports success it cannot verify.

---

## 6. Notification operations

* In-app notifications are authoritative; email and WebSocket are delivery
  channels for the same record.
* `GET /integrations/notifications` shows per-channel status: `queued`,
  `retrying`, `delivered`, `failed`.
* `POST /notifications/dispatch` is safe to call repeatedly (idempotent per
  notification).
* Acknowledge from the UI or `POST /notifications/{id}/acknowledge`.
* Escalation mapping lives in the `alert.escalation` policy — high/critical email
  responders, critical sets `on_call`.

---

## 7. Maintenance windows

1. Announce the window and the expected impact (ingest gaps appear as staleness).
2. `POST /api/v1/actions` is not needed — instead pause automation by setting the
   `response.approval` policy to require approval for everything.
3. Apply the change, run migrations if required, restart API, then verify `/ready`,
   a login, one ingest, and a dashboard load.
4. Take a backup **before** schema changes:

   ```bash
   BACKUP_DIR=/var/backups/firestorm \
   BACKUP_PASSPHRASE_FILE=/etc/firestorm/backup.key \
   FIRESTORM_DATABASE_URL="$FIRESTORM_DATABASE_URL" \
   ./infra/deployment/scripts/backup.sh
   ```

5. Confirm sensors reconnected and staleness cleared before closing the window.

---

## 8. Capacity and retention

| Signal | Watch for | Response |
| --- | --- | --- |
| Database size | Growth beyond budget | Tighten `ingest.retention`, archive events to cold storage |
| Event rate | Sustained above the ingest limit | Scale API replicas, increase `FIRESTORM_RATE_LIMIT_PER_MINUTE`, sample noisy sources |
| Evidence volume | >80 % full | Expand, archive sealed evidence, alert because new blobs will fail |
| Alert volume | Backlog trend | Tune rules, add bounded suppressions, review detection quality |
| API latency | p95 > 1 s | Check DB indexes, slow queries, replica count |

Retention defaults (`ingest.retention` policy): events 90 d, alerts 365 d,
incidents 1095 d, audit 2555 d. Confirm these against legal requirements before
production use; the maintenance worker applies them.

---

## 9. Escalation

1. On-call operator (you) — triage, restore service, document.
2. Incident commander — declares incidents, owns stakeholder communication.
3. Security lead — approves containment of business-critical assets.
4. Data protection officer / legal — personal-data exposure, employee monitoring.
5. Platform owner — database, credentials, infrastructure.

Backup and restore: see `docs/disaster-recovery.md`. Detection and containment
playbooks: `docs/incident-response.md`. Security boundaries:
`docs/security-model.md`.
