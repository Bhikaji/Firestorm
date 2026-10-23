# API reference

Base path: `/api/v1`. Interactive OpenAPI at `/api/docs`, spec at
`/api/openapi.json`. All responses are JSON unless noted; all timestamps are
UTC ISO-8601.

---

## Conventions

### Authentication

| Caller | Mechanism |
| --- | --- |
| Operator UI / API clients | `Authorization: Bearer <access_token>` |
| Sensors / collectors | `X-API-Key: <FIRESTORM_INGEST_API_KEY>` (ingestion endpoints only) |
| Live dashboard stream | `GET /ws/live?token=<access_token>` |

Access tokens expire in 15 minutes. Refresh with `POST /api/v1/auth/refresh`
(rotating; the previous refresh token is invalidated). Send
`Idempotency-Key` on action requests if you retry them.

### Errors

```json
{
  "error": {
    "code": "rate_limited",
    "message": "too many requests; slow down",
    "details": {"retry_after_seconds": 12}
  }
}
```

`message` is safe to show to operators (no raw input is echoed back, so a
payload cannot smuggle secrets or log-injection content into an error).

| Status | Meaning |
| --- | --- |
| 400 | Malformed request |
| 401 | Missing/expired/invalid credentials |
| 403 | Authenticated but not permitted (role, four-eyes, approval missing) |
| 404 | Not found (also used when the object is not visible to the caller) |
| 409 | State conflict (duplicate, already approved, wrong lifecycle stage) |
| 422 | Schema validation failure |
| 429 | Rate limited — honour `Retry-After` |
| 503 | Dependency not ready (see `/ready`) |

Every response carries `X-Request-ID` and `X-Response-Time-ms`. Reuse the request
id when reporting an issue; it is also written to the structured logs.

### Pagination

List endpoints accept `page` (1-based) and `page_size` (max 200, default 25) and
return:

```json
{ "items": [], "total": 0, "page": 1, "page_size": 25, "pages": 0 }
```

### Rate limits

| Bucket | Default |
| --- | --- |
| Login | `FIRESTORM_LOGIN_ATTEMPTS_PER_15MIN` (default 10) per 15 min per IP |

Successful sign-ins are **refunded** from the login budget: only failed attempts
count, so a shared NAT address cannot lock out a team during a normal shift while
repeated wrong passwords are still throttled after ten tries. Account lockout
(5 failures on one account for 15 minutes) is separate and always applies.
| Ingestion | 6000 / minute per client IP |
| All API routes | `FIRESTORM_RATE_LIMIT_PER_MINUTE` (default 240) per minute per client IP |

The limiter is in-process (a sliding window). Behind the proxy it keys on
`X-Forwarded-For`, so the proxy must overwrite that header. `429` responses
include `Retry-After`. For multi-replica deployments, replace the store with a
shared Redis implementation (see `app/core/ratelimit.py`).

---

## Session

### `POST /auth/login`

```bash
curl -sX POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@firestorm.example.com","password":"Firestorm-Admin!2026"}'
```

```json
{
  "access_token": "eyJ…",
  "refresh_token": "r3f…",
  "token_type": "bearer",
  "expires_in": 900,
  "role": "admin",
  "must_change_password": false
}
```

The refresh token is also set as an `HttpOnly`, `SameSite=Strict` cookie scoped
to `/api/v1/auth`. Call `GET /auth/me` for the user profile, permissions and MFA
state.

Failure modes — all `401` with a deliberately uninformative message:

| Situation | `error.message` |
| --- | --- |
| Unknown account | `invalid credentials` |
| Wrong password | `invalid credentials` |
| Locked out (5 failures / 15 min) | `account temporarily locked after repeated failures` |
| Disabled account | `account disabled` |
| MFA enabled, no code supplied | `multi-factor code required` |
| Wrong MFA code | `invalid multi-factor code` |

Call `GET /auth/me` after login when you need the profile; it is not embedded in
the token pair.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth/refresh` | Rotate refresh token, issue new access token |
| POST | `/auth/logout` | Revoke all refresh tokens for the caller |
| GET | `/auth/me` | Current user, role, permissions, MFA state |
| POST | `/auth/password` | Change password (revokes other sessions) |
| POST | `/auth/mfa/setup` | Generate TOTP secret + `otpauth://` URI |
| POST | `/auth/mfa/enable` | Confirm code, activate MFA |
| POST | `/auth/mfa/disable` | Requires current password |

---

## Telemetry (layer 1 — visibility)

### `POST /telemetry/events` — ingest one event

Header: `X-API-Key`.

```bash
curl -sX POST http://localhost:8000/api/v1/telemetry/events \
  -H "X-API-Key: $FIRESTORM_INGEST_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "network-ids",
    "event_type": "dns_query",
    "severity": "medium",
    "src_ip": "10.20.4.31",
    "dns_query": "update-check.example-cdn.net",
    "external_id": "sensor-a-0001"
  }'
```

Responds `202 Accepted`:

```json
{"accepted": 1, "duplicates": 0, "rejected": 0, "alerts_created": 1, "errors": []}
```

A duplicate (same `external_id`, or the same fingerprint as a recent event)
returns `accepted: 0, duplicates: 1` and creates no alert; repeated alerts on the
same fingerprint bump the existing alert's occurrence count instead of opening a
new one. Detections run synchronously, so `alerts_created` is authoritative for
that request.

Required: `source`, `event_type`. Optional: `sensor`, `severity`
(`info|low|medium|high|critical`, default `info`), `ts` (defaults to now),
`src_ip`, `dst_ip`, ports, `protocol`, `bytes_in`, `bytes_out`, `packets`,
`duration_ms`, `dns_query`, `http_host`, `url`, `username`, `hostname`,
`file_hash`, `file_name`, `signature`, `action`, `raw`, `external_id`.

### `POST /telemetry/events/batch`

`{"events": [ ... ]}` — max **500** per request. Body limit 2 MB. Response:

```json
{ "accepted": 497, "duplicates": 3, "rejected": 0, "alerts_created": 12, "errors": [] }
```

Duplicate detection applies both within the batch and against stored events.
A partial batch is still accepted: `rejected` counts events that raised, and
`errors` (first 10) summarises them as `"<event_type>: <ExceptionType>"`.
Senders should retry only on `5xx` or network failure — ingest is idempotent on
`external_id`.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/telemetry/events` | Filters: `source`, `event_type`, `severity`, `src_ip`, `asset_id`, `q`, `start`, `end` |
| GET | `/telemetry/events/{id}` | Single event with detection context |
| GET | `/telemetry/sources` | Per-source counts and last-seen (staleness) |

---

## Detection (layers 5–6)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/alerts` | Filters: `status`, `severity`, `rule_id`, `asset_id`, `q`, `min_risk`, `sort` (`risk|recent`) |
| GET | `/alerts/{id}` | Alert with signal breakdown, linked events, asset context |
| PATCH | `/alerts/{id}` | Triage: `status`, `assignee_id`, `note`, `false_positive`, `suppress_minutes`, `create_incident` |
| GET | `/alerts/rules/catalog` | Rule catalogue R-0001…R-0013 with severity and description |
| POST | `/alerts/suppressions` | `{rule_id|fingerprint, asset_id?, reason, duration_minutes}` |
| GET | `/alerts/suppressions/list` | `?active_only=true` |
| DELETE | `/alerts/suppressions/{id}` | Remove suppression |

Triage transitions: `open → acknowledged → investigating → resolved|false_positive`.
Suppressions are time-boxed (max 30 days) and audited.

---

## Assets and admission (layers 2–3)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/assets` | Filters: `q`, `trust_state`, `segment_id`, `min_criticality` |
| POST | `/assets` | `{hostname, ip_address, mac_address?, device_type, os_*, owner?, department?, segment_id?, criticality}` |
| GET | `/assets/{id}` | Asset with posture, admission decision, recent alerts |
| PATCH | `/assets/{id}` | Update inventory fields |
| GET | `/assets/{id}/context` | Segment, criticality, allowlist membership, history |
| POST | `/assets/{id}/posture` | Submit agent posture report |
| POST | `/assets/{id}/admission` | Evaluate admission (no body) → decision + reasons |
| POST | `/assets/{id}/trust` | `{trust_state, reason}` — audited manual override |
| POST | `/assets/{id}/quarantine` | `{reason, duration_minutes?}` — creates an approval-gated action |

### Posture report

```json
{
  "agent_version": "3.1.2",
  "edr_status": "healthy",
  "patch_level": "current",
  "firewall_enabled": true,
  "disk_encrypted": true,
  "os_name": "Windows",
  "os_version": "11 23H2",
  "malware_detections_24h": 0,
  "certificate_valid": true,
  "extra": {}
}
```

`edr_status`: `healthy|stale|missing|disabled`. `patch_level`:
`current|due|overdue|unknown`.

### Admission outcome

```json
{
  "asset_id": "3f9c…",
  "outcome": "restricted",
  "reason": "posture score 45 below threshold 70 for segment 'Finance'",
  "matched_rule": "posture-baseline",
  "posture_score": 45.0,
  "trust_state": "noncompliant",
  "risk_score": 62,
  "evaluated_at": "2026-10-23T09:12:44Z"
}
```

`outcome`: `allow|restricted|deny`. `matched_rule` is the admission rule that
decided (or `null` when the default policy applied), so the decision is
explainable. Unmatched devices fail closed (deny) with an explicit reason. A
network scan is never treated as proof of cleanliness, and IP/MAC alone is never
identity.

### Admission rules (admin)

| Method | Path |
| --- | --- |
| GET/POST | `/admission-rules` |
| PATCH/DELETE | `/admission-rules/{id}` |
| GET | `/admission/rules` (read-only effective rules) |

---

## Incidents, evidence and custody

### `POST /incidents`

```json
{
  "title": "Beaconing to known C2 from FIN-LT-041",
  "summary": "Periodic 60s TLS beacons to 203.0.113.66 observed for 42 minutes.",
  "severity": "high",
  "alert_ids": [412],
  "affected_asset_ids": [18],
  "observed_facts": ["42 connections with 60s ±2s jitter", "Destination matches synthetic lab indicator"]
}
```

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/incidents` | Filters: `status`, `severity`, `q` |
| GET | `/incidents/{id}` | Timeline, evidence, actions, notes, correlations |
| PATCH | `/incidents/{id}` | `status`, `owner_id`, `severity`, `summary`, `post_incident_review`, `hypothesis` |
| POST | `/incidents/{id}/notes` | `{"note": "…"}` |
| GET | `/incidents/{id}/correlations` | Candidate related alerts with reasons |
| POST | `/incidents/{id}/evidence` | Collect evidence |

Lifecycle: `new → triage → containment → contained → eradication → recovery →
closed`. Invalid transitions return `409` with the current and attempted state.

### `POST /incidents/{id}/evidence`

```json
{
  "kind": "event_bundle",
  "label": "DNS + TLS timeline 14:00-15:00Z",
  "event_ids": ["evt_9f2…", "evt_9f3…"],
  "alert_id": "alt_71…",
  "metadata": {"collected_by_tool": "firestorm-ui"}
}
```

`kind`: `event_bundle|file_hash|email_header|pcap_ref|screenshot|analyst_note`.
Supply `content` (≤1 MB) for notes/screenshots, `file_hash` for hash-only
evidence, or `event_ids` to bundle stored events. The response is the evidence
record: `id`, `sha256`, `size_bytes`, `collected_by`, `collected_at`, `source`,
`sealed`, and a `custody` list of timestamped entries. The canonical JSON is
written to `data/evidence/<sha256>.json`.

```bash
curl -s http://localhost:8000/api/v1/evidence/31/verify -H "Authorization: Bearer $TOKEN"
```

```json
{"id": "31", "verified": true, "detail": "content matches recorded hash", "sha256": "9d2f…", "actual_sha256": "9d2f…"}
```

`verified: null` means the blob is not stored locally (metadata-only record) —
compare the recorded hash with the archived copy instead of assuming success.
A mismatch returns `verified: false` with "treat evidence as tampered".

---

## Response actions (layer 7)

### `POST /actions`

```json
{
  "action_type": "block_ip",
  "target": "203.0.113.66",
  "reason": "Confirmed C2 destination from three independent alerts",
  "incident_id": "inc_44…",
  "require_approval": true
}
```

`action_type`: `block_ip | quarantine_asset | isolate_endpoint |
disable_account | sinkhole_domain | notify_team`. `target` is a hostname, IP,
MAC, domain or account id depending on the type. `reason` must be at least 10
characters and is stored verbatim.

States: `pending_approval → approved → executing → succeeded | failed`;
`succeeded` may become `reverted`. `rejected` is terminal. Every transition is
audited.

| Method | Path | Permission | Notes |
| --- | --- | --- | --- |
| GET | `/actions` | `action:request` | Filters: `status`, `incident_id` |
| POST | `/actions/{id}/approve` | `action:approve` | Body `{note}`; 403 if you requested it |
| POST | `/actions/{id}/reject` | `action:approve` | Body `{note}` |
| POST | `/actions/{id}/execute` | `action:execute` | Runs against the adapter; returns `mode: live\|simulated` |
| POST | `/actions/{id}/revert` | `action:execute` | Reverts a succeeded action |
| POST | `/actions/emergency-release` | `user:admin` | `{"note": "…"}` — revert all active containments |

Execution returns the action record:

```json
{
  "id": "act_91…",
  "action_type": "block_ip",
  "target": "203.0.113.66",
  "status": "succeeded",
  "mode": "simulated",
  "integration": "firewall",
  "result": "simulated block of 203.0.113.66 recorded; no device was changed",
  "requested_by": "usr_2…",
  "approved_by": "usr_7…",
  "approved_at": "2026-10-23T09:38:02Z",
  "executed_at": "2026-10-23T09:41:07Z",
  "confidence": 0.86,
  "reversible": true
}
```

`mode: simulated` means **no production change occurred** — the record is intent
only. `mode: live` means the adapter returned success. A failed adapter returns
`status: failed` with the reason in `result`. Business-critical assets on the
allowlist are rejected with `409` and an explicit reason; approvals missing or
self-approved are `403`.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/enforcement` | Every applied change with adapter, target, timestamp, revert state |

---

## Dashboard and reports

| Method | Path | Query | Returns |
| --- | --- | --- | --- |
| GET | `/dashboard/overview` | — | Counters, risk posture, click-through targets, `generated_at` |
| GET | `/dashboard/layers` | — | Eight layers with state (`healthy|degraded|partial|simulated|not_configured`), components and last signal |
| GET | `/dashboard/attention` | — | Prioritised items with reason and link |
| GET | `/dashboard/feed` | `limit` | Live activity (events, alerts, incidents, actions) |
| GET | `/dashboard/trend` | `days` (≤90) | Daily event/alert/incident series |
| GET | `/dashboard/severity` | `hours` (≤168) | Severity distribution |
| GET | `/dashboard/risky-assets` | `limit` | Ranked with contributing signals |
| GET | `/dashboard/trust` | — | Trust-state distribution |
| GET | `/dashboard/topology` | — | Segments, assets, edges (rendered in the topology view) |
| GET | `/reports/daily` | `day=YYYY-MM-DD` | Daily report object |
| GET | `/reports/daily/export` | `day` | `text/csv` attachment (audited) |
| GET | `/reports/incidents` | `days` | Incident metrics |
| GET | `/reports/monthly` | `year`, `month` | Monthly rollup |

Counters are computed from the database at request time. A zero is a real zero,
not a placeholder; each response includes `generated_at` so the UI can show
staleness.

---

## Protection layers, notifications, integrations

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/integrations` | Layer-by-layer integration status with prerequisites |
| GET | `/integrations/records` | Persisted integration configuration (secrets redacted) |
| PATCH | `/integrations/records/{id}` | Admin: `enabled`, `endpoint`, `settings` |
| POST | `/integrations/test` | Active connectivity test; honest `ok:false` when unconfigured |
| GET | `/integrations/notifications` | Delivery log (in-app, email, WebSocket) |
| GET | `/notifications` | Filters: `channel`, `status` |
| POST | `/notifications/dispatch` | Worker-safe email dispatch (idempotent) |
| POST | `/notifications/{id}/acknowledge` | Mark read/acknowledged |

`POST /integrations/test` performs active probes and returns the same health
array exposed by `/integrations`, persisting the result:

```json
[
  {
    "name": "firewall",
    "kind": "firewall",
    "layer": "automated_containment",
    "mode": "simulated",
    "enabled": true,
    "status": "simulated",
    "detail": "Simulation adapter: actions are recorded as intent only and change nothing on the network.",
    "latency_ms": null,
    "checked_at": "2026-10-23T09:44:10Z"
  }
]
```

`status`: `healthy|degraded|unavailable|simulated|not_configured`. An
unconfigured adapter never reports healthy, and never fabricates a successful
apply.

---

## Policies, users, audit, operations

| Method | Path | Permission | Notes |
| --- | --- | --- | --- |
| GET | `/policies` | `policy:read` | All policies with current config and defaults |
| PATCH | `/policies/{key}` | `policy:write` | `{name?, description?, enabled?, config?}`; validated against the policy schema |
| GET | `/users` | `user:admin` | Includes lockout/MFA state |
| POST | `/users` | `user:admin` | `{email, full_name, role, password}` |
| PATCH | `/users/{id}` | `user:admin` | Role, active flag; role change revokes sessions |
| POST | `/users/{id}/reset-password` | `user:admin` | Forces `must_change_password` |
| GET | `/users/{id}/login-attempts` | `user:admin` | `limit` ≤ 200 |
| GET | `/audit` | `audit:read` | Filters: `action`, `actor`; paginated |
| GET | `/audit/verify` | `audit:read` | Recomputes the hash chain |
| GET | `/health` | public | Liveness: process is up |
| GET | `/ready` | public | Readiness: database, migrations, storage |
| GET | `/metrics` | public | Prometheus text format — restrict at the network/reverse-proxy layer |
| GET | `/system/info` | authenticated | Version, build, configured features, degraded modes |

### `GET /health` and `GET /ready`

```json
{"status": "ok", "service": "firestorm", "environment": "development", "time": "2026-10-23T09:00:00Z", "uptime_seconds": 812.4}
```

```json
{
  "status": "ok",
  "checks": {
    "database": {"status": "ok"},
    "redis": {"status": "not_configured", "detail": "single-process mode"},
    "enforcement": {"status": "ok", "mode": "simulated"}
  }
}
```

`/health` is liveness only (no dependency checks). `/ready` checks the database,
Redis when configured, and reports the enforcement mode (`simulated` is healthy;
`live` is flagged `warning` so the mode is never accidental). It returns HTTP 200
with `status: "degraded"` if a check fails — use the body for gating, not the
status code alone. Optional services do not fail readiness.

### `GET /audit/verify`

```json
{"valid": true, "checked": 1843, "broken_at": null, "message": "audit chain intact"}
```

Verification recomputes the SHA-256 chain over up to 10,000 entries in order. A
non-null `broken_at` (audit row id) means the chain diverged at that entry —
treat it as an integrity incident and preserve the database and backups before
anything else.

---

## WebSocket

```
ws(s)://<host>/ws/live?token=<access_token>
```

The server authenticates the query token before accepting, then polls (every 5 s)
and pushes two message types:

```json
{"type": "event", "payload": {"id": "…", "ts": "…", "source": "network-ids", "event_type": "dns_query", "severity": "medium", "src_ip": "10.20.4.31", "dst_ip": null, "risk_score": 0, "alert_id": null}}
{"type": "overview", "payload": {"open_alerts": 4, "open_incidents": 1, "pending_approvals": 0, "…": "…"}}
```

An invalid or expired token closes the socket. The stream is a convenience layer,
not a source of truth: reconnect with backoff and re-fetch the REST snapshot.
Note that only fresh events and the overview counters are pushed — alert and
incident changes appear on the next REST poll.

---

## cURL cookbook

```bash
BASE=http://localhost:8000/api/v1
TOKEN=$(curl -s $BASE/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@firestorm.example.com","password":"Firestorm-Admin!2026"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# Dashboard summary
curl -s $BASE/dashboard/overview -H "Authorization: Bearer $TOKEN" | jq

# High-risk alerts
curl -s "$BASE/alerts?min_risk=60&sort=risk" -H "Authorization: Bearer $TOKEN" | jq '.items[:5]'

# Request containment
curl -sX POST $BASE/actions -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"quarantine_asset","target":"10.20.4.31","reason":"Confirmed beaconing; approved by IC on bridge 2"}' | jq

# Verify audit integrity
curl -s $BASE/audit/verify -H "Authorization: Bearer $TOKEN"
```
