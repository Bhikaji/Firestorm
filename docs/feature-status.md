# Feature status

An honest inventory of what works, what is partially implemented, what is
simulated, and what is waiting on an external system. Read this before making
claims to a stakeholder.

**Legend**

| Status | Meaning |
| --- | --- |
| ✅ Implemented | Code exists and is covered by automated tests |
| 🟡 Verified against a mock only | Code exists and is tested, but the external counterpart was simulated/faked |
| 🟠 Partial | Core path works; a meaningful part of the capability is missing |
| 🔵 Simulated by design | Deliberately does not act on the real world; clearly labelled in the UI/API |
| ⛔ Awaiting integration | Requires an external system or credential we do not have |
| ❌ Not implemented | Planned or out of scope; no claim is made |

---

## 1. Defence layers

| # | Layer | Status | What is real | What is missing |
| --- | --- | --- | --- | --- |
| 1 | Network visibility | ✅ ingest, 🟠 collection | Authenticated single/batch ingestion (max 500/request), idempotency on `external_id`/fingerprint, source staleness, event search, live stream | Zeek/Suricata log shippers ship as adapters; the actual log files must be supplied by your sensors (⛔/🟡) |
| 2 | Device identity | 🟠 | Inventory with multi-signal identity (hostname, IP, MAC, serial, enrolment), trust states, manual trust changes with reasons, asset risk ranking | No 802.1X/RADIUS posture binding, no certificate identity, no automated MAC de-duplication across segments |
| 3 | Pre-access posture | ✅ engine, 🟡 agent | Deterministic posture score (0–100) from enrolled/EDR/patch/firewall/encryption/malware signals; admission rules with priority, thresholds and fail-closed default; explicit reasons and matched rule | Posture is only as good as the reporting agent; OSQuery/Wazuh integration is configured-tested, not deployed in this repo |
| 4 | Malware scanning | 🟠 | Detection rules consume malware signatures, hashes and file names; ClamAV health handshake and YARA rule-count checks; SHA-256 evidence for hashes | **No file-upload scanning endpoint** and no sandbox/detonation. Scanning files requires an external engine (⛔) |
| 5 | IDS/IPS | 🟠 detection only | 13 deterministic rules (port scan, brute force, beaconing, DNS tunnelling, exfiltration, lateral movement, intel match, IDS signature, phishing, unknown device, malware, protection disabled, suspicious protocol) with weighted signals and fingerprints; Suricata/Wazuh adapters | **No inline prevention** — FIRESTORM does not sit in the packet path and cannot drop traffic. Blocking is a response action through a firewall/NAC (⛔) |
| 6 | East-west / internal | 🟠 | Internal-to-internal telemetry is distinguished, lateral-movement and internal scan rules exist, topology view derives segment/asset relationships | No span/mirror-port orchestration, no per-segment sensor management, no micro-segmentation policy push |
| 7 | Automated containment | ✅ workflow, 🔵 enforcement | Request → approval (four-eyes) → execute → verify → revert; business-critical allowlist rejects automation; emergency release; enforcement records | Adapters for pfSense/UniFi/LDAP/Wazuh are written but unverified against real appliances (⛔); default mode is simulated |
| 8 | SOC and recovery | ✅ | Incident lifecycle + notes + correlations, evidence hashing and custody, audit hash chain with tamper detection, in-app/WebSocket/email notifications, daily/monthly/incident reports with CSV export, health/readiness/metrics, backup script and DR runbook | No built-in SOAR playbook editor, no native SIEM export connector, no automated restore (documented manual procedure) |

---

## 2. Cross-cutting capabilities

| Capability | Status | Notes |
| --- | --- | --- |
| Authentication | ✅ | JWT access (15 min) + rotating refresh (7 d), reuse detection revokes the family, lockout 5/15 min, identical error for unknown user and bad password |
| Password policy | ✅ | 12+ chars, mixed case, digit, symbol, common-password rejection, bcrypt cost 12 |
| MFA (TOTP) | ✅ | `pyotp`, setup/enable/disable, disable requires password. Optional per user; not enforced by policy |
| RBAC | ✅ | Four roles, per-route permission checks, matrix tested |
| Four-eyes approvals | ✅ | Server-side; requester cannot approve; waiver requests are ignored (regression-tested) |
| Audit log | ✅ | SHA-256 hash chain, `/audit/verify`, tamper test |
| Rate limiting | ✅ in-process | Sliding window per client IP; **not shared across replicas** — swap in Redis for horizontal scale |
| Request hardening | ✅ | Body-size cap (2 MB), batch cap, IP/port validation, control-character sanitisation, no secret echoing in errors |
| Risk engine | ✅ | 0–100 deterministic score, 5 bands, weighted signals, confidence adjustment, human-readable contributions |
| Alert lifecycle | ✅ | Dedupe window, occurrence counts, triage states, time-boxed suppressions (max 30 days) |
| Incident workflow | ✅ | State machine, notes, correlations, post-incident review field |
| Evidence | ✅ | Canonical JSON → SHA-256 → `data/evidence/<hash>.json`, custody entries, re-verification endpoint |
| Notifications | ✅ in-app/WS, 🟡 email | In-app is immediate; WebSocket pushes events + counters every 5 s; email stays `queued` until SMTP accepts and retries with backoff |
| Dashboard | ✅ | Real counters, freshness, 8-layer health, severity mix, trend, risky assets, trust distribution, topology |
| Reports | ✅ | Daily, monthly, incident metrics, CSV export (audited) |
| Policies | ✅ | Default risk/approval/retention/escalation/allowlist policies, validated updates, audited |
| User administration | ✅ | Create/update/reset, login-attempt history, role change invalidates sessions |
| Background jobs | ✅ inline, 🟡 Celery | Retention, notification dispatch, indicator expiry; runnable as a module, Celery app included, not exercised against a real broker here |
| Observability | ✅ | `/metrics` Prometheus text, Prometheus rules, Grafana provisioning, OTel collector config |
| Deployment | ✅ local/Compose, 🟡 k8s/systemd | Compose stack builds; systemd units and Kubernetes manifests provided and linted by inspection, not deployed in a cluster here |
| Backup | ✅ script, 🟡 rehearsal | Encrypted `pg_dump`/SQLite backup with verification and retention; restore procedure documented, rehearsal is an operator task |
| CI | ✅ configured | ruff, backend + repo tests, alembic up/down/up, frontend typecheck/build, container build + Trivy, dependency audit — on GitHub Actions |
| SSO (SAML/OIDC) | ❌ | Local accounts only. An identity-provider adapter exists solely for account suspension |
| Multi-tenancy | ❌ | Single organisation per deployment |

---

## 3. Simulated or demonstration data (must be labelled)

| Item | Behaviour | How it is labelled |
| --- | --- | --- |
| Enforcement adapters | When `FIRESTORM_ENFORCEMENT_MODE=simulated` (default), actions return `mode: simulated` and change nothing | Action `mode`/`result`, layer-7 `simulated` badge, `/integrations` detail |
| Demo incidents, alerts, events | Created by `scripts/bootstrap.py` (unless `--no-demo`) | `demo: true` in dashboard payloads; incident titles include "(demonstration)" |
| Threat indicators | Bundled C2/EICAR-style indicators are synthetic lab data | Indicator source `demo-seed`; layer-5 detail shows the active count |
| Synthetic lab traffic | Optional generator producing benign-looking internal flows for the topology view | Source name `synthetic-lab`; do not present as real monitoring coverage |
| DNS sinkhole adapter | Always a simulator (no live DNS control integration) | `simulated` status |

If a screen shows demo data, the UI must say so. Never screenshot the demo
dataset as evidence of production coverage.

---

## 4. Awaiting external integration

Each item needs a system you must supply; none is claimed to work until verified
against the real thing.

| Integration | Env vars | Verification |
| --- | --- | --- |
| Zeek | `FIRESTORM_ZEEK_LOG_DIR` | `POST /integrations/test` → component `healthy`, then events arrive with `source=zeek` |
| Suricata | `FIRESTORM_SURICATA_EVE_PATH` | Same; `eve.json` modified within 5 min |
| ClamAV | `FIRESTORM_CLAMAV_HOST`, `FIRESTORM_CLAMAV_PORT` | Health sends a real `zVERSION` handshake |
| YARA | `FIRESTORM_YARA_RULES_DIR` | Component reports the count of `.yar` files found |
| Wazuh | `FIRESTORM_WAZUH_ENDPOINT`, `FIRESTORM_WAZUH_TOKEN` | Health call + active-response isolation for `isolate_endpoint` |
| OSQuery | `FIRESTORM_OSQUERY_ENDPOINT` | Posture reports arriving over the TLS endpoint |
| pfSense firewall | `FIRESTORM_FIREWALL_ENDPOINT`, `FIRESTORM_FIREWALL_TOKEN` | `block_ip` in live mode, then confirm the alias on the appliance |
| UniFi NAC | `FIRESTORM_NAC_ENDPOINT`, `FIRESTORM_NAC_TOKEN` | `quarantine_asset`, then confirm the client's VLAN |
| LDAP / IdP | `FIRESTORM_IDP_ENDPOINT`, `FIRESTORM_IDP_TOKEN` | `disable_account`, then confirm the account is disabled |
| SMTP | `FIRESTORM_SMTP_HOST/PORT/USER/PASSWORD/FROM` | `POST /notifications/dispatch` → `delivered`; check the provider log for bounces |
| Redis | `FIRESTORM_REDIS_URL` | `/ready` → `redis: ok` |
| Celery broker | `FIRESTORM_CELERY_BROKER_URL`, `FIRESTORM_CELERY_RESULT_BACKEND` | Worker consumes a retention/dispatch task |

---

## 5. Known gaps and non-goals

* **Inline IPS / packet blocking.** Response is out-of-band via firewall/NAC/EDR.
* **File scanning and sandboxing.** Metadata, hashes and signatures only.
* **Offensive capability.** None. No scanning of external systems, no
  counter-attack, no exploit tooling.
* **Attribution.** IP/domain indicators are not identities; geolocation is
  approximate.
* **High availability.** Single-node by default; horizontal scaling needs a
  shared rate-limit store and a managed database.
* **Automatic restore.** Documented and scriptable, but deliberately manual.
* **Playbook automation.** The approval workflow is fixed; there is no visual
  SOAR editor.
* **Employee monitoring.** No screen capture, no content inspection, no
  mailbox-wide search.

---

## 6. Verifying the claims yourself

```bash
# Backend unit/API tests (auth, detection, ingest, triage, response, admission,
# notifications, audit, risk engine)
cd backend && ../.venv/bin/python -m pytest -q

# Repository-level integration, security and performance tests
cd .. && PYTHONPATH=backend .venv/bin/python -m pytest tests -q

# Lint
.venv/bin/ruff check backend tests

# Frontend typecheck and production build
cd frontend && npm run typecheck && npm run build

# Live checks
curl -s http://127.0.0.1:8000/api/v1/ready | jq
curl -s http://127.0.0.1:8000/api/v1/integrations -H "Authorization: Bearer $TOKEN" | jq '.[] | {name, status}'
curl -s http://127.0.0.1:8000/api/v1/audit/verify -H "Authorization: Bearer $TOKEN" | jq
```

A capability is only "working" when the corresponding command or test above
passes **and**, for external integrations, the real service has answered.
