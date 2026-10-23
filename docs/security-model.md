# Security model and threat model

This document describes what FIRESTORM protects, what protects FIRESTORM, and
what it explicitly does not do. It is written to be reviewed by a security lead
before deployment.

---

## 1. Scope and authorisation

FIRESTORM is intended for:

* networks, segments and devices the operator owns or is contracted to protect;
* defensive monitoring, investigation and containment;
* organisations with a documented incident-response process.

It is **not** for: monitoring other people's networks, counter-attack, offensive
testing, malware analysis on production infrastructure, or employee surveillance
beyond what the organisation has lawfully authorised. Telemetry design
deliberately avoids payload capture and employee communications.

Legal review is required for jurisdiction-specific obligations (works councils,
employee monitoring law, data protection, retention limits).

---

## 2. Assets in scope for protection

| Asset | Sensitivity | Protection |
| --- | --- | --- |
| Operator credentials / sessions | High | bcrypt hashes, short-lived JWTs, rotating refresh tokens, optional TOTP, lockout |
| Audit trail | High | Hash-chained, append-only by convention, restricted permission |
| Evidence blobs | High | SHA-256 recorded; stored on a restricted volume; access audited |
| Asset inventory | Medium | RBAC read; write requires `asset:write` |
| Threat indicators | Medium | Read via detection engine only |
| Integration credentials | Critical | Environment/secret manager only; never stored in the database |
| Detection rules and policies | Medium | Versioned, audited changes |

---

## 3. Trust boundaries

1. **Internet / protected estate → edge proxy.** Untrusted. TLS terminates at
   the proxy; strict CSP, HSTS, frame denial, request-size limit and edge rate
   limiting apply.
2. **Sensors → ingestion API.** Semi-trusted. Authenticated with a shared
   `X-API-Key`; authorises submission only. A compromised sensor can inject
   false events but cannot read data or execute actions.
3. **Operator browsers → API.** Trusted after authentication, constrained by
   RBAC. MFA is optional but strongly recommended for admin/responder roles.
4. **API → database / evidence store.** Trusted within the management plane;
   database role has only DML rights on its own schema (no superuser).
5. **API → enforcement appliances.** The most sensitive boundary. Credentials
   are scoped to a single function (firewall alias write, VLAN move, agent
   isolation) and never reused. Actions are gated, logged and reversible.

---

## 4. STRIDE analysis

| Threat | Vector | Mitigation | Residual risk |
| --- | --- | --- | --- |
| **Spoofing** | Stolen credentials; forged sensor key | bcrypt + lockout + optional MFA; token fingerprinting; role claim checked against DB; API key never grants read | Credential theft by endpoint malware remains possible — enforce MFA and device trust |
| **Tampering** | Editing audit rows; modifying evidence | Hash chain (`audit_log.entry_hash` + `previous_hash`), evidence SHA-256, `verify_chain` endpoint | An attacker with DB write access can truncate history; ship logs off-host and use WORM storage |
| **Repudiation** | Denying an action | Every request, approval and execution stored with actor, IP, request id, timestamp | Clock skew if NTP is not enforced |
| **Information disclosure** | Over-broad API responses; logs | No secrets in responses (tested), redaction filter in logging, control-character sanitisation, restricted CORS, `Cache-Control: no-store` | Misconfigured integration dumps could leak; keep payload capture off |
| **Denial of service** | Flooding ingestion or login | Rate limiting (edge + app), body-size cap, batch cap (500), bounded correlation window, bounded WebSocket broadcast | A determined volumetric attack requires upstream protection |
| **Elevation of privilege** | Role escalation via API; JWT forgery | Server-side permission checks on every route; role change invalidates tokens; short expiry; four-eyes on approvals | Compromised admin account is game over by definition — monitor admin logins |
| **Supply chain** | Malicious dependency/container | Pinned versions, CI audit (pip-audit, npm audit, Trivy), minimal base images, non-root container | Zero-days require ongoing patching discipline |
| **Insider misuse** | Analyst suppressing alerts, responder containing core services | Allowlist of business-critical hosts, separate approve/execute permissions, expiring suppressions, full audit | Insider with admin rights can still cause damage; require two admins in production |
| **Prompt/AI misuse** | N/A | No opaque ML model can auto-contain. Risk scoring is deterministic and explained | If an ML layer is added later, it must not bypass the deterministic gate |

---

## 5. Authentication and session handling

* Passwords: bcrypt, cost 12, maximum 72 bytes (explicitly rejected above that).
* Policy: ≥12 chars, mixed case, digit, symbol, not a common dictionary word.
* Lockout: 5 failed attempts → 15-minute lock.
* Access token: 15 minutes, HS256, `iss=firestorm`, `jti`, `type=access`.
* Refresh token: 7 days, stored as SHA-256 fingerprint, **rotated on every use**.
  Reuse of a rotated token revokes the entire token family (theft signal).
* Logout revokes all refresh tokens for the account.
* Password change revokes all sessions.
* Role change invalidates existing tokens (role claim compared with DB).
* MFA: TOTP (RFC 6238 via `pyotp`), 30-second step, ±1 step drift.
* Tokens live in `sessionStorage`, not `localStorage`, to limit XSS persistence.
  Refresh tokens are also set as `HttpOnly`, `SameSite=Strict` cookies scoped to
  `/api/v1/auth`.

Failed logins are recorded in `login_attempts` and the audit log, and the error
message is identical for unknown accounts and wrong passwords (no enumeration).

---

## 6. Authorisation

| Permission | viewer | analyst | responder | admin |
| --- | --- | --- | --- | --- |
| dashboard:view | ✔ | ✔ | ✔ | ✔ |
| asset:read | ✔ | ✔ | ✔ | ✔ |
| asset:write | | | ✔ | ✔ |
| event:read | ✔ | ✔ | ✔ | ✔ |
| event:ingest | | | ✔ | ✔ |
| alert:read | ✔ | ✔ | ✔ | ✔ |
| alert:triage | | ✔ | ✔ | ✔ |
| incident:read | ✔ | ✔ | ✔ | ✔ |
| incident:write | | ✔ | ✔ | ✔ |
| evidence:collect | | ✔ | ✔ | ✔ |
| action:request | | ✔ | ✔ | ✔ |
| action:approve | | | | ✔ |
| action:execute | | | ✔ | ✔ |
| policy:read | ✔ | ✔ | ✔ | ✔ |
| policy:write | | | | ✔ |
| report:read | ✔ | ✔ | ✔ | ✔ |
| audit:read | | | ✔ | ✔ |
| user:admin | | | | ✔ |
| integration:read | ✔ | ✔ | ✔ | ✔ |
| integration:test | | | ✔ | ✔ |

Four-eyes rule: the user who requested an action cannot approve it. Enforced in
`ResponseEngine.approve`.

---

## 7. Data protection

* **In transit:** TLS at the proxy for all management traffic. Sensors should use
  TLS to the ingestion endpoint (terminated at the same proxy).
* **At rest:** database encryption is delegated to the platform (PostgreSQL TDE /
  encrypted volumes, SQLCipher for SQLite if required). Evidence volumes must be
  encrypted; only hashes and metadata are stored in the database by default.
* **Minimisation:** telemetry stores connection metadata, DNS names, signatures
  and hashes — not payload bodies. Email evidence defaults to headers and
  hashes; raw content requires an explicit analyst action.
* **Retention:** `ingest.retention` policy (events 90d, alerts 365d, incidents
  1095d, audit 2555d by default) applied by the maintenance worker. Retention
  must be reconciled with legal requirements.
* **Deletion:** incidents closed and past retention can be purged; evidence blobs
  must be purged with the database record and the purge recorded in the audit log
  (implemented as an operator procedure, see runbook).

---

## 8. Enforcement safety

1. Default mode is `simulated`: no device state changes. The UI labels simulated
   actions in the incident workspace and the enforcement list.
2. Live mode requires, per adapter, an endpoint and token. Missing configuration
   produces `ok=False` and a failed action — never a false success.
3. Approval is required unless policy explicitly opts out **and** the risk score
   exceeds the configured threshold **and** the asset is not business-critical.
4. Business-critical allowlist rejects automated action before it reaches an
   adapter.
5. Every applied change is recorded in `enforcement_records`, enumerable via
   `GET /api/v1/enforcement`, and reversible individually or all at once via
   `POST /api/v1/actions/emergency-release` (admin only, note required).
6. Account suspension always requires approval, regardless of policy.

**Lockout protection:** before enabling live enforcement, populate the allowlist
with firewalls, core switches, hypervisors, domain controllers and the FIRESTORM
management host itself. Test emergency release in the lab.

---

## 9. Logging and monitoring

* Structured JSON logs; control characters stripped; secret-bearing fields
  redacted (`password`, `token`, `secret`, `api_key`, `authorization`, `cookie`,
  `mfa_secret`).
* Request logging includes request id, status, duration and client IP. No bodies.
* Audit log is the authoritative record for administrative and response actions;
  application logs are operational.
* Prometheus metrics expose counters only (no tenant or personal data).
* Recommended alerts: API down, telemetry stalled, alert backlog, critical alerts
  unresolved (`infra/monitoring/alerts.yml`).

---

## 10. Known limitations

* **No detection of what you cannot see.** Uninstrumented segments and
  uninstalled agents are blind spots; the UI shows coverage rather than implying
  completeness.
* **A network scan cannot prove a device is malware-free.** Posture scoring
  reflects reported compliance from agents.
* **Signature and rule coverage is finite.** Novel attacks may pass undetected.
* **Suppression is a human decision.** Time-boxed, audited, but still a risk.
* **Single-node mode is not highly available.** Use replicated API replicas and a
  managed database for availability; the in-process rate limiter is per process.
* **Email delivery depends on your SMTP provider.** Status reflects acceptance,
  not inbox placement.
* **Threat-intel freshness depends on the feed you configure.** The bundled
  indicators are synthetic lab data.
* **Attribution is out of scope.** IPs, domains and geolocation are indicators,
  not identities.
