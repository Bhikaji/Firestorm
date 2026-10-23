# FIRESTORM architecture

FIRESTORM is a defensive security operations platform for networks and devices an
operator is **explicitly authorised** to monitor and protect. It ingests
telemetry, evaluates deterministic detections, explains risk, and supports
policy-controlled containment with human approval and full auditability.

Nothing in this document claims comprehensive protection. Coverage is bounded by
the sensors that are actually deployed, the rules that are actually written, and
the integrations that are actually configured.

---

## 1. Design principles

| Principle | How it is implemented |
| --- | --- |
| Layered, independent controls | Five coordinated layers; each adapter reports its own health and can fail without disabling the others. |
| Explainable decisions | Every risk score ships with the contributing signals, weights and sources (`app/services/risk_engine.py`). |
| Evidence over assumption | Detections record rule id, version, confidence, severity and source. Facts and hypotheses are stored separately on incidents. |
| Fail closed | Unassessed devices are restricted, not trusted. Missing admission rules default to restricted access. Unconfigured enforcement adapters refuse to act. |
| Human authority | Approval gates, four-eyes checks, allowlists, emergency release, reversible actions. |
| Honest status | Simulated adapters are labelled `simulated`. Email is not "delivered" until the SMTP server accepts it. Stale telemetry is flagged in the UI. |
| Least privilege | Four roles, separate permissions for viewing, triaging, requesting, approving and executing. |

---

## 2. Component view

```mermaid
flowchart TB
    subgraph Sensors["Authorised sensors"]
        Z[Zeek<br/>flows/DNS]
        S[Suricata<br/>IDS/eve.json]
        W[Wazuh agents<br/>endpoint + auth]
        O[OSQuery<br/>inventory/posture]
        A[ClamAV / YARA<br/>file scanning]
        F[Firewall / switch logs]
    end

    subgraph API["FIRESTORM API (FastAPI)"]
        I[Ingestion API<br/>X-API-Key]
        D[Detection pipeline]
        R[Risk engine<br/>0-100 + signals]
        AL[Alert + incident service]
        N[Notification service]
        RE[Response engine]
        AD[Admission/posture service]
        AU[Audit service<br/>hash chain]
    end

    subgraph Data["State"]
        PG[(PostgreSQL / SQLite)]
        RD[(Redis - optional)]
        EV[(Evidence store<br/>hashed blobs)]
    end

    subgraph Enforce["Enforcement adapters"]
        FW[Firewall alias]
        NAC[NAC / VLAN]
        EDR[Endpoint isolation]
        IDP[Identity provider]
        DNS[DNS sinkhole]
    end

    UI[React dashboard<br/>WebSocket feed]

    Z --> I
    S --> I
    W --> I
    O --> I
    A --> I
    F --> I
    I --> D --> R --> AL
    AL --> N
    AL --> RE
    AD --> D
    AL --> AU
    RE --> AU
    AU --> PG
    D --> PG
    AL --> PG
    RE --> FW & NAC & EDR & IDP & DNS
    AL --> EV
    UI <-->|REST + WS| API
    API --- PG
    API -.optional.-> RD
```

---

## 3. Defense layers

| Layer | Purpose | Implementation | Failure mode |
| --- | --- | --- | --- |
| **1. Network visibility** | Flows, DNS, connection metadata, sensor logs | Zeek/Suricata ingestion, normalisation, dedupe by fingerprint | Detection blind spots; dashboard shows `not_configured` for the sensor |
| **2. Device discovery & identity** | Inventory, enrolment, multi-signal identity | Asset registry, segments, posture reports, IP/MAC drift tracking | Unassessed devices are restricted, never auto-trusted |
| **3. Pre-access assessment** | Admission decisions before resource access | Weighted posture score (0–100) + ordered admission rules | No matching rule → restricted access (fail closed) |
| **4. Malware & malicious code** | Signature/pattern detection on authorised files | ClamAV (clamd TCP), YARA rule inventory, threat-intel hash lookup | Unscanned artifacts stay unscored; never executed on the server |
| **5. Intrusion detection & response** | Detect and (where supported) block | Suricata signatures + behaviour rules; passive by default | Inline blocking requires explicit live mode configuration |

Cross-cutting: **correlation** (event windows per source), **risk scoring**,
**incident management**, **evidence**, **notification**, **containment**.

---

## 4. Data flow: one event end to end

```mermaid
sequenceDiagram
    participant S as Sensor
    participant API as Ingestion API
    participant DB as Database
    participant DET as Detection
    participant RISK as Risk engine
    participant NOTIF as Notifications
    participant UI as Dashboard

    S->>API: POST /telemetry/events (X-API-Key)
    API->>API: Validate + fingerprint
    API->>DB: INSERT event (unique fingerprint)
    alt duplicate fingerprint
        API-->>S: 202 duplicates=1
    else new event
        API->>DB: Resolve asset by hostname/IP
        API->>DB: Fetch correlated events (30 min window)
        API->>DET: Evaluate rules R-0001 .. R-0013
        DET-->>API: Detections (rule, severity, confidence, TTPs)
        API->>RISK: Score with signals + asset criticality + history
        RISK-->>API: 0-100 + explanation
        API->>DB: Upsert alert (dedupe 15 min window)
        opt risk >= 80
            API->>DB: Open incident + timeline entry
        end
        API->>NOTIF: Escalate per severity matrix
        NOTIF->>DB: Queue in-app / email notification
        UI->>API: WebSocket poll / REST refresh
    end
```

Timing budget per event on the reference deployment: single-digit milliseconds
for validation, ~1–5 ms for rule evaluation over a 30-minute window (bounded to
400 related events), and one write per new alert.

---

## 5. Trust boundaries

```mermaid
flowchart LR
    subgraph Internet["Untrusted"]
        EXT[External networks]
    end
    subgraph Edge["Edge boundary"]
        RP[Reverse proxy<br/>TLS + headers + rate limit]
        SENS[Sensor ingestion<br/>API key]
    end
    subgraph Mgmt["Management plane"]
        API[API]
        DB[(Database)]
        EV[Evidence store]
    end
    subgraph Ops["Operator boundary"]
        ANALYST[Analyst browser]
        APPROVER[Approver]
    end
    subgraph Targets["Protected estate"]
        FW[Firewall]
        NAC[NAC]
        EDR[EDR]
    end

    EXT -.blocked.-> RP
    ANALYST -->|TLS + JWT + MFA| RP --> API
    APPROVER -->|TLS + JWT + MFA| RP
    SENS -->|API key| API
    API --> DB
    API --> EV
    API -->|scoped credentials| FW & NAC & EDR
```

Assumptions and non-goals:

* The API, database and evidence store are inside a management VLAN reachable
  only from the operations subnet.
* The ingestion key is a shared secret per sensor group; it authorises event
  submission only, never read access.
* FIRESTORM does not scan third-party systems, does not counter-attack, and
  does not attempt to identify real-world attackers.

Full detail: [`security-model.md`](security-model.md).

---

## 6. Data model (summary)

| Table | Purpose | Key fields |
| --- | --- | --- |
| `users` | Operator accounts | role, mfa, lockout counters, password hash |
| `refresh_tokens` | Rotation + revocation | token hash, jti, revoked_at, replaced_by |
| `login_attempts` | Auth anomaly forensics | email, success, ip, user agent |
| `segments` / `assets` | Inventory | cidr, vlan, ip, mac, criticality, trust_state, posture |
| `events` | Normalised telemetry | ts, source, event_type, src/dst, risk_score, fingerprint (unique) |
| `alerts` | Deduplicated detections | rule_id, severity, confidence, risk_score, signals, occurrence_count |
| `suppressions` | Time-boxed suppression | fingerprint, rule_id, expires_at |
| `incidents` | Case management | reference, status machine, facts, hypotheses, affected assets |
| `incident_timeline` | Append-only narrative | kind, actor, message, payload |
| `evidence` | Custody | sha256, size, custody chain, sealed |
| `response_actions` | Containment lifecycle | action_type, status, approvals, mode, result |
| `enforcement_records` | Applied state | kind, target, integration, state, reverted_at |
| `policies` / `admission_rules` | Configuration as data | versioned JSON, priority-ordered rules |
| `audit_log` | Tamper-evident trail | action, actor, detail, previous_hash, entry_hash |
| `notifications` | Delivery status | channel, status, attempts, next_attempt_at |
| `threat_indicators` | Local TI cache | type, confidence, expiry |

Indexes cover time-range queries (`ts`), correlation lookups
(`src_ip`/`dst_ip` + `ts`), alert filtering (`status`, `severity`, `risk_score`)
and dedupe (`fingerprint`).

Migration: `backend/migrations/versions/*_initial_schema.py` (Alembic).

---

## 7. Detection and scoring

Rules are pure functions over an `EventContext` (event + correlated window +
asset facts + threat-intel match). They are testable without sensors.

| Rule | Code | Signal |
| --- | --- | --- |
| R-0001 | malware_detection | Endpoint signature hit |
| R-0002 | endpoint_protection_disabled | Security control tampering |
| R-0003 | port_scan | Port/host fan-out |
| R-0004 | authentication_bruteforce | Failure bursts and spray width |
| R-0005 | dns_tunneling | High-entropy label volume |
| R-0006 | data_exfiltration | Large egress volume |
| R-0007 | lateral_movement | Internal admin-protocol fan-out |
| R-0008 | c2_beaconing | Low-jitter periodic connections |
| R-0009 | cleartext_bulk_transfer | Policy violation |
| R-0010 | threat_intel_match | Feed indicator contact |
| R-0011 | ids_signature | Suricata signature |
| R-0012 | phishing_email | SPF/DKIM/DMARC + links |
| R-0013 | unknown_device_access | Unregistered device on admin port |

Score = severity×confidence base + weighted signals + criticality + repetition +
historical context, clamped to 0–100. Bands (0–19 informational … 80–100
critical) are **policy defaults** in `risk.thresholds`, tuneable and versioned.

Severity and confidence remain distinct fields; the UI shows both.

---

## 8. Response architecture

```mermaid
stateDiagram-v2
    [*] --> PendingApproval: request (policy requires approval)
    [*] --> Approved: request (policy permits auto)
    PendingApproval --> Approved: admin approves (not requester)
    PendingApproval --> Rejected: admin rejects
    Approved --> Executing: responder executes
    Executing --> Succeeded: adapter confirms
    Executing --> Failed: adapter refuses/errors
    Succeeded --> Reverted: responder reverts
```

Guarantees:

* every transition is written to `response_actions` and `audit_log`;
* applied state lands in `enforcement_records` so `emergency-release` can undo
  everything;
* a live adapter that is unconfigured returns `ok=False` and the action is
  marked `failed` — no simulated success is ever reported as real;
* allowlisted hosts/services are rejected before execution.

---

## 9. Frontend structure

```
frontend/src
├── components/     UI primitives, charts, topology
├── hooks/          data fetching, debounce, toasts
├── layouts/        AppShell (collapsible nav, status bar)
├── pages/          Overview, Topology, Events, Alerts, Incidents,
│                   IncidentDetail, Devices, Layers, Policies, Reports,
│                   Audit, Users, Account, Login
├── services/       API client (token rotation), auth context
├── topology/       Deterministic SVG segment/device map
└── types/          Typed API contracts
```

Accessibility and responsiveness: keyboard-focus rings, ARIA labelling on
interactive charts, `prefers-reduced-motion` support, collapsible navigation for
tablet widths, horizontally scrollable data tables, modals with Escape handling
and focus capture.

Design language: graphite/navy surfaces, cyan accents, amber warnings, red for
confirmed criticals, green for healthy, thin luminous borders, restrained
glassmorphism, no decorative fake telemetry.

---

## 10. Deployment topology

```mermaid
flowchart LR
    subgraph DMZ["Edge"]
        LB[Reverse proxy<br/>TLS, CSP, rate limit]
    end
    subgraph App["Application subnet"]
        API1[api replica 1]
        API2[api replica 2]
        WK[worker: retention, notifications]
    end
    subgraph DataTier["Data subnet"]
        PG[(PostgreSQL<br/>least-privilege role)]
        RD[(Redis)]
        EV[(Encrypted evidence volume)]
    end
    subgraph Mon["Monitoring subnet"]
        PR[Prometheus]
        GF[Grafana]
        OT[OTel collector]
    end
    OPS[Operators<br/>VPN / Zero Trust] --> LB --> API1 & API2
    API1 & API2 --> PG & RD & EV
    WK --> PG & RD
    PR -->|scrape /metrics| API1 & API2
    GF --> PR
    API1 & API2 -.traces.-> OT
```

Staged rollout (documented in `installation.md`): local dev → isolated lab with
synthetic traffic → passive monitoring of an authorised network → enforcement in
a pilot segment behind approval → gradual expansion.

---

## 11. Phased plan and current status

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Threat model, architecture, schema, UI prototype | Done |
| 2 | Auth, roles, audit, inventory, device registry | Done |
| 3 | Ingestion, detection, live dashboard | Done |
| 4 | Rules, risk scoring, correlation, notifications | Done |
| 5 | Posture integration, admission policy | Done (simulated enforcement; live adapters require credentials) |
| 6 | Incidents, containment, approvals, recovery | Done (simulated adapters) |
| 7 | Hardening, monitoring, load/restore tests, deployment | Done, with the gaps listed in `feature-status.md` |

See [`feature-status.md`](feature-status.md) for the authoritative
implemented / partial / simulated / pending-external matrix.
