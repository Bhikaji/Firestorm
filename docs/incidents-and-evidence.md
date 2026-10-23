# Incidents, evidence and response

Incidents are the unit of accountability. Every detection that is worth acting on
becomes an incident, and every incident carries its own evidence, timeline,
actions and closure criteria.

---

## Lifecycle

```
new → triage → containment → contained → eradication → recovery → closed
```

| Status | Meaning | Exit criteria |
| --- | --- | --- |
| `new` | Auto-created or manually opened, unassigned | Owner assigned, severity confirmed |
| `triage` | Being scoped | Affected assets and facts recorded |
| `containment` | Active response in progress | Containment action executed or deemed unnecessary |
| `contained` | Spread stopped | Eradication plan agreed |
| `eradication` | Removing the cause | Independent verification that the threat is gone |
| `recovery` | Restoring normal operation | Monitoring stable for an agreed period |
| `closed` | Finished | Post-incident review captured |

Invalid transitions are rejected with `409` (tested in
`test_incident_state_machine_rejects_invalid_transitions`). Any authenticated
analyst or above can advance state; transitions and notes are audited.

---

## Creating an incident

```http
POST /api/v1/incidents
{
  "title": "Beaconing to known C2 from FIN-LT-041",
  "summary": "Periodic TLS beacons to 203.0.113.66 for 42 minutes.",
  "severity": "high",
  "alert_ids": ["<alert-id>"],
  "affected_asset_ids": ["<asset-id>"],
  "observed_facts": [{"fact": "Beacon interval 60s +/- 2s"}, {"fact": "Destination matches lab indicator"}]
}
```

Rules:

* `title` 5–220 characters, `summary` 10–8000 characters (required) — an incident with no explanation
  is not actionable.
* `severity` ∈ `info|low|medium|high|critical`.
* `observed_facts` is a list of objects describing what you verified. Interpretation goes in the incident
  notes or `hypothesis`, clearly labelled as such.
* Linking alerts attaches their events and moves them to `investigating`.

High-severity alerts above the critical score auto-open an incident only when the
`alert.escalation` policy enables it (`high`/`critical`) — the UI shows which
policy produced the decision.

---

## Evidence and chain of custody

Evidence kinds: `event_bundle`, `file_hash`, `email_header`, `pcap_ref`,
`screenshot`, `analyst_note`.

```http
POST /api/v1/incidents/{id}/evidence
{
  "kind": "event_bundle",
  "label": "DNS + TLS timeline 14:00–15:00Z",
  "event_ids": ["<event-id>", "..."],
  "alert_id": "<alert-id>"
}
```

What the platform does:

1. Serialises the payload deterministically (canonical JSON, sorted keys).
2. Computes SHA-256 and writes the blob to `data/evidence/<sha256>.json`.
3. Stores the hash, size, collector, timestamp and source in the database.
4. Appends a custody entry (`collected` by `<user>`).

What it never does: modify or re-hash an existing record. Re-verification is
read-only:

```http
GET /api/v1/evidence/{evidence_id}/verify
→ {"id": "…", "verified": true, "detail": "content matches recorded hash",
   "sha256": "…", "actual_sha256": "…"}
```

`verified: null` means the blob is metadata-only (not stored locally) — compare
the recorded hash against the archived copy. A mismatch is tampering until
proven otherwise; escalate rather than re-collect over the top of it.

Evidence limits: 1 MB per item, no secrets, no credentials, no unnecessary
personal data. Large artefacts belong in your forensic platform with a
`pcap_ref`/pointer recorded here.

---

## Response actions

```
requested → pending_approval → approved → executing → succeeded | failed
                                                        └────────→ reverted
                        └─→ rejected
```

| Action | Target | Effect |
| --- | --- | --- |
| `block_ip` | IP address | Firewall block |
| `quarantine_asset` | asset id / MAC | VLAN move / NAC quarantine |
| `isolate_endpoint` | asset id | EDR network isolation |
| `disable_account` | account identifier | Identity provider suspension |
| `sinkhole_domain` | domain | DNS sinkhole |
| `notify_team` | team name | Notification only |

### Approval policy

An action requires approval when **any** of these is true:

* the action type is always gated (`disable_account`);
* the target is on the business-critical allowlist or in protected services;
* the `response.approval` policy requires approval (`require_approval_for_containment`, default true);
* the requesting user asked for approval;
* the risk score is below the auto-execute threshold.

Auto-execution (when enabled) is limited to low-impact actions on non-critical
assets with a score at or above `auto_execute_threshold`. Everything else waits
for a human.

**Four-eyes:** the approver must not be the requester. Enforced server-side
(`403 four-eyes violation`), not by hiding a button.

### Execution

```http
POST /api/v1/actions/{id}/execute
→ {"status": "succeeded", "mode": "simulated", "result": "…"}
```

* `mode: simulated` → nothing was changed on the network. This is the default in
  development and must be labelled as such in any report.
* `mode: live` → the adapter returned success. Verify on the appliance when the
  action is significant; the API records adapter responses, not physical truth.
* Failures are recorded with the adapter's error; there is no silent fallback and
  no retry storm.

### Reverting

`POST /api/v1/actions/{id}/revert` reverses one action. `POST
/api/v1/actions/emergency-release` (admin, requires a note) reverts every active
containment and is audited as a single privileged event. Use it when containment
itself is causing an outage — not to tidy up.

---

## Timeline and correlations

`GET /api/v1/incidents/{id}` returns a merged timeline: alerts, notes, evidence,
actions and status changes in chronological order.

`GET /api/v1/incidents/{id}/correlations` returns candidate related alerts with
the reason they matched (shared asset, shared indicator, time proximity). Nothing
is auto-attached: correlation proposes, the analyst decides.

---

## Reports

| Endpoint | Content |
| --- | --- |
| `GET /reports/daily?day=YYYY-MM-DD` | Volume, severity mix, top rules, containment activity, open items |
| `GET /reports/daily/export?day=…` | Same as CSV for stakeholders (audited download) |
| `GET /reports/incidents?days=30` | Incident metrics: MTTD/MTTR, reopen rate, severity mix |
| `GET /reports/monthly?year=…&month=…` | Monthly rollup and trend |

Reports are computed from the database at request time and include
`generated_at`. Empty periods return zeros rather than sample data — if the demo
dataset is loaded, responses carry `demo: true` and the UI labels them.
