# Incident response with FIRESTORM

This is the operational playbook an analyst follows inside the platform. It is
deliberately conservative: validate before you contain, and never let automation
touch a business-critical system without human approval.

> FIRESTORM supports a response process; it does not replace your organisation's
> incident-response plan, legal obligations, communications plan or management
> escalation.

---

## 1. Roles

| Role | Can do | Cannot do |
| --- | --- | --- |
| Viewer | Read dashboards, alerts, incidents, reports | Change anything |
| Analyst | Triage alerts, create incidents, collect evidence, request containment | Approve or execute |
| Responder | Execute and revert approved actions, read audit | Approve their own or anyone's request |
| Admin | Approve/reject, manage users, policies, integrations | Approve their own request (four-eyes) |

Recommended minimum staffing: two admins (approval separation), at least one
responder on call, and an analyst during business hours.

---

## 2. Triage (first 15 minutes)

1. Open **Alerts**, sort by risk score. Read the alert's **signal breakdown** —
   the score is arithmetic, not a black box.
2. Check **confidence** separately from severity. A critical-severity rule at 55 %
   confidence is a lead, not a conclusion.
3. Open the linked events. Confirm the source asset exists in inventory and note
   its criticality and trust state.
4. Ask: is this consistent with known business activity (patch window, backup,
   vulnerability scan)? If yes, record the reason, then close as a false positive
   or suppress for a bounded period.
5. If it is a real lead: **Investigate** then **Create incident** from the alert
   detail panel. Assign an owner.

Record observations as notes. Notes are timestamped, attributed and audited.

---

## 3. Containment decision

Ask in order:

1. Is the asset business-critical or on the allowlist? → **Do not automate.**
   Escalate to the incident commander and use a change window.
2. Is compromise confirmed by independent evidence (malware signature, verified
   C2, credential misuse, data egress)? → containment is justified.
3. Is there a lower-impact step (block one destination IP, sinkhole a domain,
   disable one account) that contains the activity without taking a host offline?
4. What is the blast radius of the action? VLAN isolation is usually preferable
   to full endpoint isolation because it leaves a remediation channel.

Then, in the incident workspace, **Request action**, choose the type and target,
and write a justification of at least 10 characters. The action enters
`pending_approval` unless policy permits automatic execution (default: it does
not).

### Approval

An administrator reviews the evidence, then **Approve** or **Reject**. The
requester cannot approve their own request. Approvals record the approver and
timestamp.

### Execution

A responder executes the approved action. Read the result carefully:

* `succeeded` with `mode: live` → the appliance confirmed the change.
* `succeeded` with `mode: simulated` → **no real change occurred**; it is a
  rehearsal. Do not report containment to stakeholders.
* `failed` → the adapter refused or errored; the reason is stored on the action.

---

## 4. Investigation

* **Timeline** — the incident timeline merges detections, notes, evidence,
  actions and status changes.
* **Correlation** — the incident panel suggests alerts that may belong to the
  incident (same asset, or within an hour). Attach only what you can justify.
* **Evidence** — collect event bundles, file hashes, email metadata or analyst
  notes. Each item is hashed and chain-of-custody is recorded. Use **Verify** to
  re-check the hash. Do not paste credentials or personal data into evidence.
* **Facts vs hypotheses** — observed facts are stored separately from
  hypotheses. Keep them that way: an unverified theory must never be presented as
  a finding.

### Phishing

Record sender, subject, message id, SPF/DKIM/DMARC results, URLs and attachment
hashes as metadata. Preserve the message through your mail platform's approved
process. Notify the affected user through an approved channel. Do not promise to
identify the sender's real-world identity; headers are trivially forged and
geolocation is approximate.

---

## 5. Eradication and recovery

1. Remove the cause (credentials reset, patch applied, malware removed by the
   endpoint tool).
2. Verify with independent signals: endpoint scans, new telemetry, log review.
3. Revert containment deliberately: `Revert` on the specific action, or a
   controlled **emergency release** if you need to undo everything.
4. Confirm the asset's posture report is current and admission now permits the
   intended access level.
5. Move the incident through `eradication → recovery → closed`.

Closing the incident closes its linked alerts. Post-incident review text is stored
on the incident. Any change to detection rules or policies discovered during
review is a policy change — versioned and audited.

---

## 6. Notification behaviour

| Severity | In-app | Email | Incident auto-opened |
| --- | --- | --- | --- |
| info / low | yes | no | no |
| medium | yes | no | no |
| high | yes | yes (responders/admins) | yes if risk ≥ 80 |
| critical | yes | yes | yes |

Delivery status is honest: `delivered` only after SMTP acceptance. `retrying` and
`failed` are visible on **Protection layers → Notification delivery** and in the
notification list. Notification bodies contain the alert title, score, endpoints
and a short explanation — no secrets, no unnecessary personal data.

---

## 7. Post-incident review

Capture in the incident record:

* timeline accuracy (were there detection gaps?);
* whether the detection could have fired earlier;
* false positives created and whether a suppression is appropriate (bounded);
* containment impact and whether approval latency was acceptable;
* control changes required, with owners and dates.

Publish an internal summary. Do not claim attribution or impact that the evidence
does not support.

---

## 8. Mistakes to avoid

* Containing a domain controller, hypervisor or the FIRESTORM host itself.
  Keep the allowlist current.
* Treating a simulated action as real containment.
* Closing an incident without validating that telemetry from the asset resumed.
* Permanently suppressing noisy rules instead of tuning thresholds with evidence.
* Executing automated containment while the approval policy is under review.
