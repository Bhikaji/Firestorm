# Backup and disaster recovery

Recovery objectives are operational decisions; the numbers below are defaults
that must be agreed with the business.

| Objective | Default target | Notes |
| --- | --- | --- |
| RPO (database) | 15 minutes | Depends on `pg_dump`/WAL schedule you operate |
| RTO (API + dashboard) | 1 hour | Restore database, start API, verify readiness |
| RTO (telemetry continuity) | 2 hours | Sensors buffer locally; re-ship after recovery |
| Evidence retention | Per policy | Encrypted volume snapshots, verified quarterly |

---

## 1. What must be backed up

1. **Database** — users, inventory, policies, alerts, incidents, evidence metadata,
   audit log.
2. **Evidence volume** — hashed blobs referenced by `evidence.storage_path`.
3. **Configuration** — `.env` (in a secret manager, **not** in Git), reverse-proxy
   config, Grafana dashboards, Prometheus rules.
4. **Encryption keys** — wherever your platform stores them (KMS, vault).

---

## 2. Backup procedure

The provided script produces an encrypted, verified archive:

```bash
sudo install -m 600 /dev/null /etc/firestorm/backup.key
sudo openssl rand -base64 48 > /etc/firestorm/backup.key
sudo BACKUP_DIR=/var/backups/firestorm \
     BACKUP_PASSPHRASE_FILE=/etc/firestorm/backup.key \
     FIRESTORM_DATABASE_URL='postgresql+psycopg://firestorm:...@db:5432/firestorm' \
     ./infra/deployment/scripts/backup.sh
```

Properties:

* `pg_dump` (or SQLite online backup) → gzip → AES-256-CBC with PBKDF2;
* SHA-256 sidecar written next to the archive;
* the script decrypts and tests the gzip stream before reporting success;
* archives older than `RETENTION_DAYS` (default 30) are deleted.

Schedule it with cron/systemd, ship archives off-host (object storage with
versioning and object lock), and restrict access to the passphrase file.

Evidence volume: snapshot the encrypted volume at least daily, and keep snapshots
for the evidence retention period. Record snapshot ids in your operations log.

---

## 3. Restore procedure (rehearsed quarterly)

```bash
# 1. Stop write traffic
sudo systemctl stop firestorm-api firestorm-worker.timer

# 2. Restore the database
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -pass file:/etc/firestorm/backup.key \
  -in /var/backups/firestorm/firestorm-<stamp>.sql.gz.enc \
  | gunzip \
  | psql 'postgresql://firestorm:...@db:5432/firestorm_restore'

# 3. Verify counts and audit integrity
psql 'postgresql://...' -c "select count(*) from incidents;"
psql 'postgresql://...' -c "select count(*) from audit_log;"

# 4. Point the application at the restored database, start it, then verify:
curl -fsS http://127.0.0.1:8000/api/v1/ready
# In the UI: Audit trail -> chain verification must report "chain intact".

# 5. Restore evidence volume mount, then verify one evidence hash
#    (Incidents -> evidence -> Verify).

# 6. Re-enable sensors. Confirm events arrive and staleness clears.
```

Post-restore checks:

- [ ] `GET /api/v1/ready` reports `ok`
- [ ] audit chain verification passes
- [ ] at least one evidence hash verifies
- [ ] logins work for admin and one responder
- [ ] telemetry timestamp freshness is under 15 minutes
- [ ] notification queue is empty or clearly explained
- [ ] enforcement records reflect reality (re-apply containment if the appliance
      state was lost — recorded actions are the source of truth for intent)

---

## 4. Partial failures

| Failure | Impact | Action |
| --- | --- | --- |
| API process crash | Dashboard unavailable, ingestion stops | systemd/container restart; sensors buffer and retry (idempotent) |
| Database unavailable | Everything stops | Restore service; API `/ready` reports degraded |
| Redis unavailable | Optional features only (queue), API continues | Restart Redis; Celery falls back to inline tasks if not used |
| Sensor offline | Blind spot, stale badge appears | Repair sensor; check `telemetry stalled` alert |
| Enforcement appliance offline | Containment fails visibly | Actions show `failed`; use an alternative control |
| Evidence volume full | New evidence stores metadata only (no blob) | Expand volume; record the gap in the incident |
| SMTP outage | Notifications queue and retry | Alerts still visible in-app; escalate by phone per plan |

---

## 5. Disaster declaration

Declare a disaster when: the database is unrecoverable from the last archive,
encryption keys are lost, or the management plane has been compromised.

* **Lost encryption keys** → backups are unreadable; rebuild and re-ingest.
* **Compromised management plane** → rebuild from known-good images, rotate every
  credential (JWT secret, ingestion key, integration tokens, DB passwords), and
  treat prior audit entries as untrusted until validated against off-host logs.
* **Ransomware on the FIRESTORM host** → isolate the host, restore from immutable
  backups, and review `audit_log` shipped off-host for the intrusion window.

Record every disaster exercise: date, participants, timings achieved, gaps, and
follow-up actions with owners.
