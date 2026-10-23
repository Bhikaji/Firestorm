#!/usr/bin/env bash
# Encrypted, verifiable database backup.
#
#   BACKUP_DIR=/var/backups/firestorm BACKUP_PASSPHRASE_FILE=/etc/firestorm/backup.key ./backup.sh
#
# The passphrase file must be readable only by root/service account (chmod 600).
# Restores are documented in docs/disaster-recovery.md and must be rehearsed.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/firestorm}"
PASSPHRASE_FILE="${BACKUP_PASSPHRASE_FILE:?set BACKUP_PASSPHRASE_FILE}"
DATABASE_URL="${FIRESTORM_DATABASE_URL:?set FIRESTORM_DATABASE_URL}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$BACKUP_DIR/firestorm-${stamp}.sql.gz.enc"
tmp="$(mktemp)"

cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

if [[ "$DATABASE_URL" == postgresql* ]]; then
  pg_dump --no-owner --no-privileges --format=plain "$DATABASE_URL" | gzip -9 > "$tmp"
else
  # SQLite: use the online backup API through the application's own settings.
  python3 - "$DATABASE_URL" "$tmp" <<'PY'
import sqlite3, sys, gzip, shutil, pathlib
url, out = sys.argv[1], sys.argv[2]
path = url.split("sqlite:///")[-1]
src = sqlite3.connect(path)
dest = sqlite3.connect(out + ".db")
src.backup(dest)
dest.close(); src.close()
with open(out + ".db", "rb") as f, gzip.open(out, "wb", compresslevel=9) as g:
    shutil.copyfileobj(f, g)
pathlib.Path(out + ".db").unlink()
PY
fi

openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
  -pass "file:${PASSPHRASE_FILE}" -in "$tmp" -out "$out"
sha256sum "$out" > "$out.sha256"
chmod 600 "$out" "$out.sha256"

# Verify: decrypt and confirm the archive is readable before declaring success.
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:${PASSPHRASE_FILE}" -in "$out" | gzip -t

find "$BACKUP_DIR" -name 'firestorm-*.sql.gz.enc' -mtime "+${RETENTION_DAYS}" -delete
find "$BACKUP_DIR" -name 'firestorm-*.sha256' -mtime "+${RETENTION_DAYS}" -delete

echo "backup written and verified: $out"
