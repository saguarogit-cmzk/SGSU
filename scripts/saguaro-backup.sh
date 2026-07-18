#!/usr/bin/env bash
set -Eeuo pipefail
umask 0077

DEST=${SAGUARO_BACKUP_DIR:-/var/backups/saguaro}
RETENTION_DAYS=${SAGUARO_BACKUP_RETENTION_DAYS:-30}
RECIPIENT_FILE=${SAGUARO_BACKUP_RECIPIENT_FILE:-/etc/saguaro/backup-recipient.txt}
# CA private material is encrypted to a separate recipient when one is
# configured, so CA restore capability can be held by fewer people.
CA_RECIPIENT_FILE=${SAGUARO_CA_BACKUP_RECIPIENT_FILE:-$RECIPIENT_FILE}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

[[ -s $RECIPIENT_FILE ]] || { echo "ERROR: age recipient missing at $RECIPIENT_FILE; refusing to write a plaintext backup" >&2; exit 1; }
RECIPIENT=$(<"$RECIPIENT_FILE")
CA_RECIPIENT=$(<"$CA_RECIPIENT_FILE")
mkdir -p "$DEST"

# Configuration backup. /etc/step-ca is deliberately excluded and archived
# separately below under a stricter policy.
for path in /etc/saguaro /etc/kea /etc/unbound /etc/powerdns /etc/nginx /etc/nftables.conf /var/lib/saguaro; do
  [[ -e $path ]] && cp -a --parents "$path" "$WORK"
done
# The decryption key must never travel inside the backup it protects.
rm -f "$WORK/etc/saguaro/backup.agekey"

if command -v pg_dump >/dev/null 2>&1; then
  install -d "$WORK/pgsql"
  for db in saguaro kea pdns; do
    runuser -u postgres -- pg_dump --clean --if-exists "$db" >"$WORK/pgsql/$db.sql" 2>/dev/null || echo "WARN: pg_dump $db failed" >&2
  done
fi

tar -C "$WORK" -czf - . | age -r "$RECIPIENT" -o "$DEST/saguaro-$STAMP.tar.gz.age"

if [[ -d /etc/step-ca ]]; then
  tar -C / -czf - etc/step-ca | age -r "$CA_RECIPIENT" -o "$DEST/saguaro-ca-$STAMP.tar.gz.age"
fi

( cd "$DEST" && sha256sum saguaro-*"$STAMP"*.age >"saguaro-$STAMP.sha256" )
find "$DEST" -type f -name 'saguaro-*' -mtime "+$RETENTION_DAYS" -delete
