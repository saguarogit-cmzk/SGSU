#!/usr/bin/env bash
set -Eeuo pipefail
umask 0077

# Optional off-site target configuration written by the GUI (W11).
BACKUP_ENV=${SAGUARO_BACKUP_ENV:-/etc/saguaro/backup.env}
[[ -r $BACKUP_ENV ]] && source "$BACKUP_ENV"

DEST=${SAGUARO_BACKUP_DIR:-/var/backups/saguaro}
RETENTION_DAYS=${SAGUARO_BACKUP_RETENTION_DAYS:-30}
BACKUP_TARGET=${SAGUARO_BACKUP_TARGET:-local}
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
for path in /etc/saguaro /etc/kea /etc/unbound /etc/powerdns /etc/nginx /etc/nftables.conf /etc/netplan /etc/systemd/network /etc/sysctl.d/99-saguaro-forward.conf /var/lib/saguaro; do
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

# Off-site copy of this run's artifacts. The archives are already
# age-encrypted, so the transport only needs to be authenticated.
upload_files=("$DEST/saguaro-$STAMP.sha256" "$DEST"/saguaro-*"$STAMP"*.age)
case "$BACKUP_TARGET" in
  sftp)
    : "${SAGUARO_SFTP_HOST:?}" "${SAGUARO_SFTP_USER:?}" "${SAGUARO_SFTP_PATH:?}"
    key_opt=()
    [[ -n ${SAGUARO_SFTP_KEY:-} ]] && key_opt=(-i "$SAGUARO_SFTP_KEY")
    port=${SAGUARO_SFTP_PORT:-22}
    for f in "${upload_files[@]}"; do
      [[ -e $f ]] || continue
      scp -q -P "$port" "${key_opt[@]}" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "$f" "${SAGUARO_SFTP_USER}@${SAGUARO_SFTP_HOST}:${SAGUARO_SFTP_PATH}/" \
        || { echo "ERROR: SFTP upload failed for $f" >&2; exit 1; }
    done
    ;;
  s3)
    : "${SAGUARO_S3_BUCKET:?}"
    command -v aws >/dev/null || { echo "ERROR: aws CLI not installed for S3 target" >&2; exit 1; }
    endpoint_opt=()
    [[ -n ${SAGUARO_S3_ENDPOINT:-} ]] && endpoint_opt=(--endpoint-url "$SAGUARO_S3_ENDPOINT")
    for f in "${upload_files[@]}"; do
      [[ -e $f ]] || continue
      AWS_ACCESS_KEY_ID=${SAGUARO_S3_ACCESS_KEY:-} AWS_SECRET_ACCESS_KEY=${SAGUARO_S3_SECRET_KEY:-} \
        AWS_DEFAULT_REGION=${SAGUARO_S3_REGION:-us-east-1} \
        aws s3 cp "${endpoint_opt[@]}" --only-show-errors "$f" "s3://${SAGUARO_S3_BUCKET}/$(basename "$f")" \
        || { echo "ERROR: S3 upload failed for $f" >&2; exit 1; }
    done
    ;;
  local) ;;
  *) echo "WARN: unknown backup target '$BACKUP_TARGET'; kept local only" >&2 ;;
esac
