#!/usr/bin/env bash
# Llavero daily database backup (P2-T1, P2-T2, Annex H 3, 4)
#
# Steps:
#   1. pg_dump | gzip  → staging file (compressed plaintext)
#   2. age encrypt     → encrypted file; staging plaintext is deleted immediately
#   3. Move encrypted  → local archive
#   4. rsync           → three destinations (separate host, NAS, offsite)
#   5. Prune archive   → GFS retention via manage.py backup_prune
#   6. Write JSON status and ship it to the monitoring host (P2-T5)
#
# Security invariants:
#   - The server holds only the backup PUBLIC KEY (/etc/llavero/backup.pub).
#     The private key lives OFFLINE in the safe and is never present here.
#   - A fully compromised server can create new backups but cannot decrypt them.
#   - The plaintext dump is held only in the staging tempfile; it is deleted
#     immediately after age encrypts it.
#   - The status file contains only metadata (filename, timestamp, ok/failed).
#     It never contains key material or secret data.
#
# Required environment variables (set in the systemd unit's EnvironmentFile):
#   LLAVERO_DB_NAME          PostgreSQL database name
#   LLAVERO_DB_USER          PostgreSQL role for pg_dump
#   LLAVERO_BACKUP_PUBKEY    Path to the age recipients file (public key, /etc/llavero/backup.pub)
#   LLAVERO_BACKUP_DIR       Base directory (staging + archive sub-dirs will be created)
#   LLAVERO_BACKUP_HOST1     user@host:path  — separate internal host (copy 1)
#   LLAVERO_BACKUP_HOST2     user@host:path  — NAS or second host (copy 2)
#   LLAVERO_BACKUP_HOST3     user@host:path  — offsite office over MikroTik tunnel (copy 3)
#   LLAVERO_STATUS_PATH      Path for the JSON status file (/var/log/llavero/backup-status.json)
#   LLAVERO_DJANGO_DIR       Root of the Django project (for manage.py backup_prune)
#   LLAVERO_VENV             Path to the Python virtualenv (e.g., /opt/llavero/.venv)

set -euo pipefail

# ── Validate required variables ───────────────────────────────────────────
: "${LLAVERO_DB_NAME:?LLAVERO_DB_NAME must be set}"
: "${LLAVERO_DB_USER:?LLAVERO_DB_USER must be set}"
: "${LLAVERO_BACKUP_PUBKEY:?LLAVERO_BACKUP_PUBKEY must be set}"
: "${LLAVERO_BACKUP_DIR:=/var/backups/llavero}"
: "${LLAVERO_BACKUP_HOST1:?LLAVERO_BACKUP_HOST1 must be set}"
: "${LLAVERO_BACKUP_HOST2:?LLAVERO_BACKUP_HOST2 must be set}"
: "${LLAVERO_BACKUP_HOST3:?LLAVERO_BACKUP_HOST3 must be set}"
: "${LLAVERO_STATUS_PATH:=/var/log/llavero/backup-status.json}"
: "${LLAVERO_DJANGO_DIR:=/opt/llavero}"
: "${LLAVERO_VENV:=/opt/llavero/.venv}"

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
DUMP_NAME="llavero_${TIMESTAMP}.sql.gz"
ENC_NAME="${DUMP_NAME}.age"
STAGING="${LLAVERO_BACKUP_DIR}/staging"
ARCHIVE="${LLAVERO_BACKUP_DIR}/archive"

mkdir -p "${STAGING}" "${ARCHIVE}"

STATUS="failed"
ERROR_MSG="null"

_write_status() {
    printf '{"timestamp":"%s","status":"%s","backup":"%s","error":%s}\n' \
        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        "${STATUS}" \
        "${ENC_NAME}" \
        "${ERROR_MSG}" \
    > "${LLAVERO_STATUS_PATH}"
}

_ship_status() {
    # Ship the status JSON to the separate host (copy 1) so monitoring can read it
    # even if the main server is unavailable. Failure is non-fatal.
    rsync -az -e ssh \
        "${LLAVERO_STATUS_PATH}" \
        "${LLAVERO_BACKUP_HOST1%:*}:/srv/llavero-backup-status.json" \
        2>/dev/null || true
}

cleanup() {
    # Remove the plaintext staging file on any exit path.
    rm -f "${STAGING}/${DUMP_NAME}"
    _write_status
    _ship_status
}
trap cleanup EXIT

# ── 1. Dump ───────────────────────────────────────────────────────────────
pg_dump \
    --username="${LLAVERO_DB_USER}" \
    --dbname="${LLAVERO_DB_NAME}" \
    --format=plain \
    --no-password \
    | gzip > "${STAGING}/${DUMP_NAME}"

# ── 2. Encrypt (public key only — Annex H 3, 5) ───────────────────────────
#
# age -R reads one "age1..." public key per line from the recipients file.
# The private key must NEVER be present on this machine.
age \
    --recipients-file "${LLAVERO_BACKUP_PUBKEY}" \
    --output "${STAGING}/${ENC_NAME}" \
    "${STAGING}/${DUMP_NAME}"

# Plaintext is no longer needed.
rm -f "${STAGING}/${DUMP_NAME}"

# ── 3. Move to local archive ──────────────────────────────────────────────
mv "${STAGING}/${ENC_NAME}" "${ARCHIVE}/${ENC_NAME}"

# ── 4. Ship to three destinations (Annex H 4) ─────────────────────────────
#
# Copy 1: separate internal host (also holds audit anchors and shipped logs)
rsync -az -e ssh "${ARCHIVE}/${ENC_NAME}" "${LLAVERO_BACKUP_HOST1}/"

# Copy 2: second host or NAS
rsync -az -e ssh "${ARCHIVE}/${ENC_NAME}" "${LLAVERO_BACKUP_HOST2}/"

# Copy 3: offsite office over MikroTik site-to-site tunnel
rsync -az -e ssh "${ARCHIVE}/${ENC_NAME}" "${LLAVERO_BACKUP_HOST3}/"

# ── 5. GFS pruning of the local archive (Annex H 6) ──────────────────────
#
# The manage.py command applies daily-14d / weekly-8w / monthly-12m rules.
# Remote destinations manage their own retention (identical rules recommended).
"${LLAVERO_VENV}/bin/python" \
    "${LLAVERO_DJANGO_DIR}/manage.py" \
    backup_prune \
    --archive-dir "${ARCHIVE}"

# ── Mark success ──────────────────────────────────────────────────────────
STATUS="ok"
# (cleanup trap writes the status file and ships it)
