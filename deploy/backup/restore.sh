#!/usr/bin/env bash
# Llavero restore into an ISOLATED environment (P2-T6, Annex H 7, 8, 9)
#
# This is the disaster-recovery / dry-run procedure. It decrypts an age-encrypted
# dump with the OFFLINE private key, loads it into a throwaway database, and runs
# the post-restore verification. It is intended for an isolated host — never the
# live production database.
#
# Steps:
#   1. age-decrypt the backup with the offline private key (from the safe).
#      The plaintext dump is written to a private tempdir and shredded on exit.
#   2. createdb an isolated target and load the dump (psql for plain .sql.gz).
#   3. Run manage.py restore_verify against the isolated DB: chain walk, off-box
#      checkpoint match under the offline public key, and (optionally) the
#      recovery-key decrypt drill.
#
# Security invariants:
#   - The offline PRIVATE key is supplied at restore time and never copied to the
#     server (Annex H 5). Point --private-key at removable media / the safe copy.
#   - The decrypted plaintext dump lives only in a 0700 tempdir and is shredded
#     on every exit path.
#   - Trust is anchored on the offline PUBLIC key passed to restore_verify, never
#     on a value read from the restored database.
#   - No real secrets until this gate (P2-T6) AND P4-T6 both pass.
#
# Usage:
#   ./restore.sh \
#       --backup     /path/to/llavero_YYYYMMDDTHHMMSSZ.sql.gz.age \
#       --private-key /media/safe/llavero-backup-private.key \
#       --pubkey     /media/safe/offline-ed25519.pub.hex \
#       --anchor-dir /srv/llavero-anchors \
#       --target-db  llavero_restore_test \
#       [--recovery-code-env LLAVERO_DRILL_RECOVERY_CODE --secret-id <uuid>]

set -euo pipefail

BACKUP=""
PRIVATE_KEY=""
PUBKEY=""
ANCHOR_DIR=""
TARGET_DB="llavero_restore_test"
DB_USER="${LLAVERO_DB_USER:-llavero}"
DB_HOST="${LLAVERO_DB_HOST:-127.0.0.1}"
DB_PORT="${LLAVERO_DB_PORT:-5432}"
DJANGO_DIR="${LLAVERO_DJANGO_DIR:-/opt/llavero}"
VENV="${LLAVERO_VENV:-/opt/llavero/.venv}"
RECOVERY_CODE_ENV=""
SECRET_ID=""

while [ $# -gt 0 ]; do
    case "$1" in
        --backup) BACKUP="$2"; shift 2 ;;
        --private-key) PRIVATE_KEY="$2"; shift 2 ;;
        --pubkey) PUBKEY="$2"; shift 2 ;;
        --anchor-dir) ANCHOR_DIR="$2"; shift 2 ;;
        --target-db) TARGET_DB="$2"; shift 2 ;;
        --recovery-code-env) RECOVERY_CODE_ENV="$2"; shift 2 ;;
        --secret-id) SECRET_ID="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

: "${BACKUP:?--backup is required}"
: "${PRIVATE_KEY:?--private-key is required (offline key from the safe)}"
: "${PUBKEY:?--pubkey is required (offline checkpoint public key, hex)}"

WORKDIR="$(mktemp -d)"
chmod 700 "${WORKDIR}"
PLAIN="${WORKDIR}/restore.sql.gz"

cleanup() {
    # Shred the decrypted plaintext dump on every exit path.
    if [ -f "${PLAIN}" ]; then
        shred -u "${PLAIN}" 2>/dev/null || rm -f "${PLAIN}"
    fi
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

# ── 1. Decrypt with the offline private key ───────────────────────────────
echo "Decrypting ${BACKUP} with the offline private key ..."
age --decrypt --identity "${PRIVATE_KEY}" --output "${PLAIN}" "${BACKUP}"

# ── 2. Load into an isolated target database ──────────────────────────────
echo "Creating isolated database ${TARGET_DB} ..."
createdb -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" \
    -T template0 -E UTF8 "${TARGET_DB}"

echo "Loading the dump into ${TARGET_DB} ..."
gunzip -c "${PLAIN}" | psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" \
    -d "${TARGET_DB}" -v ON_ERROR_STOP=1 --quiet

# ── 3. Verify the restore (Annex H 8) ─────────────────────────────────────
echo "Verifying the restored database ..."
DRILL_ARGS=()
if [ -n "${RECOVERY_CODE_ENV}" ] && [ -n "${SECRET_ID}" ]; then
    DRILL_ARGS=(--recovery-code-env "${RECOVERY_CODE_ENV}" --secret-id "${SECRET_ID}")
fi

ANCHOR_ARGS=()
if [ -n "${ANCHOR_DIR}" ]; then
    ANCHOR_ARGS=(--anchor-dir "${ANCHOR_DIR}")
fi

DB_NAME="${TARGET_DB}" "${VENV}/bin/python" "${DJANGO_DIR}/manage.py" restore_verify \
    --trusted-key-file "${PUBKEY}" \
    "${ANCHOR_ARGS[@]}" \
    "${DRILL_ARGS[@]}"

echo ""
echo "Restore verification complete. Review the report above and record the"
echo "sign-off in deploy/backup/RESTORE-DRILL.md."
