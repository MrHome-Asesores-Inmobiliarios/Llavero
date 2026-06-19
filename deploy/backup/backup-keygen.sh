#!/usr/bin/env bash
# One-time backup key generation (P2-T1, P2-T3, Annex H 3, 5)
#
# Run this ONCE on a trusted offline machine (not the server).
# The private key stays offline in the safe.
# Copy only the public key to the server.
#
# Usage:
#   ./backup-keygen.sh [output-dir]
#   Default output-dir: current directory.
#
# Produces:
#   llavero-backup-private.key  — KEEP THIS IN THE SAFE, NEVER ON THE SERVER
#   llavero-backup.pub          — public key only; copy to /etc/llavero/ on the server
#
# Requirements: age-keygen (from the age package — https://age-encryption.org)

set -euo pipefail

OUTPUT_DIR="${1:-.}"
PRIVATE_KEY="${OUTPUT_DIR}/llavero-backup-private.key"
PUBLIC_KEY="${OUTPUT_DIR}/llavero-backup.pub"

if [ -e "${PRIVATE_KEY}" ] || [ -e "${PUBLIC_KEY}" ]; then
    echo "ERROR: key files already exist in ${OUTPUT_DIR}. Aborting to avoid overwrite." >&2
    exit 1
fi

# Generate the age keypair.
age-keygen -o "${PRIVATE_KEY}"

# Extract the public key into a separate recipients file.
grep -E '^# public key:' "${PRIVATE_KEY}" | awk '{print $NF}' > "${PUBLIC_KEY}"

chmod 600 "${PRIVATE_KEY}"
chmod 644 "${PUBLIC_KEY}"

echo "Private key: ${PRIVATE_KEY}"
echo "Public key:  ${PUBLIC_KEY}"
echo ""
echo "--------------------------------------------------------------------"
echo "NEXT STEPS:"
echo ""
echo "1. Store ${PRIVATE_KEY} in the physical safe."
echo "   It MUST NOT be copied to the server or stored alongside backups."
echo "   (Annex H 5)"
echo ""
echo "2. Copy ${PUBLIC_KEY} to the server:"
echo "   install -m 644 -o root -g llavero ${PUBLIC_KEY} /etc/llavero/backup.pub"
echo ""
echo "3. Set LLAVERO_BACKUP_PUBKEY=/etc/llavero/backup.pub in /etc/llavero/backup.env"
echo ""
echo "4. Verify encryption works:"
echo "   echo test | age -R /etc/llavero/backup.pub -o /tmp/test.age -"
echo "   age -d -i ${PRIVATE_KEY} /tmp/test.age"
echo "   (run the decrypt on the offline machine with the key)"
echo "--------------------------------------------------------------------"
