# Llavero — Deployment notes

## PostgreSQL setup (scram-sha-256)

Run once on the database host as the `postgres` superuser:

```sql
-- Ensure scram-sha-256 is the default (Ubuntu 24.04 default is md5).
-- In postgresql.conf:
--   password_encryption = scram-sha-256
-- In pg_hba.conf replace md5 with scram-sha-256 for all local connections.

CREATE USER llavero WITH PASSWORD 'change-me' CONNECTION LIMIT 5;
CREATE DATABASE llavero OWNER llavero ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8' TEMPLATE template0;

-- App role (P1-T11 will add the restricted audit role separately)
GRANT CONNECT ON DATABASE llavero TO llavero;
```

## Internal CA TLS certificate

```bash
# Generate a key and CSR for llavero.internal
openssl genrsa -out llavero.internal.key 4096
openssl req -new -key llavero.internal.key -out llavero.internal.csr \
    -subj "/CN=llavero.internal/O=MrHome IT"

# Sign with your internal CA (adjust path to your CA key/cert)
openssl x509 -req -days 365 -in llavero.internal.csr \
    -CA /etc/ssl/internal-ca/ca.crt \
    -CAkey /etc/ssl/internal-ca/ca.key \
    -CAcreateserial \
    -out llavero.internal.crt

# Deploy
install -m 640 -o root -g llavero llavero.internal.key /etc/ssl/llavero/
install -m 644 llavero.internal.crt /etc/ssl/llavero/
```

## Systemd deployment

```bash
# Install service files
cp deploy/systemd/llavero.socket /etc/systemd/system/
cp deploy/systemd/llavero.service /etc/systemd/system/

# Create runtime dirs
install -d -m 750 -o llavero -g www-data /run/llavero /var/log/llavero

systemctl daemon-reload
systemctl enable --now llavero.socket
systemctl start llavero
```

## nginx

```bash
cp deploy/nginx/llavero.conf /etc/nginx/sites-available/llavero
ln -s /etc/nginx/sites-available/llavero /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

## Off-box checkpoint anchor (P1-T14 — Annex G 7, B 2)

Each signed checkpoint is copied to a **separate internal host** (P0-T9) in an
append-only store the app can write to but cannot modify or delete. With the
printed copy in the safe, that gives two independent references the database
process cannot rewrite — the defence against an attacker who rewrites both the
DB chain and the DB checkpoint row.

The app writes through the `AnchorStore` interface (`apps/audit/anchor.py`).
The dev stand-in is `AppendOnlyFileAnchorStore` (one read-only file per
checkpoint). On the server, point it at an OS-enforced append-only target, e.g.:

- **Append-only syslog** to the separate host (the app has send-only access), or
- a **WORM / `chattr +a`** directory on the separate host that the app role can
  create files in but not modify or unlink:

```bash
# On the separate host, app role can append but not delete/modify:
install -d -m 730 -o llavero_app -g llavero /srv/llavero-anchors   # write+execute, no read/delete for others
chattr +a /srv/llavero-anchors        # append-only directory (root sets this)
```

Verify periodically with `anchor.verify_offbox_anchor(store, trusted_public_key=...)`
where the trusted key is the enrolled admin credential / configured offline key.

### Printed checkpoint copy (kept in the safe)

At least daily (and at each session end), print the latest checkpoint —
`seq`, `head_hash` (hex), `signature` (hex), `signer`, `created_at` — and store
the printout in the safe alongside the recovery key. A printed copy cannot be
altered by any online attacker and is the ultimate anchor for a dispute.

## Append-only audit roles (P1-T11 — Annex B 5, G 5)

The audit log is append-only, enforced two ways:

1. A `BEFORE UPDATE OR DELETE` trigger on `audit_entry` / `audit_checkpoint`
   (migration `audit/0002`) that raises — defence in depth, fires for all roles.
2. Database role separation: a migration role owns the schema and runs DDL,
   while the runtime app role has **INSERT/SELECT only** on the audit tables.

Apply the role split once on the production DB:

```bash
psql -U postgres -f deploy/audit-roles.sql   # creates llavero_owner + llavero_app
```

Then set `DB_USER=llavero_owner` for `manage.py migrate` and
`DB_USER=llavero_app` for the running app server. The `audit/0002` migration
re-applies the audit-table grants to `llavero_app` whenever it runs, so they
stay correct. A superuser can still bypass both layers — that residual risk is
covered by the signed external checkpoints (P1-T13/T14).

## Vault second factor (P1-T7, finalised on the server — Annex A 5.2, G 4)

The second factor is a 256-bit secret combined with each admin's Argon2id
output to form the KWK. It MUST live off the backup path.

### Preferred: TPM 2.0 seal (`SECOND_FACTOR_MODE=tpm`)

Seal a 256-bit secret to the server TPM so it can only be unsealed on this
machine (a stolen DB backup, without the hardware, cannot derive the MK):

```bash
# Generate + seal at install (example with tpm2-tools)
head -c 32 /dev/urandom > /root/factor.bin
tpm2_createprimary -C o -g sha256 -G ecc -c /etc/llavero/primary.ctx
tpm2_create -C /etc/llavero/primary.ctx -i /root/factor.bin \
    -u /etc/llavero/factor.pub -r /etc/llavero/factor.priv
shred -u /root/factor.bin
# At unlock: tpm2_load + tpm2_unseal recovers the 32 bytes on this host only.
```

Wire `TPMSecondFactor(sealed_blob=..., unseal_fn=...)` where `unseal_fn` shells
out to `tpm2_unseal`. The sealed blob (`factor.pub`/`factor.priv`) is
TPM-bound, so it may sit on disk; it is useless on other hardware.

### Fallback: keyfile (`SECOND_FACTOR_MODE=keyfile`)

```bash
install -d -m 700 -o llavero -g llavero /etc/llavero
# Provision via a one-off management shell:
#   from apps.vault.second_factor import KeyfileSecondFactor
#   KeyfileSecondFactor.provision("/etc/llavero/vault.keyfile")
# It writes 32 bytes, 0600. Keep a copy in the safe with the recovery key,
# NEVER alongside database backups.
```

Set `KEYFILE_PATH=/etc/llavero/vault.keyfile`.

> Anti-lockout: a dead TPM or lost keyfile is recovered via the printed
> recovery key (P1-T10), an independent wrap of the MK.

## Printed recovery key (P1-T10 — Annex A 8)

The recovery key is a 256-bit secret that wraps the MK independently of any
admin credential. It is the last-resort anti-lockout path: if every admin
passphrase and the second factor are lost, the printed key alone recovers the
vault.

Establish at install (and re-establish after any MK rotation), via a one-off
management shell while an admin session holds the MK:

```python
from apps.vault import recovery
code, row = recovery.establish_recovery_key(mk=<in-memory MK>, created_by=<admin>)
print(code)   # shown ONCE
```

Procedure:
1. **Print** the displayed code immediately. It is shown once and is never
   stored in the database or written to a log.
2. **Store the printout in the physical safe**, together with (not co-located
   with backups) the keyfile if one is used. Two people should know the safe
   location; the code itself is single-secret.
3. **Verify before real data:** run a recovery drill (`recovery.recover_mk(code)`
   returns the MK) — this is exercised by the P1-T10 tests now and validated end
   to end at the **P4-T6 gate**. Do not load real secrets until P2-T6 and P4-T6
   pass.
4. **After MK rotation** (removing an admin, P1-T9): the old printed code is
   invalidated automatically. Immediately establish and **re-print** a new
   recovery key, then destroy the old printout.

Only the wrapped MK + a non-secret fingerprint are stored in `vault_recovery_key`;
the recovery key itself never touches disk.

---

## Backup system (P2-T1..T5 — Annex H)

The backup system runs `pg_dump` daily, encrypts with `age` (asymmetric), and
ships the encrypted dump to three destinations. The server holds **only the
backup public key** — a fully compromised server can create backups but cannot
decrypt them.

### Security constraint (P2-T3, Annex H 5)

These three items MUST be in the physical safe, NEVER stored with the backups:

| Item | Why |
|---|---|
| Backup private key (`llavero-backup-private.key`) | Decrypts every backup |
| Vault recovery key (printout) | Unlocks the vault on new hardware |
| Keyfile (`vault.keyfile`) if used | Second factor for the vault KWK |

Storing any of these alongside the backups would let a single theft undo the
entire encryption scheme.

### One-time key generation (run on an offline machine)

```bash
# On the offline/admin machine — NOT on the server
chmod +x deploy/backup/backup-keygen.sh
./deploy/backup/backup-keygen.sh /path/to/safe-mount

# Output:
#   llavero-backup-private.key  ← into the safe
#   llavero-backup.pub          ← copy to the server
```

Install the public key on the server:

```bash
install -d -m 750 -o root -g llavero /etc/llavero
install -m 644 -o root -g llavero llavero-backup.pub /etc/llavero/backup.pub
```

### Configure the backup environment

```bash
# Copy and fill in the template
cp deploy/backup/backup.env.example /etc/llavero/backup.env
chmod 640 /etc/llavero/backup.env
chown root:llavero /etc/llavero/backup.env
# Edit LLAVERO_BACKUP_HOST1/2/3, DB credentials, paths
```

### Create required directories

```bash
install -d -m 750 -o llavero -g llavero \
    /var/backups/llavero/staging \
    /var/backups/llavero/archive
install -d -m 750 -o llavero -g llavero /var/log/llavero
```

### SSH access to backup destinations (three copies, Annex H 4)

Each destination host needs a `backup` user with a write-only rsync target:

```bash
# On each destination host
useradd -r -s /usr/sbin/nologin backup
install -d -m 730 -o backup -g backup /srv/llavero-backups
# Restrict the backup user's SSH key to rsync only (authorized_keys):
#   command="rsync --server ...",no-pty,no-port-forwarding,no-X11-forwarding ssh-ed25519 ...
```

### Install the systemd timer

```bash
cp deploy/backup/llavero-backup.service /etc/systemd/system/
cp deploy/backup/llavero-backup.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now llavero-backup.timer
# Verify:
systemctl list-timers llavero-backup.timer
```

### GFS retention (Annex H 6)

The timer calls `backup.sh` which runs `manage.py backup_prune` after shipping:

| Bucket | Retention |
|---|---|
| Daily | Last 14 days |
| Weekly | Latest backup per ISO week, last 8 weeks |
| Monthly | Latest backup per calendar month, last 12 months |
| Audit chain | **Never pruned** |

Apply the same rules on each destination host (see `manage.py backup_prune --help`).

### Backup monitoring (P2-T5, Annex H 10)

`backup.sh` writes a JSON status file after every run and ships it to the
separate host. Check backup health:

```bash
# On the server or the separate host
manage.py backup_status        # exits 0 if OK, 1 if overdue/failed
# Output: {"overdue": false, "last_backup": "...", "hours_since": 1.2}
```

The `backup_overdue` alert rule (Annex E extensible catalog) will surface this
in the dashboard when Phase 6 alert tables are built. Until then, check via:

```bash
# Cron or systemd path — alert if exit 1
/opt/llavero/.venv/bin/python /opt/llavero/manage.py backup_status \
    || echo "BACKUP OVERDUE — check /var/log/llavero/backup-status.json"
```

### Manual test-run

```bash
# Run as the llavero user (dry-run: pipe to /dev/null instead of shipping)
sudo -u llavero LLAVERO_BACKUP_HOST1=... /opt/llavero/deploy/backup/backup.sh
```
