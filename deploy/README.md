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
