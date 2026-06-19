# Restore dry run — the P2-T6 GATE (Annex H 8, 9)

This is one of the two hard gates. **No real secret may be loaded into Llavero
until BOTH this gate (P2-T6) and the Phase 4 recovery-key reveal gate (P4-T6)
pass.** Until then, use throwaway data only.

A restore is trusted only when all three hold (Annex H 9):

1. **the database loads** from a decrypted dump in an isolated environment,
2. **the audit chain verifies** and matches the off-box signed checkpoint under
   an independently-trusted offline key, and
3. **a secret decrypts through the recovery-key path** — from restored bytes
   plus the printed recovery code alone, with no admin passphrase and no
   TPM/keyfile second factor (the new-hardware DR scenario, Annex H 7).

## Automated proof (runs in CI on throwaway data)

`tests/test_restore_dry_run.py` asserts, on every run:

- **Loads** — a full dump of every security table is captured, the live data is
  wiped (modelling total disk loss), and every row is restored byte-for-byte;
  row counts and a chain walk confirm the reload. When `pg_dump`/`pg_restore`
  are present, a real `pg_dump -Fc` archive of the test DB is additionally shown
  to be loadable and to contain the security tables.
- **Chain verifies + lag is visible** — `verify_restore()` walks the restored
  chain, matches it to the off-box signed checkpoint under the offline public
  key, and reports the daily-dump lag explicitly (`behind`, with a numeric
  `lag`) — never a silent gap (Annex H 8).
- **Recovery-key path** — with every `vault_key_holder` row deleted (old
  passphrases and the old TPM/keyfile gone), the printed code alone recovers the
  master key and decrypts the secret to its original value; the MK buffer is
  then wiped.
- **Security controls** — the recovery code is the sole input; the backup
  artifact contains no plaintext and no master key (only wrapped/ciphertext
  forms); AAD binding survives the restore (a relocated ciphertext fails); the
  restored chain stays tamper-evident; trust is anchored on the caller's offline
  key, never on a value read from the restored row; a Viewer stays keyless.

Run: `pytest tests/test_restore_dry_run.py` (and the full suite).

## Manual drill on the isolated host (cannot be asserted in CI)

Do this once before go-live, then on the drill cadence (quarterly default,
Annex H 9, 11). It exercises the real `age` decryption and a full PostgreSQL
load, which CI does not.

1. **Provision an isolated environment** — a throwaway host or VM, never the
   live database. Install the same PostgreSQL major version.

2. **Bring the offline keys from the safe** (Annex H 5), on removable media:
   - the backup **private** key (`llavero-backup-private.key`) — to decrypt;
   - the offline checkpoint **public** key (hex) — to anchor chain trust;
   - the **printed recovery code** — for the recovery-key decrypt drill.

   None of these is ever copied onto a server. Remove the media when done.

3. **Run the restore** against the isolated target:

   ```bash
   export LLAVERO_DRILL_RECOVERY_CODE='....-....-....'   # typed in, not stored
   ./deploy/backup/restore.sh \
       --backup     /media/safe/llavero_YYYYMMDDTHHMMSSZ.sql.gz.age \
       --private-key /media/safe/llavero-backup-private.key \
       --pubkey     /media/safe/offline-ed25519.pub.hex \
       --anchor-dir /srv/llavero-anchors \
       --target-db  llavero_restore_test \
       --recovery-code-env LLAVERO_DRILL_RECOVERY_CODE \
       --secret-id  <a-throwaway-secret-uuid>
   unset LLAVERO_DRILL_RECOVERY_CODE
   ```

   Expect: the dump decrypts and loads, then `restore_verify` reports
   `chain verified: True`, an `anchor state` of `current` or `behind`
   (the lag is fine and expected for a daily dump), `TRUSTWORTHY: True`, and
   `recovery drill: secret <id> decrypted (<n> bytes)`.

4. **Confirm the backups actually decrypt with the offline key** (Annex H 9) —
   step 3 already proves this for the chosen backup; spot-check an older one.

5. **Tear down** the isolated database (`dropdb llavero_restore_test`) and wipe
   the host. The decrypted dump is shredded by `restore.sh` on exit.

## Sign-off

P2-T6 is signed off when the automated suite is green AND the manual drill on the
isolated host passes (DB loads, chain verifies against the off-box checkpoint, a
throwaway secret decrypts via the recovery-key path).

- [ ] Automated `tests/test_restore_dry_run.py` green
- [ ] Manual isolated-host drill passed on ______________ (date) by ____________
- [ ] Backup decrypts with the offline private key confirmed
- [ ] Recovery-key decrypt path confirmed on the isolated host

Reminder: real secrets stay out until this gate **and** P4-T6 both pass.
