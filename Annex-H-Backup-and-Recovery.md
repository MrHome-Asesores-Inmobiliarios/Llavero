# Annex H: Backup and Recovery

**Companion to the preliminary design and to Annexes A, B, and G.** Defines what is backed up, how, where, how it is recovered, and how the recovery is tested. This system is the single point of access to the whole organization, so a tested recovery is not optional.

---

## 1. Goals

- Survive disk corruption, server failure, and lost credentials, without losing the inventory, the secrets, or the audit history.
- A clear, tested path back, with known targets:

| Measure | Target |
|---|---|
| RPO, how much data you can lose | 24 hours with daily dumps, minutes if WAL archiving is added (section 3) |
| RTO, same-server restore | minutes to a couple of hours |
| RTO, full DR to new hardware | bounded by provisioning plus restore plus re-enroll (section 7) |

---

## 2. What is backed up

- **The PostgreSQL database.** This is the bulk of it: inventory, relationships, the audit chain, settings, and the secrets, which are already encrypted at the field level (Annex A). It also holds the wrapped master keys (`vault_key_holder`).
- **The Graph certificate and the reverse-proxy TLS cert**, which live as secrets or files on the server.
- **Server configuration**: systemd units, firewall and proxy config, so a rebuild is fast.
- **Not a digital backup, but part of recovery:** the printed recovery key and, if used, the keyfile, both in the safe.

Note: backing up the database does not, by itself, let anyone read the secrets. The field encryption still requires the vault master key, which needs the TPM-sealed factor (machine-bound) or the recovery key. That is the intended property.

---

## 3. Backup method

- **Logical dumps** with `pg_dump` on a schedule (daily). Simple and enough for this scale.
- **Optional WAL archiving** for point-in-time recovery, which brings the RPO from a day down to minutes. Recommended if losing a day of edits is unacceptable. At your write volume, daily may be fine, this is a choice in the open points.
- **Encrypt every backup at rest.** The inventory and the audit log are sensitive even though the secrets inside are already encrypted, so the whole dump is encrypted with `age` (or gpg).
- **Use asymmetric encryption.** The server holds only the backup public key and encrypts to it. The private key lives offline in the safe. A fully compromised server can therefore create new backups but cannot decrypt existing ones. This is a deliberate, strong property.

---

## 4. Destinations (on-prem, no cloud, no third party)

A 3-2-1 approach adapted to your sites, all copies encrypted:

| Copy | Where |
|---|---|
| 1 | The separate internal host from Annex G (the one that also holds audit anchors and logs) |
| 2 | A second host or NAS you already own |
| 3, offsite | Replicated over a MikroTik site-to-site tunnel to another office |

"Offsite" is satisfied by another of your own offices across the existing tunnel, so nothing leaves your control and there is no cloud cost.

---

## 5. What must never sit with the backups

- The backup private key. In the safe, offline.
- The vault recovery key (Annex A, section 8). In the safe.
- The keyfile, if used instead of the TPM (Annex G, section 4). In the safe.

If any of these were stored next to the backups, a single theft would undo the whole scheme.

---

## 6. Retention

Grandfather-father-son, generous because the data is small:

- Daily kept 14 days, weekly kept 8 weeks, monthly kept 12 months.
- The audit chain is append-only and never pruned. Each newer backup simply contains a longer chain.

---

## 7. Recovery procedures

### Same server, database corruption
Restore the latest dump, decrypt with the backup private key, and the vault unlocks normally because the TPM is still present and an administrator enters their passphrase. Fastest path.

### New hardware, full disaster recovery
1. Provision a hardened server per Annex G.
2. Restore the database from the offsite backup and decrypt it.
3. Unlock the vault with the **printed recovery key**, since the old TPM-sealed factor is gone with the old machine.
4. Re-seal the vault factor to the new TPM, re-enroll both administrators with new passphrases.
5. Re-point integrations, re-add the Graph certificate if needed.
6. Verify the audit chain (section 8), then resume.

### Lost passphrases or lost admin credentials
The recovery key unlocks the vault, then re-enroll the administrators.

### The unrecoverable case
If the recovery key, all administrator credentials, and the TPM are all lost at once, the secrets cannot be recovered. That is why the recovery key in the safe is the linchpin, protected and tested.

---

## 8. Verifying the restore against the audit checkpoints

After a restore, run the chain verification (Annex B) and compare the restored head against the signed checkpoints held on the separate host (Annex G). This proves the restored data was not tampered with. If you restored a daily dump rather than using WAL, the restored head will be behind the latest off-box checkpoint by up to a day, which is expected and visible, not a silent gap.

---

## 9. Testing

- **Before go-live**, do a full dry run: restore to an isolated environment, confirm the database loads, the chain verifies, and a secret decrypts through the recovery-key path. An untested recovery key is a false sense of safety.
- **Periodically**, a restore drill (quarterly is a sensible default), including the recovery-key path, not just the daily-passphrase path.
- Confirm each drill that the backups actually decrypt with the offline key.

---

## 10. Monitoring

- The backup job runs on a timer, logs success or failure, and ships its result to the separate host.
- A failed or overdue backup surfaces as an alert. This is a natural addition to the Annex E catalog (a `backup_overdue` rule with a `backup_overdue_hours` threshold), in keeping with that catalog being extensible.

---

## 11. Open points

1. **RPO target.** Daily dumps (24 hour RPO) or daily plus WAL archiving (minutes). Driven by how much edit loss is acceptable.
2. **Offsite office.** Which office is the replication target across the tunnel.
3. **Drill cadence.** Quarterly is the default for the restore test.

This annex resolves backlog item P-08.
