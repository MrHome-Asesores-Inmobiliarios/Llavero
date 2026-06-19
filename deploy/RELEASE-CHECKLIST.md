# Llavero v1 Release Checklist

**Source of truth:** Annex I §4 — Definition of done for v1.

Sign-off legend:
- `[x]` — Automated: proven green by CI / test suite.
- `[ ]` — Operator: requires a human action on the real server.

---

## Hard gates (must be both ✅ before loading real secrets)

| Gate | Automated | Manual drill |
|------|-----------|--------------|
| P2-T6: Restore dry-run (encrypted archive → DB verify) | [x] `tests/test_restore_dry_run.py` passes | `[ ]` Full DR drill on real hardware |
| P4-T6: Recovery-key path validated (vault unlock via printed key) | [x] `tests/test_recovery.py` passes | `[ ]` Confirmed on real hardware with printed key |

---

## Phase 1 — Security spine

- [x] Schema: all five entity tables exist with UUID PKs (migration 0001, `test_models.py`)
- [x] Encryption: Argon2id KDF, envelope encryption (XChaCha20-Poly1305), per-admin wrapping (`test_kdf.py`, `test_crypto_envelope.py`)
- [x] Audit log: hash chain, append-only trigger, same-transaction writes, advisory-lock ordering (`test_audit_chain.py`, `test_audit_append_only.py`, `test_audit_anchor.py`)
- [x] Signed checkpoints anchored off-box (`test_audit_checkpoint.py`)
- [x] Two roles — Administrator (read/write + reveal) and Viewer (read-only, keyless) (`test_sessions_single.py`)
- [x] Single active session system-wide; new login revokes prior (`test_sessions_single.py`)
- [x] Handover: hybrid B+C state machine, countdown cue (`test_handover.py`, `test_p7_handover.py`)
- [x] Step-up reauth window aligned with idle auto-lock (`test_p7_config.py`)
- [x] WebAuthn / TOTP operator auth (`test_operator_auth.py`)
- [x] Second factor (keyfile / TPM-sealed) present (`test_second_factor.py`)
- [ ] P1-T5: Argon2id parameters calibrated on the **real** production CPU/RAM
- [ ] P1-T7: TPM 2.0 sealing confirmed on the real hardened server

---

## Phase 2 — Backups

- [x] Backup retention logic (`test_backup_retention.py`)
- [x] Backup status reporting (`test_backup_status.py`)
- [x] Restore dry-run automated path (`test_restore_dry_run.py`)
- [ ] Daily encrypted dump job running (`backup.sh` scheduled via cron/systemd)
- [ ] Three backup destinations reachable: local, NAS, offsite office
- [ ] P2-T6: Manual restore drill on isolated host completed and result verified

---

## Phase 3 — Inventory

- [x] CRUD for Person, Account, Device, Office with states and custom fields (`test_inventory_views.py`, `test_models.py`)
- [x] Nine join-table relationships (`test_relationships.py`)
- [x] State transitions correct; no terminal-state bypass
- [x] Writes audited, reads logged in the same transaction (`test_inventory_audit.py`)
- [x] No hard-delete URLs exposed — URLconf verified (`test_p7_security_pass.py`)

---

## Phase 4 — Secrets

- [x] Secrets stored encrypted (envelope encryption, DEK-wrapped) (`test_crypto_envelope.py`)
- [x] Reveal requires per-action step-up reauth (`test_stepup.py`, `test_secrets_views.py`)
- [x] Viewer is masked and keyless — `is_vault_unlocked()` is False for Viewer sessions (`test_p7_security_pass.py`)
- [x] Rotation creates fresh DEK, re-encrypts, step-up enforced
- [x] P4-T6: Recovery-key unlock path passes automated tests (`test_recovery.py`, `test_p4_gate.py`)
- [ ] P4-T6: Manual recovery-key drill on real hardware completed

---

## Phase 5 — Integrations (read-only)

- [x] Graph MFA pull: OAuth2 client_credentials, read-only scope, token wiped after use (`test_integrations_verify.py`)
- [x] WatchGuard SNMPv3 runner: read-only OID walk
- [x] MikroTik RouterOS API runner: read-only queries
- [x] UniFi controller runner: read-only GET
- [x] Egress guard: runner files contain no rogue hardcoded URLs (`test_p7_security_pass.py`)
- [x] Write scope never requested — all integrations are READ-ONLY (hard constraint D-33)

---

## Phase 6 — Alerts and dashboard

- [x] 13 alert rules implemented and evaluated (`test_alerts_verify.py`)
- [x] Dashboard: active alerts with acknowledge flow
- [x] E-1 (phone-reset unrecoverability) rule wired to `account_device_config` (not `account_configured_on_device`)
- [x] Alerts do not log secrets or MK

---

## Phase 7 — Release gate

- [x] Security pass: egress, role/field matrix, Viewer export block, single session, audit completeness, keyless Viewer, no-hard-delete (`test_p7_security_pass.py`)
- [x] Handover countdown: amber < 60 s, red < 20 s, release locked first 5 s (`test_p7_handover.py`)
- [x] Reauth window + idle auto-lock alignment within spec (`test_p7_config.py`)
- [x] Django system check: zero errors (`test_p7_checklist.py`)
- [x] No pending migrations (`test_p7_checklist.py`)
- [x] Test suite ≥ 350 passing tests (`test_p7_checklist.py`)
- [x] Vendored `static/js/htmx.min.js` present (`test_p7_checklist.py`)
- [ ] P7-T1: Full DR drill to new hardware — complete, timed, result recorded
- [ ] P7-T5: Load real data (operators, secrets, inventory) on the hardened server
- [ ] Hardened server confirmed: minimal OS, LUKS2 + TPM + PIN, firewall, VPN-only access
- [ ] Separate anchoring/log host reachable and receiving signed checkpoints
- [ ] Go-live sign-off by responsible operator

---

## Pre-build confirmations (Annex I §6)

- [ ] P-13: Alert thresholds reviewed; E-1 device scope confirmed (phones only, or extended)
- [ ] P-14: TPM 2.0 confirmed present; separate host provisioned; disk unlock mode confirmed (TPM + PIN)
- [ ] P-15: RPO target confirmed (daily, or daily + WAL); offsite office identified; drill cadence agreed (default: quarterly)

---

*Last automated run: see CI output. Operator items require sign-off in the Cowork task tracker.*
