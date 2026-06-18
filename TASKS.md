# Llavero - Build Task Checklist (Claude Code working state)

Synced from `Llavero-v1-Build-Plan-Tracker.xlsx`. Decisions source of truth: Annex I + Master Index. `/start` reads this to route you; `/handoff` updates it. Mirror status back to the xlsx in Cowork periodically.

Status legend: `[x]` Done, `[~]` In progress, `[!]` Blocked, `[ ]` Not started. **GATE** and **VERIFY** rows are checkpoints.


## Phase 0 - Foundations
_Model/effort: infrastructure / OS work at the shell (Annex G); the P1-T1 scaffold uses Sonnet + medium._

- [x] **P0-T1** Confirm P-13: alert thresholds + E-1 unrecoverable device scope (Annex E 5, 9; Annex F 9) - deps: none _[Done]_
- [~] **P0-T2** Confirm P-14: TPM presence, separate host, disk unlock mode (Annex G 10 (3,4,7)) - deps: none _[In progress]_
- [~] **P0-T3** Confirm P-15: RPO target, offsite office, drill cadence (Annex H 11 (3,4,9)) - deps: none _[In progress]_
- [ ] **P0-T4** Record confirmations in the decision registry (Master Index 3, 6) - deps: P0-T1, P0-T2, P0-T3
- [ ] **P0-T5** Provision minimal hardened OS (Ubuntu 24.04, AppArmor/SELinux, chrony, swap off/encrypted, core dumps off) (Annex G 2) - deps: P0-T2
- [ ] **P0-T6** LUKS2 full-disk encryption, unlock bound to TPM2 + PIN (Annex G 3) - deps: P0-T2, P0-T5
- [ ] **P0-T7** Default-deny firewall (nftables/ufw) + SSH lockdown (key-only, no root) + fail2ban (Annex G 2, 8) - deps: P0-T5
- [ ] **P0-T8** Establish VPN-only access path (WatchGuard SSL VPN / MikroTik tunnels) with VPN MFA (Annex G 6) - deps: P0-T7
- [ ] **P0-T9** Provision/confirm the separate internal host (append-only checkpoints, shipped logs, backup copy 1) (Annex G 7; Annex H 4) - deps: P0-T2
- [ ] **P0-T10** Restrict outbound egress to Graph endpoints + LAN/tunnel reach only (Annex G 1, 8; Annex F 7) - deps: P0-T7

## Phase 1 - Security spine
_Model/effort: scaffold on Sonnet + medium, then Opus + xhigh (spike to max on T6, T7, T12, T13)._

- [ ] **P1-T1** Scaffold Django + PostgreSQL (scram-sha-256, localhost bind, reverse proxy internal-CA TLS, hardened systemd unit) (Annex G 5; Prelim 8) - deps: P0-T5
- [ ] **P1-T2** Annex C core entity models (operator, person, account, device, network_device_detail, office, secret, field_definition): UUIDv4, base mixin, enums (Annex C 2, 3, 4, 9) - deps: P1-T1
- [ ] **P1-T3** Nine relationship join tables with FK integrity + partial unique indexes (Annex C 5, 6) - deps: P1-T2
- [ ] **P1-T4** Session tables (operator_session, session_request) (Annex C 4.3, 4.3b) - deps: P1-T2
- [ ] **P1-T5** Argon2id calibration on the real server (~4s target, 1-2 GiB, parallelism = cores) (Annex A 5.1, 11) - deps: P0-T5
- [ ] **P1-T6** Envelope encryption passphrase->KWK->MK->DEK, XChaCha20-Poly1305 + AAD (PyNaCl, argon2-cffi) (Annex A 3, 4, 11; Annex C 4.9) - deps: P1-T5
- [ ] **P1-T7** Vault second factor: TPM 2.0 sealing combined via HKDF (keyfile fallback) (Annex A 5.2; Annex G 4) - deps: P1-T6, P0-T6
- [ ] **P1-T8** Master key in memory: mlock, memzero on lock/logout/shutdown, idle auto-lock, no core dumps (Model A) (Annex A 6, 7; Annex G 2) - deps: P1-T6
- [ ] **P1-T9** Per-administrator key wrapping: vault_key_holder table, enroll/remove + MK rotation (Annex A 13) - deps: P1-T6
- [ ] **P1-T10** Generate printed recovery key + safe-storage procedure (independent MK wrap) (Annex A 8) - deps: P1-T6
- [ ] **P1-T11** Audit schema (audit_entry, audit_checkpoint) + append-only DB role + BEFORE UPDATE/DELETE trigger (Annex B 4, 5; Annex G 5) - deps: P1-T2
- [ ] **P1-T12** Hash chain: BLAKE2b-256, canonical length-prefixed payload, same-transaction insert, advisory-lock ordering (Annex B 3, 5) - deps: P1-T11
- [ ] **P1-T13** Chain verification (walk + anchor check) + signed checkpoint via Admin WebAuthn signing (Annex B 7; Annex G 7) - deps: P1-T12, P1-T9
- [ ] **P1-T14** Off-box checkpoint anchoring to the separate host (append-only) + printed-copy procedure (Annex G 7; Annex B 2) - deps: P1-T13, P0-T9
- [ ] **P1-T15** Operator auth: login password (Argon2id hash), WebAuthn (py_webauthn) + TOTP (pyotp) (Annex D 1, 2; Annex C 4.1, 4.2; Prelim 6) - deps: P1-T1, P1-T2
- [ ] **P1-T16** Single active session via advisory lock; Viewer session never unlocks the MK (Annex D 2, 8; Annex C 4.3) - deps: P1-T4, P1-T15
- [ ] **P1-T17** Step-up reauth framework (per-action + windowed ~2 min) + idle auto-lock (Annex D 6) - deps: P1-T15, P1-T8
- [ ] **P1-T18** Session handover hybrid B+C: idle-yield 120s, grace 300s, extend +600s, release-now, depleting-bar cue (Annex D 8 (chosen config); Annex C 4.3b) - deps: P1-T16
- [ ] **P1-T19** Thin vertical slice: one entity + one secret + one logged change + one login, end to end (Annex I 3 (Phase 1)) - deps: P1-T6, P1-T12, P1-T15, P1-T16
- [ ] **P1-T20** **VERIFY** [VERIFY] Spine test pass: chain verifies; MK absent from disk/swap/core; Viewer cannot decrypt (Annex I 4, 5) - deps: P1-T19

## Phase 2 - Backups
_Model/effort: Sonnet + high (Opus + max for the P2-T6 gate)._

- [ ] **P2-T1** Daily pg_dump on a timer; asymmetric encrypt at rest (age/gpg), public key on server (Annex H 3) - deps: P1-T2
- [ ] **P2-T2** Three destinations: separate host (copy 1), second host/NAS (copy 2), offsite office over MikroTik tunnel (copy 3) (Annex H 4) - deps: P2-T1, P0-T9
- [ ] **P2-T3** Keep private key / recovery key / keyfile in the safe, never with the backups (Annex H 5) - deps: P2-T1
- [ ] **P2-T4** Retention GFS: daily 14d, weekly 8w, monthly 12m; chain never pruned (Annex H 6) - deps: P2-T1
- [ ] **P2-T5** Backup monitoring: success/failure logged + shipped to the separate host; seed backup_overdue alert (Annex H 10) - deps: P2-T1, P1-T14
- [ ] **P2-T6** **GATE** [GATE] First restore dry run to an isolated env: DB loads, chain verifies, a secret decrypts via the recovery-key path (Annex H 8, 9) - deps: P2-T1, P2-T3, P1-T13

## Phase 3 - Inventory
_Model/effort: Sonnet + medium._

- [ ] **P3-T1** CRUD + forms for person, account, device, office (+ network_device_detail) (Annex C 4; Prelim 3) - deps: P1-T2
- [ ] **P3-T2** Relationship UI: create/end typed links from any entity page (find, pick type, save) (Annex C 5; Prelim 4) - deps: P1-T3, P3-T1
- [ ] **P3-T3** State machines per entity + no-hard-delete (terminal states only) (Annex C 1, 3) - deps: P3-T1
- [ ] **P3-T4** Custom fields: field_definition admin + typed rendering + viewer_visible (Annex C 4.10, 9; Annex D 5) - deps: P3-T1
- [ ] **P3-T5** Responsive HTMX UI + list/search (Prelim 8; Annex D 4) - deps: P3-T1
- [ ] **P3-T6** Wire writes to the audit chain + read-logging granularity (record_view/list_view/search; no pagination) (Annex B 6; Annex D 6) - deps: P1-T12, P3-T1
- [ ] **P3-T7** Field-level permissions + serializer masking; server-side action matrix (Annex D 3, 4, 5, 9) - deps: P3-T1, P1-T17
- [ ] **P3-T8** **VERIFY** [VERIFY] Audit coverage check + Viewer masking holds server-side (Annex B 6; Annex D 9) - deps: P3-T6, P3-T7

## Phase 4 - Secrets
_Model/effort: Opus + xhigh (max for the P4-T6 gate)._

- [ ] **P4-T1** Secret store UI: create a secret per kind, AAD bound to the record (Annex A 3, 10; Annex C 4.9; Annex D 4) - deps: P1-T6, P3-T1
- [ ] **P4-T2** Reveal flow: step-up reauth (no cache) + reason, transient display, clipboard auto-clear, never logged/cached (Annex D 6, 7; Annex A 6) - deps: P1-T8, P1-T17, P4-T1
- [ ] **P4-T3** Rotation: new DEK + ciphertext, last_rotated_at; secret_rotate logged (Annex A 9; Annex C 4.9) - deps: P4-T1
- [ ] **P4-T4** Viewer masking backed by the keyless session (cryptographic, not just policy) (Annex D 2, 5) - deps: P1-T16
- [ ] **P4-T5** Secret audit coverage (create/rotate/reveal/state_change, non-sensitive facts only) (Annex B 6) - deps: P1-T12, P4-T1
- [ ] **P4-T6** **GATE** [GATE] Recovery-key reveal path validated end to end (Annex A 8; Annex H 7, 9) - deps: P4-T2, P2-T6

## Phase 5 - Integrations
_Model/effort: Sonnet + high._

- [ ] **P5-T1** integration table + scheduler (per-interval runs, last_run_at/last_status) (Annex F 2) - deps: P3-T1
- [ ] **P5-T2** Graph app registration (app-only, certificate auth), read-only scopes (User.Read.All + AuditLog.Read.All / UserAuthenticationMethod.Read.All); cert as a secret (Annex F 3; Annex G 6) - deps: P5-T1, P4-T1
- [ ] **P5-T3** Graph MFA pull daily: userRegistrationDetails -> account.mfa_state/mfa_types; match by external_id; surface unmatched (Annex F 3, 8) - deps: P5-T2
- [ ] **P5-T4** Network monitoring: WatchGuard SNMPv3, MikroTik RouterOS API/TLS or SNMP, UniFi controller API/HTTPS; creds as secrets; 5-min cadence (Annex F 4, 7) - deps: P5-T1, P4-T1
- [ ] **P5-T5** Telemetry table + transition-only chaining; live network_device_detail update (Annex F 6; Annex B 5) - deps: P5-T4, P1-T12
- [ ] **P5-T6** **VERIFY** [VERIFY] Read-only proof: no write scopes, egress limited to Graph + gear, telemetry off-chain (Annex F 1, 7; Annex I 5) - deps: P5-T3, P5-T5

## Phase 6 - Alerts & dashboard
_Model/effort: Sonnet + high._

- [ ] **P6-T1** alert + setting tables; idempotent eval keyed by (rule_id, target); system actor reads not logged (Annex E 3, 4) - deps: P3-T1
- [ ] **P6-T2** Scheduled evaluator (eval_interval default 15) + on-demand dashboard refresh (Annex E 3) - deps: P6-T1
- [ ] **P6-T3** Implement the 13 rules E-1..E-13 over the relationship graph (Annex E 6; Annex C 7) - deps: P6-T1, P3-T2, P5-T5
- [ ] **P6-T4** Auto-resolve + rotation-evidence exceptions (account_compromised, needs_rotation) (Annex E 3, 6) - deps: P6-T3, P4-T3
- [ ] **P6-T5** Dashboard: severity grouping, acknowledge w/ note (Admin), filters, entity links (Annex E 7; Annex D 4) - deps: P6-T3
- [ ] **P6-T6** Integrity strip + E-13 self-monitoring ('verified through seq N, last checkpoint at T') (Annex E 7, 8; Annex B 7) - deps: P6-T3, P1-T13
- [ ] **P6-T7** Thresholds in the setting table, Admin-editable + parameter_change logged (Annex E 5; Annex D 4) - deps: P6-T1
- [ ] **P6-T8** **VERIFY** [VERIFY] Rule-firing tests incl. E-1 on seeded data; alert state changes logged, eval reads not (Annex E 8; Annex I 4) - deps: P6-T3, P5-T5

## Phase 7 - Release gate
_Model/effort: Opus + max._

- [ ] **P7-T1** **GATE** [GATE] Full DR drill to new hardware: provision, restore offsite backup, unlock via recovery key, re-seal TPM, re-enroll admins, re-point integrations, verify chain (Annex H 7, 8; Annex G 9) - deps: P2-T6, P4-T6
- [ ] **P7-T2** Security pass: egress, role/field matrix, Viewer export block, single session (Annex D 4, 9; Annex F 7; Annex G 1, 8; Annex I 5) - deps: P3-T8, P4-T6, P5-T6, P6-T8
- [ ] **P7-T3** Handover polish + countdown QA (amber <60s, red <20s, release locked first 5s) (Annex D 8) - deps: P1-T18
- [ ] **P7-T4** Confirm reauth window (2 min default) + idle auto-lock alignment (Annex D 6, 10) - deps: P1-T17
- [ ] **P7-T5** **GATE** [GATE] Load real data + go live (Annex I 3 (Phase 7), 4) - deps: P7-T1, P7-T2
- [ ] **P7-T6** **VERIFY** [VERIFY] v1 definition-of-done checklist signed off (Annex I 4) - deps: P7-T1, P7-T2, P7-T3, P7-T5
