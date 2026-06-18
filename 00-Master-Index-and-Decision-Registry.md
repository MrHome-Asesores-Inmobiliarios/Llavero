# Master Index and Decision Registry

**Project:** Secure Credentials and IT Asset System
**Company:** Real estate firm (Santo Domingo)
**Document:** the plan's control center. It lives and is updated every iteration.
**This version:** 2026-06-02

---

## 1. What this document is for

This is the control document. Its job is to keep any decision from being trapped only in a chat message, where it gets lost. Every time we close something, it enters the decision registry (section 3). Every time we open a new topic, it enters the backlog (section 4).

Simple rule: if it is not in this index, it is not decided.

When you bring everything to Cowork, this document is the map. The others (preliminary design and annexes) are the detail.

---

## 2. Document map

| Document | Content | Status |
|---|---|---|
| 00 Master Index and Decision Registry (this one) | Central control, decisions, pending items, roadmap | Live |
| Preliminary Design v2 | Vision, entities, relationships, security, integrations, requirements mapping | Done, open to refinement |
| Annex A, Encryption Scheme | Secret encryption and master key handling | Done |
| Annex B, Hash-chained Audit Log | Scheme and verification of the tamper-evident log | Done |
| Annex C, Detailed Data Model | Exact fields per entity and relationship catalog | Done |
| Annex D, Permissions and Roles | Field-by-field matrix, what requires reauthentication | Done |
| Annex E, Alert Engine | Rules, graph conditions, and thresholds | Done |
| Annex F, Read-only Integrations | Graph permissions, network queries, frequency | Done |
| Annex G, Hardening and Deployment | OS, network, VPN, TPM, exposure | Done |
| Annex H, Backup and Recovery | Operational plan with recovery test | Done |
| Annex I, MVP Scope and Phases | What goes into v1 and what is deferred | Done |

---

## 3. Decision registry (what is closed)

| ID | Topic | Decision | Iteration | Notes |
|---|---|---|---|---|
| D-01 | Build approach | 100% in-house, a single application | 2 | Hybrid with external vault dropped |
| D-02 | Cost | Zero. Free software only, no paid services or third parties | 2 | |
| D-03 | v1 scope | Record, report, and query only. No advanced operations (no MFA restore, no remote changes) | 2 | |
| D-04 | Secret storage | Encrypted field inside the same PostgreSQL. No external vault | 2 | |
| D-05 | Data encryption | XChaCha20-Poly1305, 256 bits, with AAD bound to the record | 3 | AES-256-GCM is a valid alternative |
| D-06 | Key derivation | Argon2id, 1 to 2 GiB, calibrated to about 4 s on the real server | 3 | This is where the tolerated 2 to 8 s go |
| D-07 | Key hierarchy | Envelope encryption: passphrase to KWK to MK to per-secret DEK | 3 | Lets you rotate without re-encrypting |
| D-08 | Second factor (partial) | Key material outside the database. WebAuthn PRF as a future premium | 3 | Keyfile vs TPM still to choose, see P-01 |
| D-09 | Key in memory | Model A: derive at unlock, MK in locked memory, idle auto-lock | 3 | Model B documented as a max-paranoia option |
| D-10 | Stack (proposed) | Django, PostgreSQL, HTMX, PyNaCl, argon2-cffi, pyotp, py_webauthn | 2 to 3 | To validate during planning |
| D-11 | Roles and session | Administrator and Viewer roles. One active session at a time | 2 | |
| D-12 | Login MFA | Platform WebAuthn first, TOTP alternative. Hardware keys optional and future, by cost | 2 | |
| D-13 | Integrations | All read only. M365 Graph to list users and check MFA. Odoo and ZKBioTime deferred | 2 | |
| D-14 | Hosting and access | Local server, no internet exposure, remote access via VPN only | 2 | Reuses WatchGuard and MikroTik |
| D-15 | Audit log (concept) | Append-only, hash chained, with who, when, and what | 2 | Detailed scheme pending, see P-02 |
| D-16 | Backup (concept) | Encrypted pg_dump, copy on own storage and offsite, tested restore | 2 | Operational plan pending, see P-08 |
| D-17 | Anti-lockout recovery | Printed recovery key in a safe, keyfile backup, Shamir optional | 3 | Test before loading real data |
| D-18 | Plan format and language | No published artifact. Modular markdown files. Working language English | 5 | Spanish drafts replaced by English versions |
| D-19 | Primary keys | UUID v4 for every table | 6 | No perceptible cost at this scale, no extension needed |
| D-20 | Relationship modeling | Explicit join tables with database-enforced integrity, not a generic edge table | 6 | Recovery contact split into account and device tables |
| D-21 | Multi-owner accounts | Supported in v1 via account_ownership with role primary or shared | 6 | At most one active primary owner per account |
| D-22 | v1 scope trims | Per-NIC detail and richer network detail deferred to v2. IPAM (network segments) deferred | 6 | Designs kept in Annex C section 10 |
| D-23 | Audit log design | Append-only (DB role plus trigger), BLAKE2b-256 hash chain, same-transaction writes, advisory-lock ordering, signed external checkpoints, monitoring telemetry off the chain, secret plaintext never logged | 7 | Anchoring infrastructure is P-10 |
| D-24 | Read logging | Reads are logged into the same chain (record_view, list_view, search), with granularity to avoid noise. Machine monitoring reads excluded | 8 | Amends Annex B coverage |
| D-25 | Permissions model | Two roles. Viewer session never holds the master key, so it cannot reveal secrets by cryptography, not just by policy. Step-up reauth on the most sensitive actions. System-wide single session | 8 | Detail in Annex D |
| D-26 | Administrators | Two Administrators. One master key for the vault, wrapped per administrator (multi-recipient). Enroll and removal procedures defined | 9 | Annex A section 13, closes P-11 |
| D-27 | Viewer exports | Viewer is fully blocked from exports | 9 | Export is data egress |
| D-28 | Session handover config | Hybrid of B and C. Idle auto-yield 120 s, active grace 300 s, extend +600 s, release now. Visual cue is a depleting bar in seconds with a sidenote, amber under 60 s and red under 20 s. Release locked for first 5 s | 10 | Detail in Annex D section 8, closes P-12 |
| D-29 | Alert engine | 13 rules over the graph, three severities, scheduled plus on-demand evaluation by a system actor, alert table with open/acknowledged/resolved, auto-resolve, thresholds in a setting table. Phone-reset case is E-1 | 11 | Detail in Annex E, closes P-05 |
| D-30 | Integrations | All read only. Graph app-only with certificate and read-only scopes for the MFA report, daily. WatchGuard, MikroTik, UniFi via read-only SNMPv3 or scoped APIs every 5 minutes. Credentials in the vault. Odoo and ZKBioTime deferred | 12 | Detail in Annex F, closes P-06 |
| D-31 | Hardening and deployment | One internal server, app plus PostgreSQL, no internet exposure, VPN-only remote access with VPN MFA. LUKS2 with TPM plus PIN. Vault second factor is TPM sealing (keyfile fallback). Hardened systemd and DB roles. Checkpoints signed by an Administrator WebAuthn key, copied append-only to a separate host plus printed in the safe | 13 | Detail in Annex G, closes P-01, P-07, P-10 |
| D-32 | Backup and recovery | Daily encrypted pg_dump (optional WAL for PITR), asymmetric encryption with the private key offline, three copies including one offsite over a tunnel to another office. Recovery key is the DR linchpin. Restore tested before go-live and quarterly | 14 | Detail in Annex H, closes P-08 |
| D-33 | MVP scope and phases | v1 is record, report, query only. Eight build phases, security spine is the long pole built via a thin vertical slice first. Odoo, ZKBioTime, IPAM, per-NIC detail, and all writes deferred | 15 | Detail in Annex I, closes P-09 |

Iteration 1 was the initial concept. Iteration 2 fixed zero cost, in-house, and read only. Iteration 3 closed the encryption. Iteration 4 built this index. Iteration 5 dropped the artifact and moved the plan to English. Iteration 6 settled the data model open points (PK type, join tables, multi-owner, v1 scope trims). Iteration 7 defined the audit log. Iteration 8 turned on read logging and defined permissions and roles. Iteration 9 set two administrators with per-admin key wrapping, blocked Viewer exports, and laid out the session handover models. Iteration 10 chose the hybrid handover with its timers and the depleting-seconds visual cue. Iteration 11 defined the alert engine. Iteration 12 defined the read-only integrations. Iteration 13 set hardening and deployment, the vault second factor, and audit anchoring. Iteration 14 defined backup and recovery. Iteration 15 set the MVP scope and the phased build plan, completing the roadmap.

---

## 4. Pending decisions (backlog)

| ID | Topic | Why it matters | Resolved in |
|---|---|---|---|
| P-01 | Keyfile vs TPM as the concrete second factor | Decides whether a stolen database backup is decryptable or not | Annex G section 4 (resolved) |
| P-02 | Exact hash-chained audit log scheme | It is the tamper-evident proof of who did what | Annex B (resolved) |
| P-03 | Exact fields per entity and relationship catalog | It is the base of the data model, everything else hangs from it | Annex C (resolved) |
| P-04 | Field-by-field permission matrix | Defines what each role sees and edits, and what requires reauthentication | Annex D (resolved) |
| P-05 | Alert engine rules and thresholds | Defines which risks the dashboard detects and when | Annex E (resolved) |
| P-06 | Graph permissions and network device queries | Defines the real scope of the read-only integration and its frequency | Annex F (resolved) |
| P-07 | OS, network, and deployment hardening | Defines the server's attack surface | Annex G (resolved) |
| P-08 | Operational backup and recovery plan | Without it, the single point of access is also a single point of failure | Annex H (resolved) |
| P-09 | MVP scope and phases | Keeps v1 from growing without control and never shipping | Annex I (resolved) |
| P-10 | Audit anchoring target and checkpoint signing key | Decides whether the log resists a malicious administrator, not just casual tampering | Annex G section 7 (resolved) |
| P-11 | Multi-administrator master key wrapping | If more than one Administrator can reveal secrets, the master key must be wrapped per administrator | Annex A section 13 (resolved) |
| P-13 | Alert thresholds and unrecoverable device scope | Tunes the alert defaults and whether laptops or tablets also trigger the unrecoverability rule | Your confirmation, defaults in Annex E |
| P-12 | Session handover model | Picks how a second user gains access while one is active, and the related thresholds | Annex D section 8 (resolved) |
| P-14 | TPM presence, anchoring host, disk unlock mode | Three deployment confirmations from Annex G | Your confirmation, defaults in Annex G |
| P-15 | RPO target, offsite office, drill cadence | Three backup confirmations from Annex H | Your confirmation, defaults in Annex H |

---

## 5. Definition roadmap (suggested order before starting)

Ordered so each step builds on the previous one:

1. **Annex C, detailed data model.** Done. Defines entities, fields, and exact relationships. Everything else hangs from here.
2. **Annex B, hash-chained audit log.** Done. Defines how each change to the Annex C tables is recorded and verified.
3. **Annex D, permissions and roles.** Done. Defines who touches what, field by field, and what requires reauthentication.
4. **Annex E, alert engine.** Done. Turns the data model and the relationship graph into dashboard warnings.
5. **Annex F, read-only integrations.** Done. Graph permissions and network queries.
6. **Annex G, hardening and deployment.** Done. Includes the keyfile vs TPM decision (P-01).
7. **Annex H, backup and recovery.** Done. Operational plan with a tested restore.
8. **Annex I, MVP scope and phases.** Done. Closes what goes into v1 and the build order.

All nine documents are green. The plan is complete and ready to become tasks in Cowork. The only items left are the field confirmations P-13, P-14, and P-15, which have defaults and are settled during build Phase 0.

---

## 6. Versioning convention

- This index carries the date of its last update.
- Each annex carries its own status in section 2.
- When a decision changes, it is not deleted. The row in the registry is updated and the reason is noted in Notes. That preserves the history of why something changed.
