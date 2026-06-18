# Annex I: MVP Scope and Phases

**Companion to the preliminary design and to all prior annexes.** Turns the decisions into a build: what is in v1, what is deferred, the order to build it, and what "done" means. This is the document Cowork turns into milestones and tasks.

---

## 1. What v1 is

v1 is a working, secure, single-server system that records users, accounts, devices, and offices, relates them, stores their secrets encrypted, logs every action verifiably, reads MFA and network status, and surfaces risk on a dashboard. It is **record, report, and query only**. It never writes to an external system.

Guiding rule for scope: if a feature is not needed to safely hold the data and show the risk, it waits for v2.

---

## 2. In v1 vs deferred

| In v1 | Deferred to v2 or later |
|---|---|
| Five core entities, typed relationships via join tables, states, custom fields | Odoo and ZKBioTime integrations (D-13) |
| Secrets: store, reveal with reauth, rotate, Viewer masking, two-admin per-admin key wrapping, recovery key | IPAM (network segments) and per-NIC detail (D-22) |
| Hash-chained audit log, reads logged, signed anchored checkpoints | WebAuthn PRF premium factor (Annex A) |
| Two roles, system-wide single session, hybrid handover with the countdown cue | Any write or remediation to external systems |
| Graph MFA read-only reporting | Hardware security keys, Shamir recovery split |
| Network monitoring (WatchGuard, MikroTik, UniFi), read only | Extra alert rules beyond the v1 catalog |
| Alert engine (13 rules) and dashboard | |
| Backup, recovery, DR drill | |
| Hardened server, VPN-only access, TPM-sealed vault factor | |

---

## 3. Build phases

Ordered so each phase stands on the one before. Sizes are relative, not calendar estimates, since this is in-house work fitted around your day.

| Phase | Focus | Depends on | Size |
|---|---|---|---|
| 0 | Confirm open points, provision hardened infrastructure | none | M |
| 1 | Schema plus the security spine (encryption, audit, auth) | 0 | L, the long pole |
| 2 | Backups operational, before real data | 1 | S to M |
| 3 | Inventory CRUD, relationships, states, custom fields, UI | 1 | M to L |
| 4 | Secrets: store, reveal, rotate, masking, recovery validated | 1, 3 | M |
| 5 | Read-only integrations (Graph, network gear) | 3 | M |
| 6 | Alert engine and dashboard | 3, 4, 5 | M |
| 7 | Release gate: full DR drill, security review, go-live | all | S to M |

### Phase 0, foundations
Confirm P-13, P-14, P-15 (section 6). Provision the server per Annex G: minimal OS, LUKS2 with TPM plus PIN, firewall, VPN path, and the separate host for anchoring, logs, and backups.

### Phase 1, the security spine
The Django project and the Annex C schema, then the parts where an in-house mistake hurts most: the encryption and vault unlock (Annex A, including Argon2id calibration, envelope encryption, per-admin wrapping, the TPM-sealed factor, and the printed recovery key), the audit log (Annex B, hash chain, append-only roles plus trigger, same-transaction writes, advisory-lock ordering, signed checkpoints), and operator auth (Annex D, two roles, WebAuthn or TOTP, single session, the handover flow and countdown cue). **Build a thin vertical slice first**: one entity, one secret, one logged change, one login, end to end, to prove the spine before fanning out.

### Phase 2, backups
Daily encrypted dumps with the public-key scheme, the three destinations including the offsite office, and a first restore dry run. Do this before any real data exists, so everything built after is protected.

### Phase 3, inventory
The full CRUD for people, accounts, devices, offices, the nine join tables, states, custom fields, and the responsive UI. Writes are audited, reads are logged.

### Phase 4, secrets
The reveal flow with per-action reauth, rotation, Viewer masking backed by the keyless Viewer session, and a validated recovery-key path. This is where the encryption from Phase 1 meets the UI.

### Phase 5, integrations
The Graph MFA pull and the network monitoring for WatchGuard, MikroTik, and UniFi, with telemetry kept off the audit chain.

### Phase 6, alerts and dashboard
The 13 rules, the dashboard grouping and acknowledge flow, and the integrity strip that lets the audit log watch itself. Needs real-ish data and the integrations from Phase 5 to be meaningful.

### Phase 7, release gate
The full disaster-recovery drill through the recovery-key path, a security pass over egress and roles, handover polish, then load real data and go live.

---

## 4. Definition of done for v1

- Every entity type can be recorded with its fields and related to others quickly.
- Secrets are stored encrypted. Only an Administrator reveals, with reauth. The Viewer is masked and keyless.
- Every change, reveal, and read lands in a chain that verifies, with checkpoints anchored off-box.
- Both administrators unlock with their own credentials. The recovery-key path has been tested.
- The dashboard shows the alerts, including the phone-reset unrecoverability case (E-1).
- Graph MFA status and network gear status are pulled read-only.
- Backups run, and a restore through the recovery-key path has passed.
- Access is VPN-only, the server is hardened, single session and handover work with the countdown.

---

## 5. Sequencing risks

- Phase 1 is the long pole and the riskiest. The two places to be most careful are the master key in memory (Annex A) and the audit chain ordering (Annex B). The thin vertical slice exists to flush those out early.
- Do not load real secrets until backups run and the recovery-key path is validated (Phase 2 plus Phase 4).
- Keeping integrations read-only in v1 removes the largest risk surface, writing to M365 or the gear. Hold that line.

---

## 6. Pre-build confirmations (the remaining open points)

These are field confirmations, not blockers, and most have sensible defaults already:

- **P-13:** alert thresholds, and whether laptops or tablets also trigger E-1 (default phones only).
- **P-14:** server has TPM 2.0, the separate host exists, the disk unlock mode (default TPM plus PIN).
- **P-15:** RPO target (daily, or daily plus WAL), the offsite office, the drill cadence (default quarterly).

Confirm these during Phase 0. Everything else is decided (D-01 through D-33).

---

## 7. Handing off to Cowork

Each phase becomes a milestone, each deliverable a task. The master index is the map, this annex is the order of work, and the lettered annexes are the detail for each task. The decision registry keeps the history, so when a choice resurfaces during the build you can see why it was made.

This annex resolves backlog item P-09. With it, the planning roadmap is complete.
