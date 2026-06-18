# Llavero v1 - One-Page Plan Summary

**System:** Secure Credentials & IT Asset System for the firm (Santo Domingo).
**What v1 is:** a single-server app that records people, accounts, devices, and offices, relates them, stores secrets encrypted, logs every action verifiably, reads MFA and network status, and surfaces risk on a dashboard. **Record, report, and query only. It never writes to an external system.**

## Fixed constraints
Fully in-house, zero cost, no third-party or cloud services. Stack is Django + PostgreSQL + HTMX. Two Administrators and one Viewer role, one active session at a time. Decisions D-01 through D-33 are locked (see the tracker's Decisions sheet). Source of truth is `00-Master-Index-and-Decision-Registry.md`; detail lives in Annexes A-I.

## The build order (security spine first, then fan out)
The spine is built and proven through a thin vertical slice (one entity, one secret, one logged change, one login) before any feature work spreads out.

1. **Phase 0 - Foundations.** Confirm P-13/14/15; provision the hardened server (minimal OS, LUKS2 with TPM + PIN, default-deny firewall, VPN-only access, restricted egress) and the separate anchoring/log/backup host.
2. **Phase 1 - Schema + security spine (the long pole).** Annex C schema, then encryption (Annex A), the hash-chained audit log (Annex B), and operator auth (Annex D). Prove it with the thin slice.
3. **Phase 2 - Backups, before any real data.** Daily encrypted dumps, three copies including offsite, first restore dry run.
4. **Phase 3 - Inventory.** CRUD, the nine typed join tables, states, custom fields, responsive UI. Writes audited, reads logged.
5. **Phase 4 - Secrets.** Reveal with reauth, rotation, keyless Viewer masking, validated recovery-key path.
6. **Phase 5 - Integrations (read-only).** Graph MFA pull and network monitoring, telemetry kept off the audit chain.
7. **Phase 6 - Alerts + dashboard.** The 13 rules including the E-1 phone-reset case, acknowledge flow, integrity strip.
8. **Phase 7 - Release gate.** Full DR drill through the recovery-key path, security pass, then load real data and go live.

## The hard rule
**Do not load real secrets until backups run (P2-T6 restore dry run) and the recovery-key restore has passed (P4-T6).** Final release (P7-T5) happens only after the full DR drill. This is risk R-4 and it gates Phases 2, 4, and 7.

## Risk register (short)
| ID | Risk | Severity | Mitigation |
|---|---|---|---|
| R-1 | Phase 1 is the long pole and riskiest | High | Thin vertical slice first; do not fan out until it passes |
| R-2 | Master key exposed by a memory dump mid-session | High | mlock + memzero, idle auto-lock, swap off, no core dumps |
| R-3 | Audit chain ordering breaks under concurrent writes | High | Advisory-lock serialization, same-transaction insert, gap-free seq |
| R-4 | Real secrets loaded before recovery is proven | Critical | Hard gate: no real secrets until P2-T6 and P4-T6 pass |
| R-5 | Integration scope creep to writing M365 or gear | High | Read-only scopes only, egress firewalled, hold the line |
| R-6 | Lockout: the printed recovery key is the single linchpin | Critical | Recovery key in the safe, tested pre-go-live + quarterly; keys never with backups |
| R-7 | Malicious-admin tampering (a chain alone is detection-only) | Medium-High | Signed off-box checkpoints via WebAuthn + printed copies |
| R-8 | TPM hardware binding could block unlock on server failure | Medium | Recovery-key path to new hardware + re-seal; keyfile fallback |

## Open confirmations status
- **P-13 (confirmed):** E-1 unrecoverability fires on phones, tablets, and laptops. Other alert thresholds keep the Annex E defaults, tunable in the setting table.
- **P-14 (mostly confirmed):** TPM 2.0 present, so TPM sealing is the vault second factor and disk unlock is TPM + PIN. The separate anchoring/log/backup host is confirmed or provisioned in Phase 0 (P0-T9).
- **P-15 (mostly confirmed):** RPO is daily dumps (no WAL in v1); drill cadence quarterly. **Still to specify: which office is the offsite replication target.**
- **To confirm in Phase 0:** the windowed reauth length (2-minute default, Annex D).

## One conflict flagged (not a redesign)
Rule E-1 (Annex E) names a join table `account_configured_on_device`, but Annex C section 5 defines it as `account_device_config`. Annex C is authoritative; build to `account_device_config` and correct the Annex E wording.

*Day-to-day work item list with statuses, dependencies, and annex citations: `Llavero-v1-Build-Plan-Tracker.xlsx`.*
