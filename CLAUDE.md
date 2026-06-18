# Llavero - Project Context for Claude Code

## What this is
Secure Credentials & IT Asset System for an in-house IT team. v1 is RECORD, REPORT, QUERY ONLY. It never writes to an external system.

## Hard constraints (never violate)
- Fully in-house, zero cost. No third-party or cloud services. Only free, locally run libraries.
- Stack: Django + PostgreSQL + HTMX. Encryption via PyNaCl (libsodium) + argon2-cffi. WebAuthn via py_webauthn, TOTP via pyotp.
- Two roles: Administrator (read/write, can reveal secrets with reauth) and Viewer (read-only, secrets always masked, session never holds the master key).
- One active session at a time, system-wide.
- All integrations are READ-ONLY. Never request a write scope.
- Never invent cryptography. Use the vetted libraries and the annex schemes exactly.
- Never log secret plaintext or the master key. Never write the master key to disk or swap.

## Source of truth (in this repo)
- 00-Master-Index-and-Decision-Registry.md holds the locked decisions D-01..D-33.
- Preliminary-Design-Credentials-and-Asset-System.md holds the vision.
- Annex-A..I hold the detail each task implements (encryption, audit, data model, permissions, alerts, integrations, hardening, backup, phases).
- Build order, dependencies, gates, and definition of done: Annex-I and Llavero-v1-Build-Plan-Tracker.xlsx.
- Treat D-01..D-33 as settled. If a decision looks wrong, STOP and raise it. Do not redesign silently.
- (If you move the spec into a docs/ folder, update these paths.)

## How to work
- One tracker task at a time. State the task ID you are implementing and confirm its dependencies are Done.
- For each task: implement to the cited annex/section, write tests, run them, run migrations, and confirm the audit entry is produced where the task touches data.
- Security spine (Phase 1) before any later phase. Respect the dependency order in the tracker.
- After a task: summarize files changed and the task ID, and print `git diff --stat`, so the tracker can be updated in Cowork.

## Definition of done (every task)
- Matches the cited annex/section. Tests written and passing. Migrations clean.
- No secret/plaintext/master-key in logs. Permission checks server-side, not just UI masking.
- Lint/format clean (black, ruff).

## Hard gate
Do NOT load or use real secrets until BOTH the Phase 2 restore dry run (P2-T6) and the Phase 4 recovery-key path (P4-T6) pass. Use throwaway test data before then.

## Parallel-track note
App code can be built on a dev machine with throwaway data. Two Phase 1 tasks must be finalized on the real hardened server: P1-T5 (Argon2id calibration on the real CPU/RAM) and P1-T7 (TPM 2.0 sealing). Keep those open until the server from Phase 0 exists.

## Known fix
Rule E-1 reads the join table account_device_config (Annex C name). Annex E text says account_configured_on_device; that wording is wrong, use account_device_config.
```
