# Llavero MrHome

Secure credentials and IT asset system for an in-house IT team.
**Record, report, and query only — it never writes to an external system.**

## What it does

- Records people, accounts, devices, offices, and the typed relationships between them.
- Stores secrets (passwords, API keys, certificates) encrypted per-record with envelope encryption. Only an Administrator can reveal a secret, after re-authentication. Viewers are masked and cryptographically keyless.
- Logs every action in a BLAKE2b hash chain with signed off-box checkpoints — tamper-evident and verifiable.
- Pulls MFA status from Microsoft 365 (read-only) and monitors network gear (WatchGuard, MikroTik, UniFi).
- Surfaces risk on a dashboard via 13 alert rules (e.g. unrecoverable device, weak MFA, stale account).
- Runs encrypted daily backups to three destinations with a tested recovery-key restore path.

## Stack

| Layer | Choice |
|---|---|
| Web | Django 5 + HTMX |
| Database | PostgreSQL 18 (scram-sha-256, localhost) |
| Encryption | PyNaCl (XChaCha20-Poly1305, BLAKE2b, Ed25519) + argon2-cffi |
| Second factor | py_webauthn + pyotp |
| Backup encryption | age (asymmetric, public key on server, private key offline) |

Fully in-house. Zero cloud services. Zero cost.

## Roles

| Role | Can do |
|---|---|
| **Administrator** | Read + write + reveal secrets (with step-up reauth) |
| **Viewer** | Read only. Secrets always masked. Session never holds the master key — cryptographically, not just by policy. |

One active session at a time, system-wide.

## Hard gate

**Do not load real secrets until both of these pass:**

1. **P2-T6** — restore dry run: DB loads from an encrypted dump, audit chain verifies against the off-box checkpoint, a secret decrypts via the printed recovery code alone (no passphrase, no TPM). Automated proof: `pytest tests/test_restore_dry_run.py`. Manual isolated-host drill: `deploy/backup/RESTORE-DRILL.md`.
2. **P4-T6** — recovery-key reveal path validated end to end in the UI.

## Development setup

```bash
# Python 3.12+, PostgreSQL 18 required
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements/dev.txt

cp .env.example .env                # fill in DB credentials
python manage.py migrate
python manage.py test               # or: pytest
```

Pre-commit hooks (black + ruff):

```bash
pre-commit install
```

## Repository layout

```
apps/
  audit/        hash-chain audit log, signed checkpoints
  backup/       GFS retention, restore verification, recovery drill
  vault/        envelope encryption, master key lifecycle, recovery key
  operators/    authentication, WebAuthn/TOTP, session management
deploy/
  backup/       backup.sh, restore.sh, systemd timer, RESTORE-DRILL.md
  hardening/    nginx, systemd unit, firewall notes
tests/          pytest suite (244 tests, Phase 1 + Phase 2)
```

Spec documents live at the repo root: `Annex-A` through `Annex-I`, `00-Master-Index-and-Decision-Registry.md`, and `Preliminary-Design-Credentials-and-Asset-System.md`. Decisions D-01..D-33 in the master index are locked — raise before redesigning.

## Build status

| Phase | Status |
|---|---|
| 0 — Infrastructure | Ops (hardened server, LUKS2, VPN) |
| 1 — Security spine | ✅ Done (209 tests) |
| 2 — Backups | ✅ Automated done (244 tests) · Manual drill pending |
| 3 — Inventory UI | Not started |
| 4 — Secrets UI + gate | Not started |
| 5 — Integrations | Not started |
| 6 — Alerts & dashboard | Not started |
| 7 — Release gate | Not started |
