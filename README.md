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
  audit/          hash-chain audit log, signed checkpoints
  backup/         GFS retention, restore verification, recovery drill
  vault/          envelope encryption, master key lifecycle, recovery key, secrets UI
  operators/      authentication, WebAuthn/TOTP, session management
  inventory/      CRUD for persons, accounts, devices, offices, custom fields
  relationships/  nine typed join tables between entities
  integrations/   Graph MFA pull, WatchGuard/MikroTik/UniFi monitoring, telemetry
  alerts/         13-rule alert engine, dashboard, self-monitoring (E-13)
deploy/
  backup/         backup.sh, restore.sh, systemd timer, RESTORE-DRILL.md
  RELEASE-CHECKLIST.md
static/js/        htmx.min.js (vendored)
templates/        base layout + per-app templates
tests/            442-test pytest suite covering all phases
```

Spec documents live at the repo root: `Annex-A` through `Annex-I`, `00-Master-Index-and-Decision-Registry.md`, and `Preliminary-Design-Credentials-and-Asset-System.md`. Decisions D-01..D-33 in the master index are locked — raise before redesigning.

## Build status

| Phase | Code | Tests |
|---|---|---|
| 0 — Infrastructure | Ops — hardened server, LUKS2, VPN, separate host | — |
| 1 — Security spine | ✅ Done | 209 |
| 2 — Backups | ✅ Automated done · Manual drill pending | 244 |
| 3 — Inventory UI | ✅ Done | 290 |
| 4 — Secrets UI + recovery gate | ✅ Done | 321 |
| 5 — Integrations | ✅ Done | 334 |
| 6 — Alerts & dashboard | ✅ Done | 368 |
| 7 — Release gate (code) | ✅ Done | 442 |

**Remaining before go-live** (all operator tasks on the hardened server):
Argon2id calibration · TPM sealing · manual P2-T6 restore drill · full DR drill (P7-T1) · load real data (P7-T5).
See `deploy/RELEASE-CHECKLIST.md` for the sign-off checklist.
