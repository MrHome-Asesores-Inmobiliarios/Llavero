# Preliminary Design: Secure Credentials and IT Asset System

**Company:** Real estate firm (Santo Domingo)
**Author:** IT Administration
**Status:** Concept draft v2 (decisions resolved, ready to plan with Cowork)
**Date:** June 2026

> **Changes from v1:** Three constraints are now fixed. Zero cost, fully in-house, no third-party services. The v1 scope is limited to recording, reporting, and querying. No advanced operations (no MFA restore, no remote configuration changes). All previously pending decisions are resolved on this basis (section 10).

---

## 1. Recommendation (this first)

A single in-house application, self-hosted, with no paid dependencies and no external services. The v1 scope is read and record only: store, query, and report. Nothing that modifies an external system.

Because you are no longer building a full password manager (no autofill, no browser extension, no 2FA restore), the app gets much simpler. Each secret is stored as an encrypted field inside your own database, not in an external vault.

The one rule that does not bend: do not invent your own cryptography. Use a proven, audited library (libsodium via PyNaCl, or the `cryptography` package). These libraries are free and run locally, so they are not a third-party service. The danger is never storing secrets in-house, it is inventing the cipher or the mode.

The approach in brief:
- One app (Django plus PostgreSQL) that holds inventory, relationships, states, the audit log, the dashboard, and the encrypted secret field.
- Zero external services. The only outbound calls go to your own systems (your Microsoft 365 tenant, your network gear), always read only and only to report.
- Zero cost. The whole stack is free software.

---

## 2. Strategic decision: resolved

**Decision: 100% in-house, a single application.** The hybrid model with an external vault from the earlier draft is dropped.

Why building everything is the right call now:

| Factor | Effect |
|---|---|
| Scope reduced to record, report, query | The hard part of a password manager disappears. What remains is an inventory with an encrypted field |
| Zero cost, no third parties | An external vault, even if free and local, is one more moving part to maintain. One app is simpler |
| 1 to 2 users | No need for complex secret sharing or advanced multi-user features |
| Encryption via a proven library | Security without inventing anything. This is standard practice |

The risk flagged in v1 (inventing cryptography) is avoided by using vetted libraries. With that, the in-house path is safe and appropriate for your case.

---

## 3. Data model (entities)

Five core entities. All carry `state`, `notes`, `created_at`, `updated_at`, `created_by`, `updated_by`.

### 3.1 Person / User
An employee of the organization.
- Full name, internal ID, role, department
- Contact information (personal email, phone, extension)
- Assigned office
- State: active, suspended, offboarding, terminated
- Hire date, exit date

### 3.2 Account / Service
Any credential. This is what links to the encrypted secret store.
- Type: Office 365, personal Microsoft account, Google account, Samsung/Galaxy account, Apple ID, Odoo login, network device admin, external service, other
- Identifier or username
- **Encrypted secret** (encrypted field in the same database, see section 6)
- Known MFA state (has MFA, no MFA, unknown) and MFA types (informational field, filled by hand or by a read-only query to M365)
- Recovery information (recovery email or phone, backup codes stored as an encrypted secret)
- Owner (person) and devices where it is configured
- State: active, disabled, compromised, needs rotation
- Date of last password change

### 3.3 Device
An organization asset (laptop, phone, server, or network gear).
- Type, brand, model, serial number
- Specs: CPU, RAM, storage
- MAC and IP addresses, hostname
- Purchase date, warranty expiry, vendor
- Assigned user, office/location
- State: in use, in storage, pending repair, broken, decommissioned
- For network gear: firmware version, last update, monitoring endpoint

### 3.4 Office / Location
- Name, address
- Associated infrastructure (firewall, switches, APs, links)
- Network data: subnets, VLANs, IP ranges, ISP
- Responsible person
- State: active, in setup, closed

### 3.5 Network / infrastructure device
A subtype of Device with monitoring. Covers WatchGuard Firebox, MikroTik, UniFi.
- Role: firewall, tunnel router, switch, access point, controller
- Firmware version and last update date
- Health state (reachable, alerting, offline)
- Query method (read-only API or SNMP)

---

## 4. Relationship model (the heart of the system)

Relationships are **many to many and typed**. The type matters because the alert engine walks the graph looking for risk.

Main relationships:
- Person **uses / owns** Account
- Person **is assigned** Device
- Account **is configured on** Device (example: the personal Microsoft account used to set up the work laptop)
- Account **is recovery for** Account (recovery chains, critical)
- Person **is recovery contact for** Account or Device
- Device **is located in** Office
- Person **works at** Office
- Device **depends on** Device (example: an AP depends on a switch and the firewall)

Creating a relationship must be fast: find the entity, pick the relationship type, save. Ideally from the page of any entity without leaving it.

---

## 5. Alert and risk engine (dashboard)

The dashboard walks the relationship graph and surfaces actionable risks. Everything is read and report, it never acts on its own. Examples:

- **Unrecoverability risk:** a phone whose primary account (Google or Samsung) has no recovery contact, or whose recovery contact is a person already terminated. This catches your case of the phone that gets reset with no useful recovery account.
- **Offboarding cascade:** a person moves to offboarding state but still has active accounts or assigned devices. Generates a reclaim and handover list.
- **Orphaned recovery:** an account with no recovery method or marked as no MFA.
- **Warranty expiring:** devices with warranty at 30, 60, or 90 days.
- **Outdated or down network gear:** old firmware on WatchGuard, MikroTik, or UniFi, or a device not answering the monitoring query.
- **Credential hygiene:** password not rotated in X days, account marked compromised.

Each alert links to the affected entity and describes the risk. You take the action by hand in the relevant system.

---

## 6. Security architecture

### Hosting
- Local server (VM or physical) with a hardened OS and full disk encryption.
- The app listens only on the internal interface. Never exposed directly to the internet.

### Remote access
- From outside, VPN only. You already have WatchGuard and MikroTik for this at no extra cost. A VPN layer before the login is even reachable.

### Authentication (all zero cost)
- Layer 1: VPN.
- Layer 2: app login with a strong password plus a second factor. Free options, in order of preference:
  1. **WebAuthn with a platform authenticator** (Windows Hello, fingerprint, or device PIN). Phishing resistant and no hardware to buy.
  2. **TOTP** with any free authenticator app. Works on any device.
- Hardware keys (YubiKey type) are stronger but **optional and for later**, since they cost money. Not required for v1.
- The app login **does not depend on Office 365 or Entra**. This system might be needed exactly when M365 is down. Local authentication first.

### Session and permissions
- One active session at a time. A new login closes the previous one or is blocked.
- Two roles for 1 or 2 people:
  - **Administrator:** reads and writes everything. Can reveal a secret, with reauthentication and logging.
  - **Viewer:** read and report only. Cannot reveal secrets (sees them masked).

### Secret encryption (in-house, no third parties)
- The secret lives as an encrypted field in the same PostgreSQL database.
- Authenticated encryption with a proven library (libsodium via PyNaCl, or `cryptography` with AES-256-GCM). Never a homemade cipher.
- Master key derivation with Argon2id from an administrator passphrase, combined with the second factor.
- Envelope encryption: each secret is encrypted with a data key, and the data key is encrypted with the master key.
- The master key is **never** stored in plaintext on disk. It is unlocked in memory at login.
- Revealing a secret requires reauthentication and is recorded in the audit log.

### Tamper-evident audit log
- Append-only.
- Each entry chained by hash: every record includes the hash of the previous one, so any alteration breaks the chain and is detected.
- Each entry records: who, when, which entity, before and after values, source IP, session ID.
- Ideally the log is also written to a local write-only target.

### Backups (in-house, no cost)
- `pg_dump` of the database, encrypted with a free tool (for example `age` or `gpg`), copied to a second disk or storage you already own, with one offsite copy.
- Restore tested on a schedule.
- Critical: this system is a single point of access to the whole organization. If it is lost without a backup, a lot is lost.

---

## 7. Integrations (all read only in v1)

No integration modifies the external systems. They only read, to report. Querying your own M365 tenant or your own gear is not a third-party service, it is reading your own data, and it has no cost.

| System | What for (read only) | Method |
|---|---|---|
| Microsoft 365 / Entra | List users and check who has MFA and which type, for reporting. Changes nothing | Microsoft Graph, app registration with read-only permissions (for example read users and authentication methods) |
| WatchGuard Firebox | State, firmware version, alerts | SNMP or read-only API |
| MikroTik (tunnels) | Link state, firmware | RouterOS read-only API or SNMP |
| UniFi WiFi | AP state, clients, firmware | Controller API, read only |
| Odoo | Link an employee to their record (optional, deferrable) | Odoo read-only API |
| ZKBioTime / BioTimePro | Cross employee state with attendance (optional, deferrable) | API or export, read only |

Note on M365: reading MFA methods via Graph requires granting a read-only permission to the app registration in Entra. It is free and cannot change anything. If later you want to modify MFA, that would be a separate phase and a separate permission, outside the v1 scope.

---

## 8. Technology stack (all free software, zero cost)

- **Backend:** Django plus PostgreSQL. Fast admin, ORM, RBAC, change history, and WebAuthn through mature, free packages.
- **Frontend:** server rendered with HTMX. Simple, secure, responsive, with no paid dependencies.
- **Secrets:** field encryption with PyNaCl (libsodium) or the `cryptography` package. KDF Argon2id.
- **Second factor:** `py_webauthn` for platform WebAuthn, `pyotp` for TOTP.
- **Network monitoring:** `pysnmp` or `easysnmp` for SNMP, plus each vendor's read-only API.
- **M365 query:** Microsoft Graph calls with `msal` and `requests`, read only.

All of the above is free and runs inside your network.

---

## 9. Requirements mapping

| Requirement you asked for | How the design covers it |
|---|---|
| Record an O365 user with address, password, contact | Account entity of type O365, secret encrypted in the same database, data in Person |
| Record a device with brand, serial, RAM, warranty | Device entity with specs and warranty |
| Offices with infrastructure | Office entity with network and infrastructure data |
| Everything relatable | Typed relationship model (section 4) |
| Remote access with extreme authentication | VPN plus WebAuthn or TOTP, local login independent of M365 |
| Easy inventory entry with many parameters | Custom fields and per-entity forms |
| Fast relationships | Relationship creation from each entity's page |
| Every action logged with a fingerprint | Append-only hash-chained audit log |
| One session, granular access | Single session plus Administrator and Viewer roles |
| Local hosting, VPN access | Internal server, no internet exposure |
| Clear per-entity states | State field on every entity |
| Connect to network gear for monitoring | Read-only queries via API and SNMP (section 7) |
| Query O365 user MFA | Read-only Microsoft Graph, for reporting |
| Dashboard of alerts and risks | Alert engine that walks the graph (section 5) |
| Responsive | Responsive frontend with HTMX |
| Zero cost, all in-house, no third parties | 100% free-software stack, a single local app (section 8) |

---

## 10. Resolved decisions

1. **Single custom app or existing pieces.** Resolved: single in-house app. The reduced scope and zero cost make it the right path.
2. **Where to store secrets.** Resolved: encrypted field in the same PostgreSQL database, with a proven encryption library (libsodium or `cryptography`), Argon2id KDF, envelope encryption. No external vault.
3. **How many people and what permissions.** Resolved: two roles, Administrator (read and write, can reveal secrets with reauthentication) and Viewer (read only, secrets masked). One active session.
4. **Sync with Entra, Odoo, ZKBioTime.** Resolved: all read only and for reporting. M365 via Graph to list users and check MFA. Odoo and ZKBioTime are optional and deferred to a later phase.
5. **Second factor.** Resolved: platform WebAuthn (Windows Hello or fingerprint, no cost) as the first option, TOTP as the alternative. Hardware keys optional and future because of cost.
6. **Backup.** Resolved: encrypted `pg_dump`, a copy on your own storage and one offsite, with a tested restore. No cost.

---

## 11. Next steps

1. Define the final catalog of entity types, fields, and relationship types.
2. Design the exact field-encryption scheme and the in-memory handling of the master key.
3. Design the hash-chained audit log scheme.
4. Define the read-only app registration in Entra for the MFA query.
5. Bring this document to Cowork to turn the decisions into a project plan with phases and tasks.
