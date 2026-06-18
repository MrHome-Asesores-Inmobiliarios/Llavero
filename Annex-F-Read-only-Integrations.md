# Annex F: Read-only Integrations

**Companion to the preliminary design and to Annexes A, B, C, and E.** Defines what the system reads from external systems, with what least-privilege access, how often, and where the data lands. Everything here is read only. Nothing modifies an external system in v1.

---

## 1. Principles

- **Read only, least privilege.** Each integration uses a dedicated account or app with the narrowest read-only role the platform allows.
- **Credentials live in the vault.** Every integration secret (a certificate, an API token, an SNMP credential) is a `secret` row, encrypted per Annex A.
- **Telemetry is not chained.** Poll results update the live tables and a telemetry table. Only meaningful transitions reach the audit chain, per Annex B.
- **One outbound internet path.** The only integration that leaves your network is Microsoft Graph, reaching your own tenant. Everything else is on the LAN or across your existing tunnels. The app server is otherwise internal.
- **v1 scope:** Microsoft Graph (MFA reporting) plus monitoring of WatchGuard, MikroTik, and UniFi. Odoo and ZKBioTime stay deferred (D-13), sketched in section 5.

---

## 2. Integration storage and scheduling

**Table `integration`:**

| Field | Type | Notes |
|---|---|---|
| id | uuid PK | |
| type | text (enum) | graph, watchguard, mikrotik, unifi, odoo, zkbiotime |
| name | text | friendly label |
| endpoint | text | host or base URL, not a secret |
| enabled | boolean | |
| poll_interval_seconds | integer | |
| last_run_at | timestamptz | |
| last_status | text | ok, error, with a short message in `detail` |
| detail | jsonb | last error or summary |

Integration credentials are `secret` rows with `owner_type = integration`, `owner_id = integration.id`.

A scheduler runs each enabled integration on its interval, writes telemetry, updates the live tables, and records `last_run_at` and `last_status`.

---

## 3. Microsoft 365 and Entra (Graph), the MFA report

### Access
- A dedicated **app registration** in Entra, app-only (client credentials).
- **Certificate auth preferred** over a client secret. The certificate private key is stored as a `secret` in the vault. A client secret also works but expires and is weaker.
- **Read-only application permissions, admin-consented once.** The relevant scopes (confirm the exact names in the Entra admin center when you implement, Graph naming is version-sensitive):
  - `User.Read.All` to list users.
  - `AuditLog.Read.All` for the registration report below, or `UserAuthenticationMethod.Read.All` for the per-user method endpoint.
- No write scopes are requested at all, so even a compromised token cannot change MFA.

### What is read
- Primary: the registration report `GET /reports/authenticationMethods/userRegistrationDetails`, which returns per user whether MFA is registered and capable, and which methods are registered. This directly answers "who has MFA and what types."
- Drill-down (optional): `GET /users/{id}/authentication/methods` for the exact methods on one user.

### Mapping
- Match a Graph user to an `account` by `account.external_source = 'graph'` and `account.external_id` = the Entra object id, with the UPN in `identifier`.
- The pull updates `account.mfa_state` (enabled, disabled) and `account.mfa_types`. Unmatched Graph users can be surfaced for the admin to link.

### Cadence
- Daily. MFA registration changes slowly, so a once-a-day pull is plenty and keeps the report API well within limits.

---

## 4. Network gear

All three feed `network_device_detail` (firmware_version, health_state, last_seen_at) plus a telemetry table. Default cadence every 5 minutes, so the E-9 offline threshold of 15 minutes equals three missed polls. Exact OIDs, endpoints, and roles are confirmed against each device's firmware at implementation time.

| Vendor | Read-only access | What is read |
|---|---|---|
| WatchGuard Firebox | SNMPv3 read-only (preferred over plaintext v2c community). A read-only API on supported Fireware versions is an alternative | Reachability, firmware or Fireware version, interface and tunnel status, basic health |
| MikroTik (tunnels) | A RouterOS user in a read-only group, over the API on TLS (api-ssl) or the v7 REST API on HTTPS, or SNMP | RouterOS version, interface and IPsec or tunnel status, uptime, link state |
| UniFi WiFi | A controller account with the read-only Viewer role, over the controller API on HTTPS | Access point and switch status, adoption state, firmware versions, client counts |

Credentials for each (SNMPv3 user, RouterOS read-only password, UniFi Viewer password) are `secret` rows. Prefer encrypted or authenticated transports everywhere: SNMPv3 not v1 or v2c, TLS for the RouterOS API, HTTPS for UniFi.

---

## 5. Deferred integrations (later phase, read only)

- **Odoo:** a read-only Odoo user over XML-RPC or JSON-RPC to read employee records and link them to `person`. Deferred.
- **ZKBioTime / BioTimePro:** the product REST API (or a read-only export) to cross employee active state with attendance. Deferred.

Both are documented here so the design is not lost, but neither is built in v1.

---

## 6. Polling, telemetry, and failures

- Network polls write raw readings to a telemetry table and update `network_device_detail`. Only state transitions (reachable to offline, a firmware change) enter the audit chain, per Annex B.
- A failed poll sets `integration.last_status = error`. Repeated failures against a device surface through alert E-9 (the device looks offline). A failing Graph pull surfaces as a low-severity integration health note on the dashboard.
- The Graph pull is idempotent: it updates matched accounts and never deletes.

---

## 7. Security and network egress

- Every integration account is read-only on its own platform. This is the real boundary, not just the app's intent.
- Outbound egress from the app server is restricted by the firewall to exactly what is needed: HTTPS to Microsoft Graph endpoints, and LAN or tunnel reach to the gear. Nothing else.
- Transports: certificate auth for Graph, SNMPv3, TLS for RouterOS, HTTPS for UniFi. Avoid plaintext SNMP communities.
- Integration secrets are revealed to the running poller from the vault the same way any secret is used, and they are never written to logs.

---

## 8. Field mapping summary

| Source | Target | Field |
|---|---|---|
| Graph userRegistrationDetails | account | mfa_state, mfa_types |
| Graph user object id | account | external_id (match key) |
| WatchGuard, MikroTik, UniFi poll | network_device_detail | firmware_version, health_state, last_seen_at |
| Any poll | telemetry table | raw readings, not chained |

---

## 9. Open points

1. **Poll cadence.** Network gear every 5 minutes and Graph daily are defaults. Confirm. The network cadence sets the E-9 offline threshold, so this also closes part of P-13.
2. **Graph auth and exact permissions.** Certificate vs client secret, and confirming the exact read-only scope names in the Entra portal at build time.
3. **Per-device access method.** SNMPv3 vs vendor API for WatchGuard, API vs REST vs SNMP for MikroTik, and confirming the UniFi API for your controller version.

This annex resolves backlog item P-06.
