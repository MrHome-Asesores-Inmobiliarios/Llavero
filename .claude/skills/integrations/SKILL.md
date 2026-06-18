---
description: "Build Phase 5 read-only Graph and network monitoring"
disable-model-invocation: true
model: sonnet
effort: high
---

Implement Phase 5, tracker P5-T1..T6, per CLAUDE.md and Annex F. The integration table and scheduler. A Graph app registration, app-only with certificate auth, read-only scopes only (User.Read.All plus AuditLog.Read.All or UserAuthenticationMethod.Read.All); request NO write scopes. Daily MFA pull into account.mfa_state and mfa_types, matched by external_id. Network monitoring for WatchGuard (SNMPv3), MikroTik (RouterOS API over TLS or SNMP), and UniFi (controller API over HTTPS) every 5 minutes. Credentials stored as vault secrets.

Telemetry goes to a non-chained table; only meaningful transitions reach the audit chain. Stop at P5-T6 and prove there are no write scopes, egress is limited to Graph plus the gear, and telemetry stays off the chain.
