---
description: "Build Phase 6 alert engine and dashboard"
disable-model-invocation: true
model: sonnet
effort: high
---

Implement Phase 6, tracker P6-T1..T8, per CLAUDE.md and Annex E. The alert and setting tables, an idempotent evaluator keyed by (rule_id, target) running every 15 minutes and on demand, as a system actor whose reads are not logged. All 13 rules E-1..E-13 over the relationship graph. E-1 unrecoverable_device_types = [phone, tablet, laptop] per P-13, reading account_device_config (the Annex C name; ignore Annex E's account_configured_on_device wording). Auto-resolve with the rotation-evidence exceptions.

Dashboard with severity grouping, Admin acknowledge with note, filters, links, and the integrity strip fed by E-13. Thresholds in the setting table, Admin-editable, each change logged. Stop at P6-T8 and run rule-firing tests including E-1 on seeded data.
