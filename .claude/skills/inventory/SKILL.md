---
description: "Build Phase 3 inventory, relationships, and UI"
disable-model-invocation: true
model: sonnet
effort: medium
---

Implement Phase 3, tracker P3-T1..T8, per CLAUDE.md and Annex C and D. CRUD plus HTMX UI for person, account, device, office, and network_device_detail. The nine join tables with their partial-unique constraints. State machines with no hard delete. Custom fields honoring viewer_visible. Fast relationship creation from any entity page.

Wire every write to the audit chain and add read logging at the defined granularity (record_view, list_view, search; never pagination). Enforce field-level permissions server-side. Tests per task. Stop at P3-T8 and verify audit coverage and that Viewer masking holds server-side. Throwaway data only.
