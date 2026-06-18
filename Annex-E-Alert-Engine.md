# Annex E: Alert Engine

**Companion to the preliminary design and to Annexes B, C, and D.** Defines the exact rules, conditions over the data model and the relationship graph, thresholds, severities, and lifecycle that turn the inventory into dashboard warnings. The phone-reset unrecoverability case is rule E-1.

---

## 1. What the engine does

It reads the Annex C tables and join tables, applies a set of rules, and produces a list of open alerts on the dashboard. It never changes inventory data and never acts on external systems. It only surfaces risk so a human acts.

---

## 2. Severity model

| Severity | Meaning | Color |
|---|---|---|
| critical | Data or access could be lost, or a real security exposure (compromised, unrecoverable, sensitive account with no recovery) | red |
| warning | Needs attention soon, no immediate loss (warranty near, password old, gear alerting) | amber |
| info | Worth knowing, low urgency (warranty far out, firmware mildly stale, long-running repair) | gray |

---

## 3. Evaluation model

- A scheduled evaluator runs every `eval_interval_minutes` (default 15) and on demand from the dashboard refresh button.
- The evaluator is a **system actor**. Its graph reads are machine reads, not human access, so they are not logged as `record_view`. This mirrors the monitoring-telemetry rule in Annex B. Only alert state changes (raised, acknowledged, resolved) are logged.
- Evaluation is idempotent. Each rule produces alerts keyed by `(rule_id, target)`, so re-running updates the existing alert rather than duplicating it.
- **Auto-resolve:** every alert resolves automatically when its condition no longer holds at the next evaluation. Two exceptions resolve only on rotation evidence, not by editing a field: `account_compromised` and the `needs_rotation` case clear only when `secret.last_rotated_at` is later than the flag.

---

## 4. Alert lifecycle and storage

Statuses: open, acknowledged, resolved. Acknowledging is an Administrator action (it is a change, so Viewer cannot), it carries a note, and it is logged. An acknowledged alert stays visible but moves out of the active count until it resolves or re-fires.

**Table `alert`:**

| Field | Type | Notes |
|---|---|---|
| id | uuid PK | |
| rule_id | text | for example `device_unrecoverable` |
| alert_key | text | `rule_id` plus target identity, for dedup |
| severity | text | critical, warning, info |
| status | text | open, acknowledged, resolved |
| target_table | text | primary entity table |
| target_id | uuid | primary entity |
| related | jsonb | other involved entities (the account, the recovery contact) |
| summary | text | rendered message |
| detail | jsonb | the specifics behind the alert |
| first_detected_at | timestamptz | |
| last_evaluated_at | timestamptz | |
| resolved_at | timestamptz | |
| acknowledged_by | uuid FK operator | |
| acknowledged_at | timestamptz | |
| ack_note | text | |

Unique partial index on `alert_key` where `status <> 'resolved'`, so there is one live alert per rule and target.

**Table `setting`** holds system parameters (thresholds below, the eval interval, the reauth window, the handover timers). Administrator-editable, each change logged as `parameter_change`. Key material parameters stay in `vault_key_holder` (Annex A), not here.

| Field | Type | Notes |
|---|---|---|
| key | text PK | |
| value | jsonb | |
| description | text | |
| updated_at | timestamptz | |
| updated_by | uuid FK operator | |

---

## 5. Configurable thresholds (defaults)

| Key | Default | Used by |
|---|---|---|
| warranty_info_days | 90 | E-8 |
| warranty_warning_days | 30 | E-8 |
| password_age_warning_days | 180 | E-7 |
| password_age_critical_days | 365 | E-7 |
| secret_age_warning_days | 365 | E-7 |
| network_offline_after_minutes | 15 | E-9 |
| firmware_stale_days | 180 | E-11 |
| repair_stale_days | 30 | E-12 |
| checkpoint_overdue_hours | 24 | E-13 |
| unrecoverable_device_types | ["phone"] | E-1 |

---

## 6. Rule catalog

Severity shown as fixed, or conditional where it depends on the target. Unless noted, an alert auto-resolves when the "fires when" condition stops being true.

| ID | Severity | Fires when | Suggested action |
|---|---|---|---|
| E-1 device_unrecoverable | critical | A device whose type is in `unrecoverable_device_types` is linked to an account (via `account_configured_on_device`, or an owned account of type google, samsung, or apple_id) and that account has no viable recovery: no active `account_recovery` into it, no `account_recovery_contact` or `device_recovery_contact` to an active person, and `recovery_email` and `recovery_phone` are both empty | Add a recovery account or an active recovery contact, or set a recovery email or phone, before the device is ever reset |
| E-2 recovery_path_dead | critical if sole path, else warning | An account's or device's recovery depends only on a person in offboarding or terminated state, or on an account in disabled or compromised state | Assign a new active recovery path |
| E-3 offboarding_cascade | warning, critical if secrets attached | A person in offboarding or terminated state still has active `account_ownership` or `device_assignment` | Reclaim devices, reassign accounts, rotate any shared secrets |
| E-4 account_no_mfa | critical for o365, network_admin, ms_personal, google, else warning | `account.mfa_state` is disabled or unknown | Enable MFA in the provider, then update the record |
| E-5 account_no_recovery | warning | An account has no recovery method at all: no `recovery_email`, no `recovery_phone`, no `account_recovery`, no `account_recovery_contact` | Add a recovery method |
| E-6 account_compromised | critical | `account.state` is compromised | Rotate the secret immediately. Clears only when `secret.last_rotated_at` is after the flag |
| E-7 credential_stale | warning, critical past the critical threshold | `account.last_password_change` older than `password_age_warning_days` (or `_critical_days`), or `account.state` is needs_rotation, or the account's `secret.last_rotated_at` older than `secret_age_warning_days` | Rotate the credential. The needs_rotation case clears only on rotation evidence |
| E-8 warranty_expiring | info within info window, warning within warning window or already expired | `device.warranty_expiry` within `warranty_info_days`, `warranty_warning_days`, or past | Plan renewal or replacement |
| E-9 network_device_down | critical if offline, warning if alerting | `network_device_detail.health_state` is offline or alerting, or `last_seen_at` older than `network_offline_after_minutes` | Investigate the device |
| E-10 dependency_cascade | critical | A device that is offline, broken, or pending_repair has incoming `device_dependency` edges (other devices depend on it) | Restore it first, it has the largest blast radius |
| E-11 firmware_stale | info, warning past twice the window | `network_device_detail.last_firmware_update` older than `firmware_stale_days` | Plan a firmware update |
| E-12 repair_stale | info | A device has been in pending_repair longer than `repair_stale_days` | Resolve the repair or decommission |
| E-13 audit_checkpoint_overdue | warning, critical if last verify failed | The latest `audit_checkpoint` is older than `checkpoint_overdue_hours`, or the last `chain_verify` found a problem | Create a signed checkpoint, or investigate the chain break |

E-1 and E-2 overlap by design: E-1 is the device-centric phone-reset case, E-2 is the broader "recovery exists but is dead" case. Both can fire on the same account from different angles, which is intentional, the dedup key keeps them as two distinct, clearly-labeled alerts.

---

## 7. Dashboard presentation

- Alerts grouped by severity, critical first, with a count badge per group.
- Each alert shows its summary, the primary entity (linked), and the suggested action. Expanding shows the related entities from `detail`.
- Filters by severity, rule, and entity type. A refresh button triggers an on-demand evaluation.
- Administrator can acknowledge with a note. Viewer sees everything but cannot acknowledge.
- A small integrity strip shows "chain verified through seq N, last checkpoint at T", fed by E-13 and Annex B.

---

## 8. Relationship to the audit log

Alert state changes (raised, acknowledged, resolved) are logged to the Annex B chain. The evaluator's reads are not. Rule E-13 is the bridge that makes the audit log monitor itself: if checkpoints stop or verification fails, an alert appears like any other.

---

## 9. Open points

1. **Unrecoverable device scope.** Default is phones only (`unrecoverable_device_types = ["phone"]`). Decide whether laptops and tablets that hold a personal account should also trigger E-1.
2. **Threshold defaults.** The values in section 5 are starting points. Confirm or tune, especially `password_age_*` and `network_offline_after_minutes`, which depends on the poll cadence set in Annex F.
3. **Extra rules.** The catalog is the v1 set. Easy to extend later, each new rule is a row plus a query.

This annex resolves backlog item P-05 and adds backlog item P-13 for the threshold and scope confirmation.
