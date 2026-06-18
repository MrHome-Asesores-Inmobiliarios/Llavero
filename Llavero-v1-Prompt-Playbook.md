# Llavero v1 - Prompt Playbook (Cowork + Claude Code)

A working reference of the exact prompts to use, where each runs, and which model and effort level to set. Copy the blocks as-is and fill the angle-bracket placeholders. Pair this with `Llavero-v1-Build-Plan-Tracker.xlsx` (task IDs) and the annexes (the detail each task implements).

---

## 1. The two-layer model

Two tools, two jobs. Keep them in their lanes and the build stays cheap and clean.

- **Cowork layer (Opus 4.8): think, plan, track, review, document.** Design validation before each phase, security review of diffs at each gate, tracker and decision-registry updates, runbooks, test strategy. This is where your 2X month is well spent.
- **Code layer (Claude Code): build, test, debug.** The actual Django repo, migrations, tests, git. Model and effort are dialed per phase.

The repo never needs to leave Claude Code. The plan, the tracker, and the reviews never need to leave Cowork. The handoff between them is a short pasted brief (Cowork to Code) and a short pasted diff or summary (Code to Cowork).

---

## 2. Model + effort cheat sheet

**Models.** Opus 4.8 for deep reasoning and anything security-critical. Sonnet 4.6 for fast, high-volume coding (CRUD, UI, plumbing). Haiku 4.5 only for throwaway trivial tasks.

**Effort levels** (verified against the Claude docs):

| Level | What it does | Use it for |
|---|---|---|
| `low` | Most token-efficient, least depth | Trivial tasks, status rollups, simple edits |
| `medium` | Balanced speed and cost | Routine agentic coding, CRUD, UI, plumbing |
| `high` | Default. Strong reasoning | Difficult coding, nuanced analysis |
| `xhigh` | "Extra." Extended depth for long coding/agentic runs | The recommended start for serious coding on Opus 4.8 |
| `max` | Ceiling, no token constraint | Frontier reasoning, crypto/audit design, security reviews |

**How to set it.**
- **Claude Code:** set the model with `/model` (opus or sonnet) and the effort with `/effort low|medium|high|xhigh|max`. Default is `high`. The old `ultrathink` keyword was deprecated in Jan 2026; use `/effort`. ("ultracode" in the menu is just `xhigh` plus permission for multi-agent runs.)
- **Cowork:** pick Opus 4.8. If your build shows an effort or thinking control, set it to the matrix level. If it does not, Opus runs at `high` by default, so for the `max`-effort security reviews add a line like "this is security-critical, reason carefully and exhaustively" to push depth.

Rule of thumb: **raise effort, do not prompt around shallow output.** If Opus looks shallow on a hard problem, bump `/effort` rather than re-explaining.

---

## 3. Session to model and effort matrix

| Session | Tool | Model | Effort | Why |
|---|---|---|---|---|
| Phase design validation (CW-1) | Cowork | Opus 4.8 | `max` for Phase 1, `xhigh` otherwise | Security-critical reasoning before any code |
| Security / diff review (CW-2) | Cowork | Opus 4.8 | `max` | Catch subtle leaks at the gate |
| Tracker + registry update (CW-3) | Cowork | Opus 4.8 | `low` | Mechanical bookkeeping |
| Runbook / docs (CW-4) | Cowork | Opus 4.8 | `high` | Clear writing, moderate reasoning |
| Test strategy / threat model (CW-5) | Cowork | Opus 4.8 | `xhigh` | Substantial structured reasoning |
| Weekly status (CW-6) | Cowork | Opus 4.8 | `low` | Quick rollup |
| Phase 0 infra (CD-0) | Code | Sonnet 4.6 | `medium` | Config and ops, high volume |
| Phase 1 security spine (CD-1) | Code | Opus 4.8 | `xhigh`, `max` on crypto/audit tasks | The long pole, mistakes hurt most |
| Phase 2 backups (CD-2) | Code | Sonnet 4.6 | `high`, Opus `xhigh` for the gate P2-T6 | Ops scripting; the recovery proof matters |
| Phase 3 inventory (CD-3) | Code | Sonnet 4.6 | `medium` | Mechanical CRUD and UI |
| Phase 4 secrets (CD-4) | Code | Opus 4.8 | `xhigh`, `max` on the recovery gate P4-T6 | Crypto meets the UI |
| Phase 5 integrations (CD-5) | Code | Sonnet 4.6 | `high` | Read-only plumbing, scope correctness matters |
| Phase 6 alerts + dashboard (CD-6) | Code | Sonnet 4.6 | `high` on the 13 rules, `medium` on UI | Rule logic plus presentation |
| Phase 7 release gate (CD-7) | Code | Opus 4.8 | `max` | Highest stakes: DR drill + security pass |
| Routine bug / test fail (FIX-1, FIX-4) | Code | Sonnet 4.6 | `medium` | Everyday fixes |
| Stubborn or subtle bug (FIX-2) | Code | Opus 4.8 | `xhigh` | Structured debugging |
| Security bug (FIX-3) | Code | Opus 4.8 | `max` | Treat as critical |
| Apply review feedback (FIX-5) | Code | Sonnet 4.6 | `high` | Turn findings into fixes |
| Migration issue (FIX-6) | Code | Sonnet 4.6 | `high`, Opus if data-integrity risk | Schema safety |

---

## 4. Standing setup (do once)

### 4.1 CLAUDE.md (paste into the repo root)

This file gives every Code session the project's rules automatically, so the per-session prompts stay short.

```markdown
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

## Source of truth
- Spec in /docs: 00-Master-Index (D-01..D-33 locked decisions), Preliminary Design, Annex A-I.
- Build order and definition of done: Annex I and Llavero-v1-Build-Plan-Tracker.xlsx.
- Treat D-01..D-33 as settled. If a decision looks wrong, STOP and raise it. Do not redesign silently.

## How to work
- One tracker task at a time. State the task ID you are implementing and confirm its dependencies are Done.
- For each task: implement to the cited annex/section, write tests, run them, run migrations, and confirm the audit entry is produced where the task touches data.
- Security spine (Phase 1) before any later phase. Respect the dependency order.
- After a task: summarize files changed and the task ID, and print `git diff --stat`, so the tracker can be updated in Cowork.

## Definition of done (every task)
- Matches the cited annex/section. Tests written and passing. Migrations clean.
- No secret/plaintext/master-key in logs. Permission checks server-side, not just UI masking.
- Lint/format clean (black, ruff).

## Hard gate
Do NOT load or use real secrets until BOTH the Phase 2 restore dry run (P2-T6) and the Phase 4 recovery-key path (P4-T6) pass. Use throwaway test data before then.

## Known fix
Rule E-1 reads the join table account_device_config (Annex C name). Annex E text says account_configured_on_device; that wording is wrong, use account_device_config.
```

### 4.2 First Code session (CD-0)

> **Tool: Claude Code · Model: Sonnet 4.6 · Effort: `/effort medium`**

```
Read CLAUDE.md and /docs first. Implement tracker task P1-T1: scaffold the Llavero Django + PostgreSQL project. Bind the app to localhost, set scram-sha-256 for the DB, add a reverse proxy with an internal-CA TLS cert, and a hardened systemd unit (Annex G 5, Preliminary Design 8). Set up settings split, pinned dependencies, pre-commit with black and ruff, and a test runner. Do not add feature models yet. Confirm the dev server starts and an empty test suite runs, then stop.
```

(Phase 0 infrastructure tasks P0-T5..T10 are server/OS work done at the shell per Annex G, not app code. Use CD-0 only once the OS host exists.)

---

## 5. Cowork layer prompts (Opus 4.8)

### CW-1 Phase design validation (run before each Code phase)

> **Tool: Cowork · Model: Opus 4.8 · Effort: `max` for Phase 1, `xhigh` for later phases**

```
You are my design reviewer for Llavero. Read in this folder: 00-Master-Index, Annex <letters for this phase>, and the Phase <N> tasks in the tracker.
Before I implement Phase <N> in Claude Code, do NOT write application code. Instead:
1. Restate the exact approach for each Phase <N> task in plain build terms.
2. List the concrete failure modes and edge cases I must handle. For Phase 1 cover: master key in memory, Argon2id calibration on the real server, audit-chain ordering under concurrent writes, per-admin key wrapping, and the recovery-key path.
3. Flag any gap or ambiguity in the annexes for this phase, and any conflict with D-01..D-33.
4. Give me an ordered, dependency-correct task checklist with the acceptance test for each task.
Output a short design brief I can paste straight into the Code session.
```

### CW-2 Security and diff review (run at each phase boundary / gate)

> **Tool: Cowork · Model: Opus 4.8 · Effort: `max`**

```
Act as a security reviewer for Llavero, an in-house secrets and audit system. I will paste the git diff and file list from the last Claude Code session for Phase <N>, tasks <IDs>.
Check against Annex A (encryption), B (audit), D (permissions), F (read-only), G (hardening):
- Is any secret plaintext or the master key ever logged, cached, written to disk or swap, or sent to a Viewer session?
- Are permission checks server-side, not just UI masking? Is the Viewer session truly keyless?
- Audit: same-transaction insert, advisory-lock ordering, gap-free seq, canonical hashing, append-only enforced at the DB role and trigger?
- Integrations: read-only scopes only, no write permission, egress limited to Graph plus the gear?
- Any deviation from D-01..D-33 or the annexes?
Return findings as Critical / Should-fix / Nit, each with the file, the rule it breaks, and the fix. End with a go / no-go for the phase gate.

<paste git diff here>
```

To produce the input, end the Code session with: `run: git diff > last_phase.diff and print the file list`. Or use the `code-review` skill in Cowork on the pasted diff.

### CW-3 Update tracker and decision registry

> **Tool: Cowork · Model: Opus 4.8 · Effort: `low`**

```
Update Llavero-v1-Build-Plan-Tracker.xlsx from this Claude Code session summary.
- Set the status of the listed task IDs (Done / In progress / Blocked) in the Tasks sheet.
- If a decision was made or changed, add or adjust a row following the Master Index convention and note the reason.
- If I hit a blocker, add a short note in that task's Notes cell.
Keep formulas and formatting intact, then tell me the new progress counts.

<paste session summary here>
```

### CW-4 Runbook / docs

> **Tool: Cowork · Model: Opus 4.8 · Effort: `high`**

```
Write the <runbook name> for Llavero as a markdown doc in this folder, drawing only from the annexes and the current build.
Topic: <e.g., the disaster-recovery restore through the recovery-key path, Annex H 7 plus Annex G 9>.
Audience: a future admin acting under pressure. Numbered steps, exact commands where known, decision points called out, and the failure and rollback path. No filler.
```

### CW-5 Test strategy / threat model

> **Tool: Cowork · Model: Opus 4.8 · Effort: `xhigh`**

```
Produce the <test strategy | threat model> for Phase <N> of Llavero from Annex <letters>.
Test strategy: list the unit, integration, and security tests per task, each with the exact assertion it makes. Example: "A Viewer reveal request returns 403, the response body contains no ciphertext, and no secret_reveal audit entry is created."
Threat model: enumerate the threats for this phase, the defense the annexes specify, and any residual risk.
Output a checklist I can hand to Claude Code.
```

### CW-6 Weekly status

> **Tool: Cowork · Model: Opus 4.8 · Effort: `low`**

```
From the tracker, give me a 6-line status: phase in progress, percent of tasks done overall and in this phase, what is blocked, the next gate and what it needs, and any open confirmation still pending (offsite office, reauth window).
```

---

## 6. Code build prompts (one per phase)

Each prompt assumes CLAUDE.md is in the repo. Set the model and effort from the header line first.

### CD-1 Phase 1, the security spine

> **Tool: Claude Code · Model: Opus 4.8 · Effort: `/effort xhigh` (switch to `/effort max` for the crypto and audit tasks)**

```
Implement the Phase 1 security spine, one tracker task at a time, in this order:
schema P1-T2, T3, T4; encryption and keys P1-T5, T6, T7, T8, T9, T10; audit log P1-T11, T12, T13, T14; auth and session P1-T15, T16, T17, T18; thin slice P1-T19; verify P1-T20.
Build each task exactly to its cited annex/section. Write tests, run them, and stop for my review before the next task.
Crypto and audit tasks are security-critical: before T6 and T12, tell me to set /effort max. Never put the master key on disk or swap, never log a secret.
At P1-T20 prove: the chain verifies, the master key is absent from disk/swap/core dump, and a Viewer session cannot decrypt. Use throwaway data only.
```

### CD-2 Phase 2, backups

> **Tool: Claude Code · Model: Sonnet 4.6 · Effort: `/effort high` (use Opus 4.8 `xhigh` for the gate task P2-T6)**

```
Implement Phase 2, tracker P2-T1..T6. Daily pg_dump on a timer, encrypted at rest with age using asymmetric keys (public key on the server, private key offline). Three destinations: the separate host, a second host/NAS, and the offsite office over the MikroTik tunnel. GFS retention. Backup monitoring shipped to the separate host.
No WAL in v1 (P-15). Keep the private key, recovery key, and keyfile in the safe, never with the backups.
For P2-T6 switch to Opus 4.8 at /effort xhigh: run the restore dry run in an isolated env, prove the DB loads, the chain verifies, and a secret decrypts through the recovery-key path. This is a hard gate: no real secrets until it passes.
```

### CD-3 Phase 3, inventory

> **Tool: Claude Code · Model: Sonnet 4.6 · Effort: `/effort medium`**

```
Implement Phase 3, tracker P3-T1..T8. CRUD plus HTMX UI for person, account, device, office, and network_device_detail. The nine join tables with their partial-unique constraints. State machines with no hard delete. Custom fields honoring viewer_visible. Fast relationship creation from any entity page.
Wire every write to the audit chain and add read logging at the defined granularity (record_view, list_view, search; never pagination or refresh). Enforce field-level permissions server-side, not just in the UI.
Tests per task. Stop at P3-T8 and verify audit coverage and that Viewer masking holds server-side. Throwaway data only.
```

### CD-4 Phase 4, secrets

> **Tool: Claude Code · Model: Opus 4.8 · Effort: `/effort xhigh` (use `/effort max` for the recovery gate P4-T6)**

```
Implement Phase 4, tracker P4-T1..T6. Secret store with AAD bound to the record. The reveal flow with per-action step-up reauth and a logged reason, transient display, clipboard auto-clear, never logged or cached. Rotation producing a new DEK and ciphertext. Viewer masking backed by the keyless session. Full secret audit coverage with non-sensitive facts only.
For P4-T6 set /effort max: validate the recovery-key reveal path end to end. With P2-T6 this clears the real-secrets gate.
Build to Annex A, D, and B exactly. Tests per task. Throwaway data only until the gate passes.
```

### CD-5 Phase 5, read-only integrations

> **Tool: Claude Code · Model: Sonnet 4.6 · Effort: `/effort high`**

```
Implement Phase 5, tracker P5-T1..T6. The integration table and scheduler. A Graph app registration, app-only with certificate auth, read-only scopes only (User.Read.All plus AuditLog.Read.All or UserAuthenticationMethod.Read.All); request NO write scopes. Daily MFA pull into account.mfa_state and mfa_types, matched by external_id. Network monitoring for WatchGuard (SNMPv3), MikroTik (RouterOS API over TLS or SNMP), and UniFi (controller API over HTTPS) every 5 minutes. Credentials stored as vault secrets.
Telemetry goes to a non-chained table; only meaningful transitions reach the audit chain. Stop at P5-T6 and prove there are no write scopes, egress is limited to Graph plus the gear, and telemetry stays off the chain.
```

### CD-6 Phase 6, alerts and dashboard

> **Tool: Claude Code · Model: Sonnet 4.6 · Effort: `/effort high` for the rules, `/effort medium` for the dashboard UI**

```
Implement Phase 6, tracker P6-T1..T8. The alert and setting tables, an idempotent evaluator keyed by (rule_id, target) running every 15 minutes and on demand, as a system actor whose reads are not logged. All 13 rules E-1..E-13 over the relationship graph. E-1 unrecoverable_device_types = ["phone","tablet","laptop"] per P-13, reading account_device_config. Auto-resolve with the rotation-evidence exceptions. Dashboard with severity grouping, Admin acknowledge with note, filters, links, and the integrity strip fed by E-13.
Thresholds live in the setting table, Admin-editable, each change logged. Stop at P6-T8 and run rule-firing tests including E-1 on seeded data.
```

### CD-7 Phase 7, release gate

> **Tool: Claude Code · Model: Opus 4.8 · Effort: `/effort max`**

```
Run Phase 7, tracker P7-T1..T6. Full DR drill to fresh hardware: provision per Annex G, restore the offsite backup, unlock via the printed recovery key, re-seal to the new TPM, re-enroll both admins, re-point integrations, and verify the chain against the off-box checkpoints. Then the security pass over egress, the role and field matrix, the Viewer export block, and single-session. Handover countdown QA. Confirm the reauth window.
Only after P7-T1 and P7-T2 pass: load real data and go live (P7-T5). Finish with the v1 definition-of-done checklist (P7-T6).
```

### CD-NEXT generic single-task prompt (any phase)

> **Tool: Claude Code · Model and effort per the matrix for that phase**

```
Implement tracker task <ID> only. Read its row (task, implements, depends-on) and the cited annex section. Confirm its dependencies are Done first. Build to spec, write and run tests, then stop and summarize the files changed and the task ID for the tracker. Do not start the next task.
```

---

## 7. Corrections and debugging prompts (Claude Code)

### FIX-1 Routine bug

> **Model: Sonnet 4.6 · Effort: `/effort medium`**

```
Bug in <area>, tracker task <ID>. Symptom: <what you see>. Expected: <what should happen>. Reproduce it, find the root cause, fix it, add a regression test, and run the suite. Explain the cause in two lines.
```

### FIX-2 Stubborn or subtle bug

> **Model: Opus 4.8 · Effort: `/effort xhigh`**

```
This bug resists the obvious fix. Symptom: <...>. What I already tried: <...>. Do a structured debug pass: reproduce, isolate, form hypotheses, test each, then fix at the root cause, not the symptom. Add a regression test. If it touches crypto, audit, or permissions, treat it as security-critical and set /effort max.
```

### FIX-3 Security bug

> **Model: Opus 4.8 · Effort: `/effort max`**

```
Possible security issue in Llavero: <description>. Treat as critical. Determine whether a secret, plaintext, or the master key can leak, whether a Viewer can reach a key, or whether the audit chain can be bypassed. Confirm the vulnerability with a failing test first, then fix it, then prove the test passes and nothing else regressed. Summarize the root cause and the blast radius.
```

### FIX-4 Test failure

> **Model: Sonnet 4.6 · Effort: `/effort medium`**

```
These tests fail: <paste output>. Diagnose and fix the code, not the test, unless the test itself is wrong, in which case say so and explain. Re-run until green.
```

### FIX-5 Apply Cowork review feedback

> **Model: Sonnet 4.6 · Effort: `/effort high`**

```
Address the review findings from Cowork for task <ID>. Findings: <paste the Critical and Should-fix list>. Fix each one, add tests where missing, re-run the suite, and summarize what changed per finding.
```

### FIX-6 Migration issue

> **Model: Sonnet 4.6 · Effort: `/effort high` (Opus 4.8 if there is data-loss risk)**

```
Migration problem: <paste error>. Resolve it without data loss and without breaking the append-only audit constraints or the no-hard-delete rule. Show me the migration plan before applying it.
```

---

## 8. How a phase flows across the two tools

The loop, per phase:

1. **Cowork CW-1** design validation (Opus, `max` for Phase 1 else `xhigh`). Paste the brief into Code.
2. **Code CD-n** build the phase (model and effort per the matrix). End with `git diff` and a summary.
3. **Cowork CW-2** security and diff review (Opus `max`). Get the go / no-go.
4. **Code FIX-5** apply the findings (Sonnet `high`).
5. **Cowork CW-3** update the tracker and decision registry (Opus `low`).
6. At the gates (P2-T6, P4-T6, Phase 7): run the restore and recovery validation before moving on, and use **CW-4** to capture the DR runbook.

Spend the 2X Cowork month on steps 1, 3, and especially 5's sibling reviews: heavy Opus reasoning on design and security is where the value is, while Sonnet does the high-volume coding in Code.

---

*Companion files: `Llavero-v1-Build-Plan-Tracker.xlsx` (tasks, dependencies, gates) and `Llavero-v1-Plan-Summary.md` (the one-pager).*
