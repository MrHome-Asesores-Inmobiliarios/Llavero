# Annex D: Permissions and Roles

**Companion to the preliminary design, Annex A (encryption), Annex B (audit), and Annex C (data model).** Defines exactly what each role can see and do, field by field, what triggers reauthentication, and how the single-session rule works.

---

## 1. Roles and philosophy

Two roles, least privilege, enforced on the server. The user interface masks data for convenience, but the server is the real boundary: it never sends a secret to a session that is not entitled to it.

- **Administrator:** full read and write across the inventory. Can reveal and rotate secrets (with reauthentication), manage operators and custom fields, change parameters, and create signed audit checkpoints.
- **Viewer:** read-only across the inventory and the audit log. Secrets are always masked. Cannot change anything. Exports are not available to Viewer.

---

## 2. The key idea: the Viewer session never holds the master key

This is the strongest part of the model. Per Annex A, the master key (MK) is unlocked only from an Administrator passphrase plus second factor. A Viewer login authenticates the person, but it **does not unlock the MK**. The Viewer session simply never has the key in memory.

The consequence: "Viewer cannot reveal secrets" is not merely a permission check that code could get wrong, it is a cryptographic fact. A Viewer session, even if fully compromised, has nothing to decrypt with. Only the Administrator session ever holds the MK, and only while unlocked.

Side effect: the 2 to 8 second Argon2id cost is paid only by the Administrator at unlock. Viewer login is fast.

---

## 3. Permission dimensions

Every request is evaluated on three dimensions:

1. **Action on a resource.** Can this role create, read, update, change state, or relate this entity type.
2. **Field-level visibility.** Some fields are masked even when the record is readable. Secrets always. Custom fields per their `viewer_visible` flag.
3. **Step-up gates.** Some actions require fresh reauthentication regardless of role, because the role check alone is not enough for the most sensitive operations.

---

## 4. Action matrix

R = allowed, blank = denied. "reauth" means the action also requires a step-up (section 6).

| Operation | Administrator | Viewer |
|---|---|---|
| View list, view record | R | R (secrets masked) |
| Search | R | R |
| Create entity (person, account, device, office) | R | |
| Update entity fields | R | |
| Change entity state | R | |
| Create or end a relationship | R | |
| Create a secret | R, reauth | |
| Rotate a secret | R, reauth | |
| Reveal a secret | R, reauth | (no key, cannot) |
| Change a secret's state | R | |
| View that a secret exists (kind, label, last rotated) | R | R |
| View dashboards and on-screen reports | R | R |
| Export data (report or file leaving the system) | R, reauth | |
| Manage operators (create, disable, change role) | R, reauth | |
| Manage custom field definitions | R | |
| Change system parameters (KDF, intervals, thresholds) | R, reauth | |
| View the audit log | R | R |
| Run chain verification | R | R |
| Create a signed audit checkpoint | R, reauth and signing key | |
| Unlock the vault (hold the MK) | R | (not applicable) |

---

## 5. Field-level visibility

| Field group | Administrator | Viewer |
|---|---|---|
| Secret values (password, recovery codes, PINs, keys) | revealable via the gated flow | always masked, no key to decrypt |
| Secret metadata (kind, label, last_rotated_at, exists) | visible | visible |
| Recovery email and phone on an account | visible and editable | visible, not editable |
| Account identifier, MFA state, MFA types | visible and editable | visible |
| Custom fields | visible and editable | visible only if `viewer_visible` is true |
| All other ordinary fields | visible and editable | visible, not editable |

Recovery email and phone are data, not secrets, and the unrecoverability dashboard needs them, so both roles see them. Only the actual stored secrets are gated by the MK.

---

## 6. Reauthentication (step-up)

Reauthentication is a fresh second-factor check (a WebAuthn tap, or a TOTP code) on top of an already-open Administrator session. It exists so that a walked-away-from but still-unlocked session cannot perform the most damaging actions without a deliberate human present.

- **Per-action reauth, no caching:** reveal a secret, create or rotate a secret, create a signed checkpoint. Each of these prompts every time.
- **Windowed reauth (valid about 2 minutes for a batch):** export, operator management, parameter changes. One step-up covers a short burst of related admin work.
- **Idle auto-lock:** after the inactivity window (Annex A, Model A, for example 5 minutes), the session locks and the MK is wiped from memory. Resuming requires the full Administrator unlock again, which re-runs Argon2id. A Viewer resuming only re-authenticates, with no MK to derive.

Every reauth event and every gated action is logged (Annex B), reveals with their reason.

---

## 7. The secret reveal flow

1. Administrator opens a record and requests reveal of a specific secret.
2. The server requires a fresh second-factor step-up and a short reason, both logged.
3. The server decrypts using the MK held in this Administrator session only, and returns the value for transient display: shown briefly or copied to the clipboard with an auto-clear, never written to logs, never cached client-side.
4. A `secret_reveal` entry is appended to the audit chain with who, when, source IP, session, the target, and the reason.

A Viewer cannot enter this flow at all, and even a forged request fails because the Viewer session has no key.

---

## 8. Session concurrency and handover (system-wide single session)

One active session at a time across the whole system, not one per person. With two Administrators, the real contention is one wanting in while the other is active. Three models are described; the chosen one is pending your selection (P-12). Model A is the one you specified and is the default.

### Common rules (all models)
- One privileged session at a time. Privileged means the session that can write and, for an Administrator, holds the master key.
- **Handover never transfers the key.** The outgoing session locks and its master key is wiped. The incoming Administrator unlocks with their own passphrase and second factor (per-administrator wrapping, Annex A section 13).
- Every request, grant, deny, takeover, and expiry is logged (Annex B).
- The notice shown to the active user is server-driven (the client holds a live channel or polls), so a refresh cannot clear it.

### Model A: Request and persistent notify (your design)
B requests access while A is active. A gets a persistent notice that cannot be dismissed by hand, only resolved. A can Release now (A locks, B may unlock) or Deny. If A does neither, the request expires after a TTL (for example 3 minutes), or the instant A goes idle (idle auto-lock frees the session and the pending request is granted to B). On expiry the notice clears and B must re-request. State machine: pending to granted, denied, expired, or cancelled. Tradeoff: A stays in control, B has no guaranteed time bound.

### Model B: Activity-aware auto-yield
Same persistent notice, plus the system watches real input. If A is idle for a short threshold (60 to 90 seconds, far shorter than the full idle-lock), the session transfers to B automatically. A can press Hold to keep it (resets the timer) or Release now. Optimizes the common stepped-away case. Tradeoff: under continuous use by A, B still waits with no hard bound.

### Model C: Bounded grace countdown with auto-transfer
When B requests, A gets a countdown (for example 2 minutes) with Save and release now and Extend once (+5 minutes, capped at one or two extensions). If A does not release and extensions run out, control transfers automatically, A's session locks, and unsaved work is preserved as a draft. Guarantees B access within a bounded time. Tradeoff: A can be forced out by design, and it needs draft preservation.

### Recommendation
A hybrid of B and C: auto-yield on short idleness for the everyday case, plus a bounded countdown if A stays continuously active so B is never locked out. Model A is the simplest to build and keeps humans fully in control, at the cost of no guaranteed access for B.

### Implementation
Backed by `operator_session` plus the `session_request` table (Annex C). The login and request paths take the same advisory lock used elsewhere, so two logins cannot race and at most one session is ever privileged.

### Chosen configuration (decided)
Model: the hybrid of B and C, with these parameters.

- **Active grace countdown: 300 seconds.** The hard ceiling on the waiting admin's wait. It counts down continuously, and at 0 it auto-transfers: the outgoing session locks, the master key is wiped, and in-progress work is saved as a draft.
- **Idle auto-yield: 120 seconds.** Continuous no input from the active admin for 120 seconds hands over early, even with grace time left. Any keystroke or click resets the idle counter to zero.
- **Extend: +600 seconds**, added to the remaining grace time. The idle auto-yield stays armed after an extend, so extending and then walking away still hands over after 120 seconds idle. Each extend is logged.
- **Release now:** immediate handover at any time.
- Whichever trigger fires first wins, idle (120 s) or the grace countdown (300 s plus any extends). Net wait for the requester: about 120 s if the active admin is away, up to 300 s if they keep working, longer if they extend, instant on release.
- **Visual cue:** a long horizontal bar that depletes continuously, labeled in seconds remaining, with a small sidenote that it also hands over after 120 s of inactivity and that unsaved work becomes a draft. The bar shifts to amber under 60 s and red under 20 s. Controls are Release now and Extend +600 s. Release now is disabled for the first 5 seconds after the notice appears, visibly greyed with a small countdown, so it cannot be dismissed reflexively.

This is separate from the general unattended idle auto-lock in Annex A, which locks a session when no one is requesting access. That remains its own setting.

---

## 9. Enforcement notes

- All checks are server-side. UI masking is presentation only, never the security boundary.
- The server never serializes a secret value into a Viewer response, and a Viewer session has no MK regardless.
- Use the framework's permission layer for the action matrix, and field masking in the serializers for visibility. Object-level rules are unnecessary at 1 to 2 operators, role plus field-level is enough.

---

## 10. Open points

1. **Number of administrators and key wrapping.** Resolved: two Administrators, master key wrapped per administrator (Annex A section 13). Closes P-11.
2. **Export by Viewer.** Resolved: Viewer is fully blocked from exports.
3. **Session handover model.** Resolved: hybrid of B and C (section 8, chosen configuration).
4. **Reauth window length.** Two minutes for the windowed group is a starting value. Confirm.
5. **Handover thresholds.** Resolved: idle auto-yield 120 s, active grace 300 s, extend +600 s. The general unattended idle auto-lock (Annex A) is still its own setting, confirm if you want it aligned.

This annex resolves backlog items P-04, P-11, and P-12.
