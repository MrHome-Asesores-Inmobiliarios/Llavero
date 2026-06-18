---
description: "Run Phase 7 DR drill, security pass, and go-live"
disable-model-invocation: true
model: opus
effort: max
---

Run Phase 7, tracker P7-T1..T6, per CLAUDE.md and Annex H and G. Full DR drill to fresh hardware: provision per Annex G, restore the offsite backup, unlock via the printed recovery key, re-seal to the new TPM, re-enroll both admins, re-point integrations, and verify the chain against the off-box checkpoints. Then the security pass over egress, the role and field matrix, the Viewer export block, and single-session. Handover countdown QA. Confirm the reauth window.

Only after P7-T1 and P7-T2 pass: load real data and go live (P7-T5). Finish with the v1 definition-of-done checklist (P7-T6).
