---
description: "Run the phase gate proofs"
disable-model-invocation: true
model: opus
effort: high
---

Run the gate proofs for the current phase and report pass/fail with evidence.
- Phase 1 (P1-T20): the audit chain verifies end to end, the master key is absent from disk, swap, and core dumps, and a Viewer session cannot decrypt.
- Phase 2 (P2-T6): a restore into an isolated environment loads the DB, the chain verifies, and a secret decrypts through the recovery-key path.
- Phase 4 (P4-T6): the recovery-key reveal path works end to end.
Do not load real secrets unless both P2-T6 and P4-T6 have passed. Summarize the results.
