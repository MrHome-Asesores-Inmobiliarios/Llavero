---
description: "Implement a security-critical task at max rigor"
disable-model-invocation: true
model: opus
effort: max
argument-hint: "[task-id]"
---

Security-critical task. Implement tracker task $ARGUMENTS only, at maximum rigor. Read its annex section and acceptance test (Phase1-Design-Brief.md section B for Phase 1). Treat it as a place where a subtle error is expensive: reason exhaustively about the master key in memory, audit-chain ordering, AAD binding, the keyless Viewer, and the recovery path as relevant. Confirm dependencies are Done.

Write the test first where it expresses a security property (for example: no ciphertext in a Viewer response, or the master-key buffer is zeroed after lock). Build, run the suite, then stop and summarize. Never log a secret or place the master key on disk or swap.
