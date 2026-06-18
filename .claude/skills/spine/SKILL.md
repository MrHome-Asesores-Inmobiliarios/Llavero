---
description: "Build the Phase 1 security spine from the design brief"
disable-model-invocation: true
model: opus
effort: xhigh
argument-hint: "[optional task id]"
---

Follow Phase1-Design-Brief.md. Build the Phase 1 security spine one tracker task at a time in the order in section A: schema P1-T2..T4, encryption and keys P1-T5..T10, audit P1-T11..T14, auth and session P1-T15..T18, slice P1-T19, verify P1-T20. Build each task exactly to its acceptance test in section B.

Tasks T6, T7, T12, and T13 are the most security-critical: pause and tell me to run `/secure-task <ID>` (Opus, max effort) for those, then resume. Never put the master key on disk or swap, and never log a secret. Stop after each task and summarize for the tracker.

At P1-T20 prove the chain verifies, the master key is absent from disk, swap, and core dumps, and a Viewer cannot decrypt. Use throwaway data only. If $ARGUMENTS names a task, start there.
