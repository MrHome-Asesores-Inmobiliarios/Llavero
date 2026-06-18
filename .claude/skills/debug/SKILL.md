---
description: "Structured debug pass for a stubborn bug"
disable-model-invocation: true
model: opus
effort: xhigh
argument-hint: "[symptom / what you tried]"
---

Stubborn bug. Context: $ARGUMENTS. Do a structured debug pass: reproduce, isolate, form hypotheses, test each, then fix at the root cause, not the symptom. Add a regression test and run the suite. If it touches crypto, audit, or permissions, treat it as security-critical.
