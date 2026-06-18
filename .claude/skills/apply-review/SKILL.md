---
description: "Apply Cowork review findings"
disable-model-invocation: true
model: sonnet
effort: high
argument-hint: "[paste findings]"
---

Apply the Cowork review findings: $ARGUMENTS. Fix each Critical and Should-fix item, add tests where missing, re-run the suite, and summarize what changed per finding. If a finding needs a design change beyond the annexes, stop and flag it instead of redesigning.
