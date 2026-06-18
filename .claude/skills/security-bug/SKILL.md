---
description: "Investigate and fix a security issue (critical)"
disable-model-invocation: true
model: opus
effort: max
argument-hint: "[description]"
---

Possible security issue: $ARGUMENTS. Treat as critical. Determine whether a secret, plaintext, or the master key can leak, whether a Viewer can reach a key, or whether the audit chain can be bypassed. Confirm the vulnerability with a failing test first, then fix it, then prove the test passes and nothing else regressed. Summarize the root cause and the blast radius.
