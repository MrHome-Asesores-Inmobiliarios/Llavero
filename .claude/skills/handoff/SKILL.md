---
description: "Update TASKS.md and summarize the session for Cowork"
disable-model-invocation: true
model: sonnet
effort: low
---

Update the build state and summarize the session.

1. In TASKS.md, set the status marker of each task you touched: `[x]` Done, `[~]` In progress, `[!]` Blocked, and append `_[status]_`.
2. Run `git diff --stat` and `git status`.
3. Produce a short block I can paste into Cowork to sync the xlsx tracker: the task IDs and their new status, the files changed, any decision or deviation from the annexes, any blocker, and whether tests pass.

Do not change application code.
