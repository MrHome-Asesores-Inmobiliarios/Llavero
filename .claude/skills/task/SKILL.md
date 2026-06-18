---
description: "Implement a single tracker task by ID"
disable-model-invocation: true
argument-hint: "[task-id]"
---

Implement tracker task $ARGUMENTS only. Read its row (task, implements, depends-on) in Llavero-v1-Build-Plan-Tracker.xlsx and the cited annex section. Confirm its dependencies are Done first. Build to spec, write and run tests, then stop and summarize the files changed and the task ID for the tracker. Do not start the next task. Set /model and /effort to match the phase first if you have not already.
