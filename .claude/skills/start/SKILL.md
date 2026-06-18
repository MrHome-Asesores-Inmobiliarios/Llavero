---
description: "Orient and route to the next command to run"
disable-model-invocation: true
model: sonnet
effort: low
argument-hint: "[optional: what you want to work on]"
---

Read CLAUDE.md, Phase1-Design-Brief.md, and TASKS.md, and skim the Annex files they reference.

If $ARGUMENTS describes something specific I want to work on, match it to the matching tracker task. Otherwise pick the next task whose dependencies are all Done.

Then, in at most 6 lines: state the hard constraints in one line, the current phase, the last completed task, and the chosen next task with its dependencies. Do not write code.

Recommend the exact slash command to run next so its model and effort load correctly: `/scaffold`, `/spine`, `/task <ID>`, `/secure-task <ID>`, `/backups`, `/inventory`, `/secrets`, `/integrations`, `/alerts`, `/release`, or a fix command (`/fix`, `/debug`, `/security-bug`). Also tell me the session baseline to set for this phase (for example `/model opus` then `/effort xhigh`). If the next step is a gate (P2-T6 or P4-T6), remind me real secrets stay out until both gates pass. Then wait for me to run it.
