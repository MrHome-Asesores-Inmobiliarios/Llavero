---
description: "Scaffold the Django + PostgreSQL project (P1-T1)"
disable-model-invocation: true
model: sonnet
effort: medium
---

Read CLAUDE.md and the spec first. Implement tracker task P1-T1: scaffold the Llavero Django + PostgreSQL project. Bind the app to localhost, set scram-sha-256 for the DB, add a reverse proxy with an internal-CA TLS cert and a hardened systemd unit (Annex G 5, Preliminary Design 8). Set up the settings split, pinned dependencies, pre-commit with black and ruff, and a test runner. Do not add feature models yet. Confirm the dev server starts and an empty test suite runs, then stop and summarize for the tracker.
