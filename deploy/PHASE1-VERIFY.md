# Phase 1 — Security Spine VERIFY (P1-T20, Annex I 4, 5)

Phase 1 is signed off only when all three proofs pass: the chain verifies, the
master key is absent from disk/swap/core, and a Viewer cannot decrypt.

## Automated proofs

`tests/test_spine_verify.py` asserts, on every CI run:

1. **The chain verifies** — `verify_chain()` (walk), `verify_with_anchor()`
   (signed checkpoint vs trusted key), and `verify_offbox_anchor()` (immutable
   off-box copy) all green after a full slice run.
2. **The master key is absent from disk/swap/core** — the in-memory holder
   refuses pickling/JSON (so it can never enter a Django session or cache); the
   plaintext MK appears in no persisted column (only wrapped forms); the session
   table stores only a token hash; `disable_core_dumps()` drives `RLIMIT_CORE` to
   0 on POSIX.
3. **A Viewer cannot decrypt** — a Viewer session is keyless; `current_master_key()`
   and the reveal flow raise `MasterKeyLocked`.

Run: `pytest tests/test_spine_verify.py` (and the full suite).

## Manual checks on the hardened server (cannot be asserted in CI)

Run these once on the real server (P0-T5) before loading real data:

1. **Swap is off or encrypted** (so the mlock'd MK can never be paged in clear):
   ```bash
   swapon --show            # expect empty, OR all devices on an encrypted backing
   cat /proc/sys/vm/swappiness
   ```
2. **Core dumps are disabled process-wide** (defence with the app-level
   `RLIMIT_CORE=0` and the systemd `LimitCORE=0`):
   ```bash
   cat /proc/sys/kernel/core_pattern     # expect a no-op / disabled pattern
   systemctl show llavero -p LimitCORE   # expect LimitCORE=0
   grep -E 'hard core' /etc/security/limits.conf
   ```
3. **The MK is not paged or dumped while unlocked.** With an admin session
   unlocked, confirm the process has locked memory and no core file is produced
   on a forced abort in a test environment:
   ```bash
   grep VmLck /proc/$(pgrep -f gunicorn | head -1)/status   # non-zero locked memory
   ```
4. **No MK in logs.** `grep -ri` the shipped app/host logs for any base64/hex
   blob of key length — expect none. The code never logs key material.

## Sign-off

When the automated suite is green AND the manual checks pass on the server,
Phase 1 is signed off and later phases may fan out. Note the hard gate: real
secrets stay out until the Phase 2 restore dry run (P2-T6) and the Phase 4
recovery-key path (P4-T6) also pass.
