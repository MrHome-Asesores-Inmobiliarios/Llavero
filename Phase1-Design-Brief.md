# Llavero Phase 1 Design Brief (CW-1 output)

Vetted, dependency-ordered build brief for the security spine. Paste into the Claude Code `/spine` (CD-1) session. Built from Annex A, B, C, D, G, and the tracker. Treat D-01..D-33 as settled.

---

## A. Build order (dependency-correct)

1. **Schema:** P1-T2 core models, then P1-T3 join tables, then P1-T4 session tables. (Needs P1-T1 scaffold done.)
2. **Encryption and keys:** P1-T5 Argon2id calibration, then P1-T6 envelope encryption, then P1-T7 TPM second factor, P1-T8 MK in memory, P1-T9 per-admin wrapping, P1-T10 recovery key.
3. **Audit:** P1-T11 schema + append-only role + trigger, then P1-T12 hash chain, then P1-T13 verify + signed checkpoint, then P1-T14 off-box anchor.
4. **Auth and session:** P1-T15 operator auth, then P1-T16 single session + keyless Viewer, then P1-T17 step-up reauth + idle lock, then P1-T18 handover.
5. **Slice:** P1-T19 thin vertical slice.
6. **Verify:** P1-T20.

**Cross-track note.** Build T2 to T6, T8 to T13, and T15 to T19 on a dev box with a keyfile stub and dev-grade Argon2 params. Finalize T5 (calibration on real CPU/RAM) and T7 (real TPM seal) on the hardened server, and T14 needs the separate host (P0-T9). Use throwaway data until the Phase 2 and Phase 4 gates pass.

---

## B. Per-task approach and acceptance test

**P1-T2 Core models** (Annex C 2, 3, 4, 9). operator, operator_webauthn_credential, operator_session, person, account, device, network_device_detail, office, secret, field_definition. UUIDv4 PKs, base mixin (state, notes, custom_fields, created_at, updated_at, created_by, updated_by), enums as TextChoices + CHECK. created_by/updated_by reference operator, never person.
Accept: migrations apply clean; a CHECK rejects an invalid enum value; created_by FK targets operator.

**P1-T3 Join tables** (Annex C 5, 6). Nine tables, FK both ends, link columns (state, valid_from, valid_to + audit). Partial unique indexes: one active primary owner per account, one active holder per device, one active location per device, one active responsible per office. CHECK a<>b on account_recovery and device_dependency.
Accept: a second active primary owner insert fails on the partial unique; ending a link sets state=former and valid_to without deleting the row.

**P1-T4 Session tables** (Annex C 4.3, 4.3b). operator_session (token_hash, never the token; last_activity_at; revoked_at). session_request (enum pending/granted/denied/expired/cancelled; expires_at).
Accept: only the token hash is stored; a new login can set revoked_at on a prior session.

**P1-T5 Argon2id calibration** (Annex A 5.1, 11). Calibrate to about 4s, memory 1 to 2 GiB, parallelism = physical cores. Store params next to the wrapped MK with scheme_version. Dev uses lower params; recalibrate on the server.
Accept: calibrate() returns params whose measured time meets the target on the target box; params persisted.

**P1-T6 Envelope encryption** (Annex A 3, 4, 11; Annex C 4.9). XChaCha20-Poly1305, 24-byte random nonce, AAD = account_id + field name. Hierarchy passphrase -> (Argon2id) KWK -> (HKDF with second factor) MK -> per-secret DEK. Store ciphertext, nonce, dek_wrapped, dek_nonce, aad_context, scheme_version.
Accept: encrypt/decrypt round-trips; tampering the ciphertext or AAD makes decrypt raise; a DEK reused on another record fails AAD verification.

**P1-T7 Vault second factor, TPM sealing** (Annex A 5.2; Annex G 4). Seal a secret to TPM2; combine with the Argon2id output via HKDF to form the KWK. Keyfile fallback kept off the backup path.
Accept: unlock works with passphrase + factor; with the factor missing or wrong the wrapped-MK decrypt fails; a database-only copy with no factor cannot derive the MK.

**P1-T8 Master key in memory, Model A** (Annex A 6, 7; Annex G 2). sodium_malloc/mlock the MK buffer; memzero on lock, logout, shutdown; idle auto-lock; core dumps disabled.
Accept: the buffer is zeroed after lock/idle/logout (assert via a test wrapper); core dumps are off; the MK never enters a Django session, cache, or log.

**P1-T9 Per-admin wrapping** (Annex A 13). vault_key_holder, one row per admin (kdf params, mk_wrapped, mk_nonce, second_factor_ref). Enroll second admin (an existing in-memory MK wraps under the newcomer KWK). Remove admin (delete the row, then rotate the MK: new MK, re-wrap all DEKs and remaining admins).
Accept: both admins unlock the same MK via their own rows; after removal + rotation the removed row no longer derives a working MK and all secrets still decrypt for the remaining admin.

**P1-T10 Printed recovery key** (Annex A 8). Generate a high-entropy recovery key that independently wraps the MK; print and store in the safe; independent of admin credentials.
Accept: the recovery key alone unwraps the MK in a test; the print/store procedure is documented.

**P1-T11 Audit schema + append-only** (Annex B 4, 5; Annex G 5). audit_entry and audit_checkpoint. App DB role has INSERT/SELECT only on the audit tables, no UPDATE/DELETE; a BEFORE UPDATE OR DELETE trigger raises; migrations use a separate role.
Accept: UPDATE/DELETE on audit_entry as the app role fails by both grant and trigger; INSERT/SELECT work.

**P1-T12 Hash chain** (Annex B 3, 5). BLAKE2b-256; canonical length-prefixed payload over the ordered field list plus raw prev_hash; genesis prev_hash = 32 zero bytes; gap-free seq. append_audit takes pg_advisory_xact_lock(constant), reads the head, and inserts in the SAME transaction as the data change.
Accept: concurrent operator + monitoring writes under load produce a gap-free linear chain; verify passes; forcing the audit insert to fail rolls back the data change too.

**P1-T13 Verify + signed checkpoint** (Annex B 7; Annex G 7). Chain-walk verifier (recompute entry_hash, check links). Signed checkpoint over head_hash using an Administrator WebAuthn assertion; the server stores only the public key and the signature.
Accept: verify pinpoints an altered entry at the right seq; a checkpoint signature verifies against the admin public key; post-checkpoint tampering is caught by the anchor check.

**P1-T14 Off-box anchor** (Annex G 7; Annex B 2). Copy each signed checkpoint to the separate host in an append-only store the app can write but not modify or delete; printed-copy procedure. Needs P0-T9.
Accept: a checkpoint lands on the separate host; the app role cannot overwrite or delete it there.

**P1-T15 Operator auth** (Annex D 1, 2; Annex C 4.1, 4.2; Prelim 6). Login = operator password (Argon2id login hash, separate from the vault) + second factor (py_webauthn platform authenticator, pyotp TOTP fallback). Login does not depend on M365.
Accept: login needs password + a valid WebAuthn/TOTP; WebAuthn sign_count replay is rejected; an Admin login enters the vault-unlock path, a Viewer login does not.

**P1-T16 Single session + keyless Viewer** (Annex D 2, 8; Annex C 4.3). Advisory-lock-guarded login; a new privileged login revokes or blocks the prior one. The Viewer session never derives or holds the MK.
Accept: two concurrent privileged sessions are impossible (race test); the Viewer session holds no MK and a forced reveal has nothing to decrypt with.

**P1-T17 Step-up reauth + idle lock** (Annex D 6). Per-action reauth with no caching (reveal, create, rotate, checkpoint); windowed reauth (about 2 minutes) for export, operator, and parameter changes; idle auto-lock wipes the MK.
Accept: reveal prompts every time; a windowed action reuses one step-up within the window then re-prompts; idle timeout wipes the MK and forces a full unlock next.

**P1-T18 Handover** (Annex D 8 chosen config; Annex C 4.3b). Hybrid B+C: idle-yield 120s, grace 300s, extend +600s, release-now. Server-driven notice; depleting bar; release locked the first 5s; amber under 60s, red under 20s. Handover never transfers the key.
Accept: the state machine moves pending -> granted/denied/expired/cancelled; on auto-transfer the outgoing MK is wiped and work is saved as a draft; the incoming admin unlocks with their own credentials.

**P1-T19 Thin vertical slice** (Annex I 3). One entity create, one secret stored and revealed, one logged change, one login, end to end.
Accept: the full happy path works through the UI, each step writes the right audit entries, and verify is green.

**P1-T20 Verify** (Annex I 4, 5). Prove the chain verifies, the MK is absent from disk/swap/core, and a Viewer cannot decrypt.
Accept: the three checks pass in an automated test plus a manual swap/core check. Sign-off to fan out.

---

## C. Failure modes to guard (the riskiest)

- **MK in memory (R-2):** any path that logs, pickles, copies, caches, or pages the MK. Guard with mlock, memzero, no core dumps, swap off or encrypted, and never placing the MK in a Django session, cache, or log line.
- **Argon2id calibration (R-1):** dev params shipped to prod (too weak) or prod params on a weak box (too slow, a self-DoS). Guard by calibrating on the real server, storing params per record with scheme_version, and keeping a recalibrate path.
- **Audit chain ordering (R-3):** concurrent operator and monitoring writes interleave into a gap or a fork. Guard with pg_advisory_xact_lock on a constant key, same-transaction insert, and a gap-free seq assertion. Load-test it inside the slice.
- **Same-transaction coupling:** a data write without its audit entry, or the reverse. Guard with a single transaction and test the rollback both directions.
- **Per-admin removal without MK rotation:** a removed admin plus a retained wrapped copy could still decrypt. Removal must always rotate the MK.
- **Untested recovery key (R-6):** a false sense of safety. Exercise the recovery wrap in the P1-T10 test now; validate the full path at P4-T6.
- **Viewer keyless by policy only:** assert at the session layer that a Viewer never derives the MK, and that serializers never emit ciphertext to a Viewer.
- **WebAuthn signing key on the server:** store only the public key and the assertion; the private key stays in the authenticator.

---

## D. Gaps and conflicts (no silent redesign)

- **E-1 table name:** Annex E says `account_configured_on_device`; Annex C (authoritative) says `account_device_config`. Use `account_device_config`. Carried in CLAUDE.md, surfaces in Phase 6, harmless in Phase 1.
- **Reauth window length** (Annex D 10, open point 4): 2 minutes is a starting value, confirm in Phase 0 or 7. Not blocking.
- **General idle auto-lock vs handover idle-yield** (Annex D 8 note): two separate timers, keep them distinct, confirm if you want them aligned.
- No conflict found with D-01..D-33 for Phase 1.

---

## E. What to hand the build session

Build in the order in section A, one task at a time, each to its acceptance test in section B. Set `/effort xhigh`, and switch to `/effort max` for T6, T7, T12, and T13. Stop at T20 and run the three proofs. Use throwaway data and a keyfile or dev Argon2 stub until the hardened server exists.
