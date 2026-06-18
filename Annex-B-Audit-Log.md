# Annex B: Hash-Chained Audit Log

**Companion to the preliminary design and to Annex C.** Defines the tamper-evident, append-only log that records every state-changing action and every secret reveal across the Annex C tables. This is the "secure fingerprint" requirement made concrete.

---

## 1. Goals

1. **Complete and attributable.** Every state change and every secret reveal is recorded with who, when, from where, on what, and what changed.
2. **Append-only.** Entries can be inserted and read, never updated or deleted, enforced at the database level.
3. **Tamper-evident.** Each entry is hash-chained to the previous one, so any insertion, deletion, reordering, or edit breaks the chain at a detectable point.
4. **No secret leakage.** The log never stores secret plaintext, not even in before-and-after diffs.
5. **Verifiable on demand.** A verification routine can confirm the chain is intact and matches a trusted external anchor.

---

## 2. Threat model and the honest limitation

A hash chain detects tampering, it does not prevent it. If an attacker has write access to the database, they can edit an old entry and then recompute every hash from that point to the head, producing a chain that looks valid on its own. The chain is only trustworthy if you also know the real head independently.

That is why this design has two parts:

- **The chain** catches casual tampering, accidental corruption, and any attacker who cannot rewrite the entire chain atomically.
- **Signed external checkpoints** catch the full-rewrite attack. At intervals, the current head hash is signed with a key the database process does not hold, and a copy is written to an append-only location outside the database. To forge history undetectably, an attacker would now also need that signing key and the ability to rewrite the external copies, which they do not have.

Without the second part, the log is detection-only and assumes you trust whoever holds the database. With it, the log resists even a malicious administrator.

---

## 3. The chain construction

- Each entry has a strictly increasing, gap-free sequence number `seq`.
- Each entry stores `prev_hash` (the previous entry's `entry_hash`) and its own `entry_hash`.
- `entry_hash = H(canonical_payload || prev_hash)`.
- The genesis entry has `seq = 1` and `prev_hash` set to 32 zero bytes.
- **Hash function:** BLAKE2b-256 via libsodium (`crypto_generichash`), to stay consistent with the encryption stack. SHA-256 is an equally valid alternative.

**Canonicalization is mandatory.** The hash must be computed over a deterministic byte encoding so that verification reproduces the exact input. The payload is a length-prefixed concatenation of a fixed, ordered field list:

```
payload = LP(seq) || LP(occurred_at_iso) || LP(actor_type) ||
          LP(actor_operator_id) || LP(actor_username) || LP(session_id) ||
          LP(source_ip) || LP(action) || LP(target_table) || LP(target_id) ||
          LP(target_label) || LP(canonical_json(changes)) ||
          LP(canonical_json(metadata))
```

where `LP(x)` is a 4-byte big-endian length followed by the UTF-8 bytes of `x`, and `canonical_json` uses sorted keys and compact separators (RFC 8785 JCS is the rigorous option). Length-prefixing removes any ambiguity between fields. `prev_hash` is appended as raw bytes after the payload.

---

## 4. Schema

### 4.1 audit_entry

| Field | Type | Notes |
|---|---|---|
| seq | bigint PK | strictly increasing, gap-free, assigned under the append lock |
| id | uuid unique | stable external id |
| occurred_at | timestamptz | when the action happened |
| recorded_at | timestamptz | when the row was written, default now() |
| actor_type | text (enum) | operator, system |
| actor_operator_id | uuid FK operator | null for system actions |
| actor_username | text | snapshot, so the log reads correctly even if the operator is later renamed |
| session_id | uuid FK operator_session | null for system actions |
| source_ip | inet | |
| action | text (enum) | see section 6 |
| target_table | text | which Annex C table |
| target_id | uuid | which row |
| target_label | text | human-readable snapshot, for example the account label or device serial |
| changes | jsonb | redacted before-and-after diff, default `'{}'` |
| metadata | jsonb | extra context, for example reveal reason, default `'{}'` |
| prev_hash | bytea(32) | previous entry hash |
| entry_hash | bytea(32) unique | this entry's hash |
| hash_algo | text | for example `blake2b-256` |
| scheme_version | integer | for future upgrades |

### 4.2 audit_checkpoint

| Field | Type | Notes |
|---|---|---|
| id | uuid PK | |
| seq | bigint | the head seq at checkpoint time |
| head_hash | bytea(32) | the entry_hash at that seq |
| created_at | timestamptz | |
| created_by | uuid FK operator | |
| signature | bytea | signature over head_hash, see section 5 |
| signer | text | which key signed, for example "admin hardware key" |
| external_anchor_ref | text | where the copy was written, for example a syslog host id or file path |

Both tables are append-only. `audit_checkpoint` is the trusted reference for verification.

---

## 5. Append-only enforcement and write path

### Database-level immutability
- The application connects with a database role that has `INSERT` and `SELECT` on the audit tables, and no `UPDATE` or `DELETE`.
- A `BEFORE UPDATE OR DELETE` trigger on both audit tables raises an exception, as defense in depth.
- A superuser can still bypass these. That residual risk is exactly what the signed external checkpoint in section 2 covers.

### Same-transaction guarantee
The audit insert happens inside the same database transaction as the change it records. Either both commit or both roll back. There is no way to change data without a matching log entry, and no orphan log entry for a change that did not happen.

### Strict ordering
The chain must be linear even though a background monitoring job can write at the same time as an operator. Before reading the head and inserting a new entry, the writer takes a fixed advisory lock (`pg_advisory_xact_lock` on a constant key). This serializes appends so `seq` stays gap-free and every `prev_hash` points at the true previous head. At this system's scale the lock is essentially never contended.

### Monitoring telemetry stays out of the chain
The network monitoring poll updates volatile fields like `health_state` and `last_seen_at` frequently. Logging every poll would flood the chain and bury the meaningful events. Decision: raw telemetry is written to a separate, non-chained telemetry table, and only **state transitions** that matter (for example reachable to offline, or a firmware version change) produce an `audit_entry`. The tamper-evident chain stays focused on human actions and significant changes.

---

## 6. What gets logged (coverage policy)

| Category | Actions |
|---|---|
| Entity lifecycle | create, update (with field diff), state_change |
| Relationships | relationship_create, relationship_end |
| Secrets | secret_create, secret_rotate, secret_reveal, secret_state_change |
| Authentication | login_success, login_failure, logout, vault_unlock, vault_lock, session_revoke, reauth |
| Configuration | field_definition_change, operator_change, parameter_change |
| Data egress | export (any report or data leaving the system) |
| Read access | record_view, list_view, search |
| Integrity | chain_verify, checkpoint_created |

Policy notes:
- **Secret reveals are always logged**, with the reason captured in `metadata`. The value is never logged.
- **Reads are logged**, into the same tamper-evident chain, so the log answers "who looked at what." To keep it useful, granularity is defined: log opening a record (`record_view`), browsing a filtered list once (`list_view`, with the filter), and a search (`search`, with the query). Do not log pagination, refreshes, or each row of a list as separate events. Machine reads from the monitoring poll are not human access and stay out, as in section 5.
- Viewing the audit log is itself a `record_view`. This does not recurse, since writing a log entry is not a logged action.
- At this system's scale (1 or 2 people) the added read volume is small and the chain stays manageable.
- For the `secret` table, `changes` records non-sensitive facts only: the kind, the owner, the scheme version, and a hash of the ciphertext if useful for integrity. Never the plaintext, never the ciphertext bytes in full.

---

## 7. Verification

### Chain walk
Iterate entries in `seq` order. For each entry, recompute `entry_hash` from its canonical payload and stored `prev_hash`, and confirm it equals the stored `entry_hash` and equals the next entry's `prev_hash`. The first mismatch pinpoints the earliest tampered or corrupted entry.

### Anchor check
Confirm the chain head (and ideally each historical checkpoint) matches the signed `audit_checkpoint` values and the external copies. A valid chain whose head does not match the last signed checkpoint means the chain was rewritten after that checkpoint.

### Cadence
- Run the chain walk on a schedule (for example daily) and on demand from the dashboard.
- Create a signed checkpoint at intervals (for example every session, or every N entries, or daily). Signing uses a key the database does not hold: the administrator hardware key (WebAuthn-based signing) or an offline key kept with the recovery material from Annex A.
- The dashboard shows "chain verified through seq N, last signed checkpoint at T."

### Reference pseudocode

```python
import nacl.bindings as sodium

ZERO32 = b"\x00" * 32

def entry_hash(e, prev_hash):
    payload = b"".join(lp(x) for x in [
        e.seq, e.occurred_at_iso, e.actor_type, e.actor_operator_id,
        e.actor_username, e.session_id, e.source_ip, e.action,
        e.target_table, e.target_id, e.target_label,
        canonical_json(e.changes), canonical_json(e.metadata),
    ]) + prev_hash
    return sodium.crypto_generichash(payload, digest_size=32)

def lp(x):
    b = b"" if x is None else str(x).encode("utf-8")
    return len(b).to_bytes(4, "big") + b

def append_audit(db, fields):
    with db.transaction():
        db.advisory_xact_lock(AUDIT_LOCK_KEY)   # serialize appends
        head = db.fetch_head()                   # latest by seq, or None
        prev = head.entry_hash if head else ZERO32
        seq = (head.seq + 1) if head else 1
        e = build_entry(seq=seq, prev_hash=prev, **fields)
        e.entry_hash = entry_hash(e, prev)
        db.insert_audit_entry(e)
        # the data change is inserted in this same transaction

def verify_chain(db):
    prev = ZERO32
    for e in db.iter_entries_by_seq():
        if e.prev_hash != prev:
            return ("broken_link", e.seq)
        if entry_hash(e, e.prev_hash) != e.entry_hash:
            return ("altered_entry", e.seq)
        prev = e.entry_hash
    return check_against_latest_checkpoint(db, prev)
```

---

## 8. Retention

At this system's scale the log grows slowly (manual entry by 1 or 2 people plus a trickle of monitoring transitions). Keep all entries indefinitely. There is no rotation that deletes entries, since deletion would break the chain and defeat the purpose. If size ever matters, archive old entries to an append-only export and keep the chain head and checkpoints, rather than deleting.

---

## 9. Open points (deferred to Annex G, deployment)

- **External anchor target.** Where the signed checkpoints are copied: a separate hardened syslog host, an append-only file on a second machine, or printed copies with the recovery material. This is an infrastructure choice, resolved in Annex G.
- **Checkpoint signing key.** Administrator hardware key via WebAuthn signing, or an offline key stored with the Annex A recovery material. Resolved in Annex G.

Firm decisions (logged in the index): append-only enforced at the database role and by trigger, BLAKE2b-256 hash chain, same-transaction writes, advisory-lock ordering, monitoring telemetry kept out of the chain, secret plaintext never logged.

This annex resolves backlog item P-02 and adds backlog item P-10 for the anchoring infrastructure.
