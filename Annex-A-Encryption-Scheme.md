# Annex A: Secret Encryption Scheme and Master Key Handling

**Companion document to the preliminary design of the credentials and asset system.**
**Status:** technical reference specification, for planning with Cowork.

---

## 1. The most important thing first

The real security of this system does not come from picking a more exotic cipher. It comes from three things, in this order:

1. **A slow, memory-hard key derivation (Argon2id).** This is where your 2 to 8 seconds are spent. It is what makes guessing the passphrase by brute force cost centuries.
2. **A second factor that does NOT live in the database.** A key file (keyfile) or the server TPM. That way a stolen database backup is useless on its own.
3. **A strong passphrase.** Long, unique, randomly generated. Without this, the rest loses its strength.

The data encryption itself is already solved with XChaCha20-Poly1305, 256 bits. It takes microseconds. That is not where you gain security by spending time.

Key performance detail: the cost of the 2 to 8 seconds is paid **once, at session unlock**, not on every query. Once unlocked, revealing a secret is instant.

---

## 2. Threat model (what we are defending against)

| Threat | Primary defense |
|---|---|
| Disk or backup theft | Encryption at rest. The master key is not in the database |
| Brute force of the passphrase with the database stolen | Heavy Argon2id plus a second factor outside the database |
| Backup stolen without the keyfile/TPM | Undecryptable. Missing key material that was not in the backup |
| Memory dump with the session open | Idle auto-lock, locked memory (mlock), key wiped on logout |
| Viewer role trying to see secrets | Secrets masked, revealing requires Administrator and reauthentication |

---

## 3. Data encryption (symmetric layer)

- **Algorithm:** XChaCha20-Poly1305 (authenticated encryption, AEAD). 256-bit key, 192-bit nonce, 128-bit tag.
- **Why this one:** the 192-bit nonce lets you use random nonces with no reuse risk, which removes a whole class of mistakes. It is modern, fast, and heavily audited (libsodium). AES-256-GCM is an equally valid alternative if you prefer AES.
- **Nonce:** random and unique per encryption operation. Stored next to the ciphertext, it is not secret.
- **Associated data (AAD):** each secret is encrypted with the ciphertext bound to the record it belongs to (for example `account_id` plus field name). That way a ciphertext cannot be copied from one record to another without the verification failing.

On "the best encryption possible": a 256-bit symmetric cipher is already considered quantum resistant for practical purposes. No post-quantum cryptography is needed here, because everything is local symmetric encryption, not key exchange. Chaining several ciphers (cascade style) sounds stronger but adds complexity and error surface with no real gain over a well-chosen AEAD. The professional recommendation is a single solid, well-implemented AEAD.

---

## 4. Key hierarchy (envelope encryption)

Three levels. This lets you rotate keys without re-encrypting everything, and limits the damage of any single exposure.

```
Administrator passphrase
        │  (Argon2id, 2 to 8 s)
        ▼
   KWK  (key wrapping key)  ── combined with the second factor (keyfile or TPM)
        │  (authenticated encryption)
        ▼
   MK   (master key, 256 bits, only in memory after unlock)
        │  (wraps each DEK)
        ▼
  DEK   (one random data key per secret)
        │  (XChaCha20-Poly1305)
        ▼
  Encrypted secret in the database
```

- **MK (Master Key):** 256-bit master key, generated once at install. Never stored in plaintext. Stored wrapped (encrypted) by the KWK.
- **KWK (Key Wrapping Key):** derived from the passphrase with Argon2id, then combined with the second factor. Never stored. Recomputed at unlock.
- **DEK (Data Encryption Key):** a distinct random key for each secret. Encrypts the secret. Stored wrapped by the MK, next to the ciphertext.

Operational benefit: changing the passphrase only re-wraps the MK (one Argon2id, fast). Rotating the MK only re-wraps the DEKs (tiny operations). The secrets themselves never need re-encryption.

---

## 5. Protecting the master key at rest (the core)

This is where the 2 to 8 seconds go.

### 5.1 Argon2id
- **Type:** Argon2id (resistant to both GPU attacks and side-channel attacks).
- **Starting parameters** (for a server with enough RAM):
  - Memory: 1 to 2 GiB
  - Iterations (time cost): calibrated up to the target time
  - Parallelism: equal to the number of physical cores (for example 4)
- **Do not set the parameters by guessing. Calibrate them on the real server** until you hit the target time (I suggest aiming at 4 seconds, inside your 2 to 8 range, leaving headroom).
- Because the system enforces **one session at a time**, there will almost never be two unlocks in parallel, so you can use high memory without fear of exhausting the server RAM.
- Store the parameters used next to the wrapped MK. That way, in the future, with faster hardware, you recalibrate upward and re-wrap without breaking anything.

### 5.2 Second factor outside the database
Combine the Argon2id output with a secret that is not in the database or its backups. Pick one or both:

- **Keyfile:** a 256-bit high-entropy file, stored outside the database backup path, with strict permissions. The final KWK is derived by combining Argon2id(passphrase) with the keyfile (via HKDF). Result: a stolen database backup, without the keyfile, is undecryptable.
- **Server TPM 2.0:** seal a secret in the TPM so it can only be recovered on that machine. This ties decryption to the server hardware. It fits your local model well and is zero cost if the server has a TPM.

Optional premium: if later you use WebAuthn with the PRF extension (hmac-secret) on a hardware key or compatible platform authenticator, decryption can require the physical tap of the authenticator. It is among the strongest options for this, but it ties decryption to that device, so it demands careful recovery backups.

### 5.3 Unlock flow
1. The administrator logs in (after the VPN) and provides the passphrase and the second factor.
2. Argon2id(passphrase, salt, parameters) produces key material. This takes the 2 to 8 seconds.
3. It is combined with the keyfile or the TPM secret via HKDF, producing the KWK.
4. The KWK decrypts the wrapped MK. If the authenticated-encryption verification fails, the unlock is rejected.
5. The MK stays in protected memory for the session.

---

## 6. Where to spend the 2 to 8 seconds: two models

Since you tolerate latency, you have two models. I recommend the first as the default.

**Model A, recommended: derive at unlock, MK in protected memory.**
- Argon2id runs once at login.
- The MK lives in locked memory while the session is active.
- Each secret read or write is instant.
- Idle auto-lock (for example 5 minutes) that wipes the MK from memory.
- To reveal a specific secret, also require a second-factor tap, which is fast.

**Model B, maximum paranoia: derive on every operation, ephemeral MK.**
- The MK is not kept in memory between operations.
- Each time you reveal a secret, you re-enter passphrase and second factor, and it is re-derived (another 2 to 8 seconds).
- Minimizes the time the key lives in memory, which limits the damage of a memory dump.
- Cost: heavier UX. Reasonable only if you reveal secrets rarely.

Important technical note: if the MK is in memory (Model A), a memory dump with the session open exposes everything, no matter how slow Argon2id is. That is why Model B exists. The default A is the sane balance for 1 or 2 administrators.

---

## 7. Key handling in memory

- Use libsodium secure memory (`sodium_malloc`, `sodium_mlock`) to keep the key from being paged out to swap.
- Wipe the key with `sodium_memzero` on logout, on idle timeout, and on process shutdown.
- Disable core dumps for the process.
- Never log the key or the passphrase, not in logs and not in error messages.

---

## 8. Recovery and anti-lockout (do not skip this)

The stronger the scheme, the easier it is to lock yourself out permanently. This system is the single point of access for the company, so recovery is mandatory.

- **Printed recovery key.** At install, generate a high-entropy recovery key that can also wrap the MK. Print it and store it in a physical safe. It lets you recover if the passphrase is forgotten or the keyfile is damaged.
- **Keyfile backup.** If you use a keyfile, keep a copy in a separate, physically secure place, different from where database backups go.
- **Secret sharing (Shamir), optional.** You can split the recovery key into several shares and require, say, 2 of 3 to reconstruct it. Useful if you want no single person to be able to recover alone. It adds complexity, evaluate it for your team of 1 or 2.
- Test recovery at least once before loading real data.

---

## 9. Rotation and versioning

- **Passphrase change:** re-derive the KWK and re-wrap the MK. One Argon2id operation.
- **MK rotation:** generate a new MK, re-wrap all DEKs. Tiny operations.
- **Secret rotation:** when a password changes, new DEK and new ciphertext.
- **Scheme versioning:** store a version identifier and the Argon2id parameters next to each piece of data. That way you can raise parameters or change algorithm in the future without breaking the old data.

---

## 10. Suggested database schema

Vault configuration (a single row):
- `scheme_version`
- `kdf_algo`, `kdf_salt`, `kdf_memory`, `kdf_iterations`, `kdf_parallelism`
- `mk_wrapped`, `mk_nonce`
- reference to the second factor (keyfile id or TPM handle, never the keyfile itself)

Per secret field:
- `scheme_version`
- `dek_wrapped`, `dek_nonce`
- `ciphertext`, `nonce`
- AAD context (or derived from the record)

---

## 11. Reference pseudocode (Python)

Illustrative, so Cowork has a starting point. Uses `argon2-cffi` and `PyNaCl` (libsodium), both free.

```python
import time
import nacl.bindings as sodium
from argon2.low_level import hash_secret_raw, Type

# ---------- Argon2id calibration (run on the real server) ----------
def calibrate_argon2(target_sec=4.0, memory_kib=1048576, parallelism=4):
    # Raise iterations until the target time is reached.
    salt = sodium.randombytes(16)
    iterations = 2
    while True:
        t0 = time.perf_counter()
        hash_secret_raw(b"test", salt, time_cost=iterations,
                        memory_cost=memory_kib, parallelism=parallelism,
                        hash_len=32, type=Type.ID)
        if time.perf_counter() - t0 >= target_sec:
            return {"memory_kib": memory_kib, "iterations": iterations,
                    "parallelism": parallelism}
        iterations += 1

# ---------- Derive KWK from passphrase plus keyfile ----------
def derive_kwk(passphrase: bytes, salt: bytes, params: dict, keyfile: bytes) -> bytes:
    base = hash_secret_raw(passphrase, salt,
                           time_cost=params["iterations"],
                           memory_cost=params["memory_kib"],
                           parallelism=params["parallelism"],
                           hash_len=32, type=Type.ID)
    # Combine with the second factor (HKDF via libsodium BLAKE2b).
    return sodium.crypto_generichash(base + keyfile, digest_size=32)

# ---------- Encrypt a secret with its own DEK, wrapped by the MK ----------
def encrypt_secret(mk: bytes, secret: bytes, aad: bytes):
    dek = sodium.randombytes(32)
    nonce = sodium.randombytes(24)  # XChaCha20 uses a 24-byte nonce
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(secret, aad, nonce, dek)
    # Wrap the DEK with the MK.
    dek_nonce = sodium.randombytes(24)
    dek_wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(dek, b"", dek_nonce, mk)
    sodium.sodium_memzero(dek)
    return {"ciphertext": ct, "nonce": nonce,
            "dek_wrapped": dek_wrapped, "dek_nonce": dek_nonce}

# ---------- Decrypt ----------
def decrypt_secret(mk: bytes, row: dict, aad: bytes) -> bytes:
    dek = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        row["dek_wrapped"], b"", row["dek_nonce"], mk)
    secret = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        row["ciphertext"], aad, row["nonce"], dek)
    sodium.sodium_memzero(dek)
    return secret
```

Notes on the pseudocode: treat every decryption error as a rejection (the tag check fails if anything was tampered with). Lock the `mk` buffers in memory (`mlock`) and wipe them with `memzero` when the session ends. Calibrate once and store the parameters.

---

## 12. Summary of encryption decisions

| Topic | Decision |
|---|---|
| Data encryption | XChaCha20-Poly1305, 256 bits, with AAD bound to the record |
| Key derivation | Argon2id, 1 to 2 GiB of memory, calibrated to about 4 seconds |
| Hierarchy | Passphrase to KWK to MK to per-secret DEK (envelope encryption) |
| Second factor | Keyfile outside backups, or server TPM. WebAuthn PRF as a future premium |
| Where latency goes | At unlock (once per session), not on every query |
| Memory | mlock, memzero, idle auto-lock, no core dumps |
| Recovery | Printed recovery key in a safe, keyfile backup, Shamir optional |
| Post-quantum | Not needed. 256-bit symmetric is already enough |

---

## 13. Multiple administrators (per-administrator key wrapping)

The system has two Administrators who can both reveal secrets. There is still **one master key (MK)** for the whole vault, so both decrypt the same data. The MK is wrapped once per Administrator and never shared in the clear. This replaces the single wrapped-MK row from section 10 with one row per Administrator.

For each Administrator i: `KWK_i = HKDF( Argon2id(passphrase_i, salt_i, params_i), second_factor_i )`, and the MK is encrypted under `KWK_i` to produce that admin's wrapped copy.

**Table `vault_key_holder`** (one row per Administrator):

| Field | Type | Notes |
|---|---|---|
| id | uuid PK | |
| operator_id | uuid FK operator | the Administrator |
| kdf_salt | bytea | per-admin |
| kdf_memory, kdf_iterations, kdf_parallelism | integer | per-admin calibration |
| mk_wrapped | bytea | MK encrypted under this admin's KWK |
| mk_nonce | bytea | |
| second_factor_ref | text | keyfile id or TPM handle for this admin |
| created_at | timestamptz | |
| created_by | uuid FK operator | the enrolling admin |

**Unlock:** the logging-in Administrator uses their own row, running their own Argon2id (their own 2 to 8 seconds).

**Enrolling a second Administrator:** an existing Administrator, whose session already holds the MK in memory, wraps the MK under the newcomer's KWK and writes their `vault_key_holder` row. The newcomer never sees the raw MK, they only set their passphrase and second factor.

**Removing an Administrator:** delete their `vault_key_holder` row so they can no longer unlock, then **rotate the MK** (new MK, re-wrap all DEKs, re-wrap for remaining admins). Rotation matters: without it, a wrapped copy the removed admin might have kept, plus their passphrase, could still decrypt old data.

The printed recovery key from section 8 stays an independent wrap of the MK, so the vault is still recoverable even if every Administrator credential is lost.
