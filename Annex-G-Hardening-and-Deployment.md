# Annex G: Hardening and Deployment

**Companion to the preliminary design and to Annexes A, B, C, D, and F.** Defines where the system runs, how it is locked down, how remote access works, the vault second factor, and where the signed audit checkpoints are anchored. Closes the keyfile-versus-TPM choice (P-01) and the audit anchoring choice (P-10).

---

## 1. Topology and exposure

- One on-prem server (VM or physical) holding the app and PostgreSQL on the same box. For 1 to 2 users this is simpler and safer than splitting them.
- The app binds to localhost. A reverse proxy on the same host terminates TLS on the internal interface only. **Nothing is exposed to the internet.**
- The server sits in a management segment, firewalled by the WatchGuard.
- Outbound egress is restricted to exactly what Annex F needs: HTTPS to Microsoft Graph, and LAN or tunnel reach to the gear. Nothing else leaves.

---

## 2. Server and OS hardening

- Minimal Linux install (Ubuntu Server 24.04 or similar), no desktop, only required packages.
- Default-deny firewall (nftables or ufw): inbound limited to the reverse proxy port from the internal or VPN range, and SSH from the management range only.
- SSH locked down: key-only, no root login, no password auth, restricted source addresses.
- Automatic security updates enabled. A planned cadence for non-security updates.
- AppArmor or SELinux enforcing.
- Time sync with chrony. Accurate time matters for audit timestamps, certificate validation, and Graph auth.
- Swap disabled, or encrypted swap, so the master key cannot be paged to disk in the clear. This pairs with the `mlock` from Annex A.
- Core dumps disabled process-wide, also per Annex A.

---

## 3. Disk encryption and TPM

- Full disk encryption with LUKS2, so a stolen disk is opaque.
- Unlock bound to the server TPM 2.0 with a boot PIN (`systemd-cryptenroll --tpm2-device`). TPM plus PIN balances unattended reboots against the risk of a stolen powered-off machine. A boot passphrase is the stricter alternative if you can attend reboots.
- This disk layer is independent of the vault. Even with the disk unlocked, the encrypted secrets still require the vault master key.

---

## 4. Vault second factor (closes P-01)

Decision: **TPM 2.0 sealing** as the second factor that combines with each administrator's Argon2id output (Annex A, section 5.2).

- A secret is sealed to the server TPM so it can only be recovered on this machine. Combined with the admin passphrase, this means a stolen database backup, without the physical server, cannot be brute-forced at all.
- Hardware-binding downside is fully covered by the **printed recovery key** (Annex A, section 8): on hardware failure you restore elsewhere with the recovery key, then re-seal to the new TPM.
- **Keyfile is the fallback** if the server has no usable TPM 2.0. Same role, kept off the backup path, but portable and therefore copyable, so slightly weaker.

Confirm the server has TPM 2.0 (most modern hardware does). That is the only thing standing between the recommended path and the fallback.

---

## 5. Application and database deployment

- The app runs as a non-root service user under a hardened systemd unit: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `MemoryDenyWriteExecute`, a `SystemCallFilter`, and `LimitCORE=0`.
- PostgreSQL listens on localhost or a unix socket only, with scram-sha-256 auth.
- Database roles enforce the append-only audit log from Annex B: the app role has INSERT and SELECT on the audit tables and no UPDATE or DELETE, schema changes use a separate migration role, and the delete-blocking trigger stays as defense in depth.
- The master key is held in `mlock`ed memory, wiped on lock and shutdown, never logged (Annex A).
- TLS on the reverse proxy uses an internal CA certificate. The app is never reached except through it.

---

## 6. Remote access

- From outside, the existing WatchGuard SSL VPN or the MikroTik tunnels, then the internal address of the app. No new exposure.
- Enable MFA on the VPN itself as the outer layer. The app then adds its own WebAuthn or TOTP as the inner layer (Annex D), and the Administrator unlock adds the vault passphrase. Three independent layers before a secret can be revealed.

---

## 7. Audit anchoring (closes P-10)

The signed external checkpoints from Annex B are made concrete here.

- **Signing key:** the Administrator WebAuthn credential. The head hash is signed as the authenticator challenge, so the private key never leaves the authenticator (Windows Hello TPM-backed, or a hardware key) and is never on the server. The server stores only the public key and the signed assertion, and verifies with it. Forging history would require the physical authenticator. An offline Ed25519 key is the alternative if you want fully unattended signing.
- **Anchor target:** each signed checkpoint is copied to a separate internal host in an append-only store the app can write to but not modify or delete, and a periodic copy is printed and kept in the safe with the recovery key. Two independent copies the database process cannot rewrite.
- **Cadence:** a checkpoint at each session end and at least daily.
- The same separate host also receives shipped host and application logs, so a compromise of the main server cannot quietly erase its own traces.

---

## 8. Patching, monitoring, and egress

- Security patches automatic, the rest on a planned cadence with a reboot window.
- Host monitoring and SSH brute-force protection (fail2ban or equivalent).
- Egress firewalled to Graph endpoints plus LAN and tunnels, matching Annex F.
- Host logs shipped to the separate host from section 7.

---

## 9. Disaster recovery posture

- The vault factor is TPM-bound to this server, so recovery to new hardware runs through the printed recovery key: restore the database from backup (Annex H), unlock with the recovery key, re-seal to the new TPM, re-enroll the administrators.
- The recovery key in the safe is the single linchpin of DR. Test the full restore before going live (Annex H).

---

## 10. Open points

1. **TPM 2.0 presence.** Confirm the server has it. If not, the vault second factor falls back to a keyfile (section 4).
2. **Separate anchoring and log host.** Confirm one exists or provision a small one. It is what makes the audit log and host logs resistant to a compromise of the main server.
3. **Disk unlock mode.** TPM plus PIN by default, or a boot passphrase if you accept attending reboots.

This annex resolves backlog items P-01, P-07, and P-10, and adds backlog item P-14 for the items above.
