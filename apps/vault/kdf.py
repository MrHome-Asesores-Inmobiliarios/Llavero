"""Argon2id key derivation and calibration (Annex A 5.1, 11).

This module owns *only* the Argon2id primitive and its calibration. The
envelope (combining the Argon2id output with the second factor via HKDF to
form the KWK, then MK and per-secret DEKs) is built in P1-T6.

Calibration target on the real server: ~4 s, 1-2 GiB memory,
parallelism = physical cores (Annex A 5.1). That must be run on the hardened
server (P0-T5) and the resulting params persisted next to the wrapped MK
(vault_key_holder, P1-T9). On the dev box we use the lighter DEV_PARAMS with
throwaway data only.

No secret material is ever logged here.
"""

import time
from dataclasses import dataclass

import nacl.utils
from argon2.low_level import Type, hash_secret_raw

ARGON2_TYPE = Type.ID
KEY_LEN = 32  # 256-bit derived key material
SALT_LEN = 16

# Default scheme version; must track settings.LLAVERO_ARGON2_SCHEME_VERSION.
SCHEME_VERSION = 1


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id parameters, persisted alongside the wrapped MK (Annex A 9, 10).

    Stored so that, on faster hardware, calibration can be raised and the MK
    re-wrapped without breaking existing data (scheme_version).
    """

    memory_kib: int
    iterations: int
    parallelism: int
    scheme_version: int = SCHEME_VERSION

    def to_dict(self) -> dict:
        return {
            "memory_kib": self.memory_kib,
            "iterations": self.iterations,
            "parallelism": self.parallelism,
            "scheme_version": self.scheme_version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Argon2Params":
        return cls(
            memory_kib=int(data["memory_kib"]),
            iterations=int(data["iterations"]),
            parallelism=int(data["parallelism"]),
            scheme_version=int(data.get("scheme_version", SCHEME_VERSION)),
        )


# Dev-grade params (throwaway data ONLY — never ship to production).
DEV_PARAMS = Argon2Params(memory_kib=65536, iterations=2, parallelism=1)


def generate_salt() -> bytes:
    """A fresh 16-byte salt (not secret; stored with the wrapped MK)."""
    return nacl.utils.random(SALT_LEN)


def derive_raw_key(passphrase: bytes, salt: bytes, params: Argon2Params) -> bytes:
    """Run Argon2id, returning 32 bytes of key material.

    This is the slow step (the 2-8 s at unlock on the real server). The caller
    (P1-T6) combines this output with the second factor to form the KWK.
    """
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=params.iterations,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=ARGON2_TYPE,
    )


def _measure(salt: bytes, memory_kib: int, iterations: int, parallelism: int) -> float:
    t0 = time.perf_counter()
    hash_secret_raw(
        secret=b"calibration-probe",
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=ARGON2_TYPE,
    )
    return time.perf_counter() - t0


def _best_measure(
    salt: bytes, memory_kib: int, iterations: int, parallelism: int, samples: int
) -> float:
    """Fastest of ``samples`` derivations.

    We calibrate against the *best case* (minimum time): the cost must meet the
    target even on the machine's fastest run, since that is the case that
    favours an attacker. Under real load the derivation only gets slower.
    """
    return min(_measure(salt, memory_kib, iterations, parallelism) for _ in range(samples))


def calibrate(
    target_seconds: float = 4.0,
    memory_kib: int = 1048576,
    parallelism: int = 4,
    *,
    max_iterations: int = 1000,
    samples: int = 3,
    scheme_version: int = SCHEME_VERSION,
) -> Argon2Params:
    """Raise the iteration count until the best-case derivation hits the target.

    Run this on the *real* hardware so the cost matches the deployment box
    (Annex A 5.1: "do not set the parameters by guessing"). Memory and
    parallelism are fixed inputs; iterations is the calibrated dimension.
    """
    if target_seconds <= 0:
        raise ValueError("target_seconds must be positive")

    salt = generate_salt()
    iterations = 1
    while iterations <= max_iterations:
        best = _best_measure(salt, memory_kib, iterations, parallelism, samples)
        if best >= target_seconds:
            return Argon2Params(
                memory_kib=memory_kib,
                iterations=iterations,
                parallelism=parallelism,
                scheme_version=scheme_version,
            )
        iterations += 1

    raise RuntimeError(
        f"Could not reach {target_seconds}s within {max_iterations} iterations "
        f"at memory={memory_kib} KiB; raise memory or lower the target."
    )
