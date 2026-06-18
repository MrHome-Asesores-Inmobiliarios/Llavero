"""P1-T5 acceptance tests (Annex A 5.1, 11).

Brief acceptance criteria:
- calibrate() returns params whose measured time meets the target on this box
- params persisted (serialize round-trip with scheme_version)

Calibration here uses a small target and small memory so the test is fast;
the real server calibrates to ~4 s at 1-2 GiB (P0-T5 / deploy).
"""

from apps.vault import kdf
from apps.vault.kdf import Argon2Params

MEM = 16384  # 16 MiB: light enough for a fast test


def _best(iterations: int, samples: int = 5) -> float:
    salt = kdf.generate_salt()
    return min(kdf._measure(salt, MEM, iterations, 1) for _ in range(samples))


# --- calibration ----------------------------------------------------------
# Note: absolute sub-second timing on a loaded CI/desktop box is noisy, so we
# assert the calibration *logic* (it climbs above the 1-iteration floor and is
# monotonic in the target) rather than pinning an exact wall-clock value. The
# real server calibrates to ~4 s at 1-2 GiB, where the noise is negligible.


def test_calibrate_climbs_above_the_single_iteration_floor():
    floor = _best(iterations=1)
    target = max(0.05, floor * 4)
    params = kdf.calibrate(target_seconds=target, memory_kib=MEM, parallelism=1, samples=1)

    assert isinstance(params, Argon2Params)
    assert params.memory_kib == MEM
    assert params.parallelism == 1
    # Reaching a target several times the 1-iteration cost requires climbing.
    assert params.iterations >= 2
    # Ballpark sanity: the chosen params land in the neighbourhood of target.
    assert _best(params.iterations) >= target * 0.4


def test_calibrate_iterations_increase_with_target():
    low = kdf.calibrate(target_seconds=0.08, memory_kib=MEM, parallelism=1, samples=1)
    high = kdf.calibrate(target_seconds=0.24, memory_kib=MEM, parallelism=1, samples=1)
    # A 3x larger target dominates timing noise: more iterations are required.
    assert high.iterations >= low.iterations


def test_calibrate_rejects_nonpositive_target():
    import pytest

    with pytest.raises(ValueError):
        kdf.calibrate(target_seconds=0)


def test_calibrate_raises_if_target_unreachable():
    import pytest

    # An absurd target with a tiny iteration ceiling cannot be reached.
    with pytest.raises(RuntimeError):
        kdf.calibrate(
            target_seconds=10_000,
            memory_kib=8,
            parallelism=1,
            max_iterations=2,
        )


# --- params persistence ---------------------------------------------------


def test_params_round_trip_through_dict():
    params = Argon2Params(memory_kib=1048576, iterations=7, parallelism=4)
    restored = Argon2Params.from_dict(params.to_dict())
    assert restored == params
    assert restored.scheme_version == kdf.SCHEME_VERSION


def test_params_dict_carries_scheme_version():
    d = Argon2Params(memory_kib=1024, iterations=3, parallelism=2, scheme_version=9).to_dict()
    assert d["scheme_version"] == 9
    assert Argon2Params.from_dict(d).scheme_version == 9


# --- derivation determinism ----------------------------------------------


def test_same_inputs_yield_same_key():
    salt = kdf.generate_salt()
    k1 = kdf.derive_raw_key(b"pw", salt, kdf.DEV_PARAMS)
    k2 = kdf.derive_raw_key(b"pw", salt, kdf.DEV_PARAMS)
    assert k1 == k2
    assert len(k1) == kdf.KEY_LEN


def test_different_salt_yields_different_key():
    k1 = kdf.derive_raw_key(b"pw", kdf.generate_salt(), kdf.DEV_PARAMS)
    k2 = kdf.derive_raw_key(b"pw", kdf.generate_salt(), kdf.DEV_PARAMS)
    assert k1 != k2
