"""Local-loop equivalence test for the `carrier_count` bundle.

Proves the full pinned pipeline end-to-end on synthetic contributors:

    keygen -> encode -> encrypt (N>=3) -> compute -> decrypt -> decode

and asserts, per docs/simulation_mode.md's oracle claim:

    decode(decrypt(compute(encrypt(encode(raw)))))  ==  cleartext aggregate

**bit-exact** (BFV, precision_tolerance 0), AND that the append-1 sentinel
decrypts to **exactly N** (docs/spec.md).

carrier_count differs from the flagship only in the client-side encoding: the
raw alt-allele dosage {0,1,2}/null is thresholded LOCALLY to a carrier indicator
{0,1} before encryption. The homomorphic circuit (additive fold) and the
correctness oracle (`_cleartext_aggregate`, which sums `encode(...)`) are the
same shape as the flagship — because encode now emits {0,1}, the same oracle
yields per-coordinate CARRIER counts (people carrying >=1 alt allele), not
allele dosages. That is exactly the registry-composability point (catalog §2).

The pure functions live in the author modules (server.py / local_project_owner.py
/ local_data_owner.py), grouped by role per docs/rfcs/0002. The numbered stage
files at the bundle root are kit-owned argparse shims that call these same
functions — so testing the functions directly exercises the identical logic the
shims (and the hosted worker, for compute) run. Run:

    uv --project signed/env run --group dev python -m pytest tests/    # from bundle root
    # or, with tenseal already importable:
    python -m pytest tests/

If TenSEAL cannot be imported the whole module skips with a clear reason (real
code, no pseudo-code — the skip is only for a machine that cannot install the
sealed dependency).
"""
from __future__ import annotations

import json
import pathlib
import random
import sys

import pytest

BUNDLE_ROOT = pathlib.Path(__file__).resolve().parent.parent / "signed"

# The author modules live at the bundle root (importable names, unlike the
# digit-prefixed shim files). Put the bundle root first on sys.path so
# `import server` resolves to THIS bundle's server.py.
sys.path.insert(0, str(BUNDLE_ROOT))

# The encrypted engine needs TenSEAL. Skip cleanly (not fail) if it is absent —
# but note this in the task's `unresolved` if it ever fires.
pytest.importorskip("tenseal", reason="TenSEAL not installed; sealed env not built")

import local_data_owner  # noqa: E402  (after sys.path insert)
import local_project_owner  # noqa: E402
import server  # noqa: E402


def _cleartext_aggregate(raw_vectors: list[list], length: int) -> list[int]:
    """The correctness oracle: sum encoded carrier vectors coordinate-wise.

    Identical shape to the flagship oracle; because `encode` thresholds dosage to
    a {0,1} carrier indicator, the summed result is the per-coordinate carrier
    count (participants carrying >=1 alt allele), not the allele dosage sum.
    """
    counts = [0] * length
    for raw in raw_vectors:
        for j, value in enumerate(local_data_owner.encode(raw, length)):
            counts[j] += value
    return counts


# HomomorphicEncryption.org coeff-modulus caps (max Σ coeff_mod_bit_sizes) per
# (poly_modulus_degree, security level). achieved(N, Σbits) = the strictest
# level whose cap Σbits still fits under. Mirrors the benchmark harness so the
# test can assert achieved == requested WITHOUT reading it back from SEAL (SEAL
# always validates at tc128 and cannot report tc192/tc256).
COEFF_MOD_CAPS = {
    8192: {128: 218, 192: 152, 256: 118},
    16384: {128: 438, 192: 305, 256: 237},
    32768: {128: 881, 192: 611, 256: 476},
}


def _achieved_security(poly_modulus_degree: int, coeff_mod_bit_sizes: list[int]) -> int:
    """Strictest HE security level (bits) a (N, Σbits) chain certifies."""
    total = sum(coeff_mod_bit_sizes)
    caps = COEFF_MOD_CAPS[poly_modulus_degree]
    for level in (256, 192, 128):  # strictest first
        if total <= caps[level]:
            return level
    raise AssertionError(
        f"Σ={total} exceeds the 128-bit cap {caps[128]} at N={poly_modulus_degree}"
    )


def _run_pipeline(raw_vectors: list[list], length: int, security: int = 128) -> dict:
    """keygen -> encode -> encrypt -> compute (server) -> decrypt -> decode."""
    secret_ctx, public_ctx = local_project_owner.keygen(security=security)

    # Local data-owner stages, once per contributor.
    ciphertexts = []
    for raw in raw_vectors:
        encoded = local_data_owner.encode(raw, length)
        ciphertexts.append(local_data_owner.encrypt(public_ctx, encoded))

    # The ONLY server-side stage: sum ciphertexts under the PUBLIC context.
    result_ct = server.compute(ciphertexts, public_ctx)

    # Local researcher stages: decrypt with the secret context, then decode.
    plain = local_project_owner.decrypt(secret_ctx, result_ct)
    return local_project_owner.decode(plain, length)


def test_encode_thresholds_dosage_to_carrier_indicator():
    """The distinguishing encoding: dosage {0,1,2}/null -> carrier {0,1}."""
    encoded = local_data_owner.encode([0, 1, 2, None], 4)
    assert encoded == [0, 1, 1, 0]  # dosage 2 -> carrier 1, null -> 0
    assert set(encoded) <= {0, 1}


def test_local_loop_matches_cleartext_and_fixtures():
    """The committed 4-contributor fixtures decode to the committed expected."""
    vectors_dir = BUNDLE_ROOT / "tests" / "vectors"
    expected = json.loads((BUNDLE_ROOT / "tests" / "expected" / "aggregate.json").read_text())
    length = expected["coordinates_length"]

    raw_vectors = [
        json.loads(path.read_text()) for path in sorted(vectors_dir.glob("*.json"))
    ]
    assert len(raw_vectors) >= 3, "need >=3 synthetic contributors"

    result = _run_pipeline(raw_vectors, length)

    # Sentinel recovers the EXACT contributor count.
    assert result["n_contributors"] == len(raw_vectors)
    assert result["n_contributors"] == expected["n_contributors"]

    # Encrypted aggregate == cleartext oracle == committed fixture, bit-exact.
    assert result["carrier_counts"] == _cleartext_aggregate(raw_vectors, length)
    assert result["carrier_counts"] == expected["carrier_counts"]
    assert result["carrier_rates"] == pytest.approx(
        expected["carrier_rates"], abs=0.0, rel=0.0
    )

    # A carrier count is a headcount: it can never exceed the contributor count.
    assert all(0 <= c <= result["n_contributors"] for c in result["carrier_counts"])


def test_local_loop_full_coordinate_length_random_cohort():
    """Exercise the manifest coordinate length (L=1000) with a seeded cohort."""
    length = 1000
    n_contributors = 5
    rng = random.Random(20260705)  # reproducible synthetic cohort
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(n_contributors)
    ]
    # Inject a couple of missing calls (null) to exercise the encode-as-0 path.
    raw_vectors[0][3] = None
    raw_vectors[2][17] = None

    result = _run_pipeline(raw_vectors, length)

    assert result["n_contributors"] == n_contributors  # sentinel == N, exactly
    assert result["carrier_counts"] == _cleartext_aggregate(raw_vectors, length)
    assert all(0 <= c <= n_contributors for c in result["carrier_counts"])


@pytest.mark.parametrize("security", [128, 192, 256])
def test_local_loop_bit_exact_at_every_security_level(security):
    """The full loop is bit-exact vs the cleartext oracle at 128/192/256-bit HE.

    Also asserts the harness-computed achieved level equals the requested level,
    so the SECURITY table's chain actually lands in the intended q-band (not a
    weaker one). If a level cannot be bit-exact at the table's params, that is a
    table bug — this test must FAIL, never be loosened.
    """
    length = 256
    n_contributors = 7
    rng = random.Random(0xC0FFEE + security)  # per-level reproducible cohort
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(n_contributors)
    ]
    # Exercise the missing-call (null -> 0) encode path at this level too.
    raw_vectors[1][5] = None
    raw_vectors[4][42] = None

    # The requested level must actually be certified by the generated context's
    # chain (achieved == requested), computed the same way the benchmark does.
    chain = local_project_owner.SECURITY[security]
    achieved = _achieved_security(local_project_owner.DEFAULT_POLY_MODULUS_DEGREE, chain)
    assert achieved == security, (
        f"requested {security}-bit but chain {chain} (Σ={sum(chain)}) certifies "
        f"{achieved}-bit at N={local_project_owner.DEFAULT_POLY_MODULUS_DEGREE}"
    )

    result = _run_pipeline(raw_vectors, length, security=security)

    # Sentinel recovers EXACTLY N at this security level.
    assert result["n_contributors"] == n_contributors
    # Encrypted aggregate == cleartext oracle, bit-for-bit (BFV, tolerance 0).
    assert result["carrier_counts"] == _cleartext_aggregate(raw_vectors, length)
    # Headcount invariant holds regardless of the modulus chain.
    assert all(0 <= c <= n_contributors for c in result["carrier_counts"])


def test_sentinel_tracks_dropped_upload():
    """Dropping one upload yields N-1 (the sentinel is a live contributor count)."""
    length = 32
    rng = random.Random(7)
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(6)
    ]

    full = _run_pipeline(raw_vectors, length)
    dropped = _run_pipeline(raw_vectors[:-1], length)

    assert full["n_contributors"] == 6
    assert dropped["n_contributors"] == 5
    # And the aggregate really lost exactly the dropped contributor's indicators.
    last_encoded = local_data_owner.encode(raw_vectors[-1], length)
    assert [
        full_c - dropped_c
        for full_c, dropped_c in zip(full["carrier_counts"], dropped["carrier_counts"])
    ] == last_encoded
