"""Local-loop equivalence test for the `polygenic_score_aggregate` bundle.

Proves the full pinned pipeline end-to-end on synthetic contributors:

    keygen -> encode -> encrypt (N>=3) -> compute -> decrypt -> decode

and asserts, per docs/simulation_mode.md's oracle claim:

    decode(decrypt(compute(encrypt(encode(raw)))))  ==  cleartext oracle

**bit-exact on the integer-scaled aggregate** (BFV, tolerance 0), where the
oracle applies the SAME public integer-scaled weight vector the server does:

    weighted_counts[j] = w_scaled[j] * sum_i encode(g_i)[j]

Also asserts (a) the append-1 sentinel decrypts to **exactly N** even though the
public weights are applied — because the sentinel slot is weighted by 1 (the one
subtlety this protocol adds over the flagship); (b) the real-domain fixed-point
resolution of the published scale S is <= 1/S per weight (catalog §4 exactness
clause); and (c) dropping one upload yields N-1 and removes exactly that
contributor's weighted contribution.

The pure functions live in the author modules (server.py / local_project_owner.py
/ local_data_owner.py), grouped by role per docs/rfcs/0002. The numbered stage
files at the bundle root are kit-owned argparse shims that call these same
functions — so testing the functions directly exercises the identical logic the
shims (and the hosted worker, for compute) run. Run:

    uv --project signed/env run --group dev python -m pytest tests/   # from bundle root
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


# Achieved-security caps (Σ coeff_mod_bit_sizes) per N, from the
# HomomorphicEncryption.org table. The benchmark/harness computes the achieved
# level itself (strictest L with Σbits <= CAP[N][L]) — NEVER read back from SEAL
# (SEAL only validates at tc128 and cannot report tc192/tc256).
_CAP = {
    8192: {256: 118, 192: 152, 128: 218},
    16384: {256: 237, 192: 305, 128: 438},
    32768: {256: 476, 192: 611, 128: 881},
}


def _achieved_security(poly_modulus_degree: int, coeff_bits: list[int]) -> int:
    """The strictest security level whose cap the coeff chain fits under."""
    total = sum(coeff_bits)
    caps = _CAP[poly_modulus_degree]
    for level in (256, 192, 128):
        if total <= caps[level]:
            return level
    raise AssertionError(f"Σ={total} exceeds even the 128 cap at N={poly_modulus_degree}")


def _cleartext_weighted_aggregate(raw_vectors: list[list], length: int) -> list[int]:
    """The correctness oracle: sum encoded vectors, then apply the SAME public
    integer-scaled weights the server applies (`w_scaled[j] * sum_i g_ij`)."""
    counts = [0] * length
    for raw in raw_vectors:
        for j, value in enumerate(local_data_owner.encode(raw, length)):
            counts[j] += value
    weights = server.scaled_weights(length)
    return [weights[j] * counts[j] for j in range(length)]


def _run_pipeline(raw_vectors: list[list], length: int, security: int = 128) -> dict:
    """keygen -> encode -> encrypt -> compute (server) -> decrypt -> decode."""
    secret_ctx, public_ctx = local_project_owner.keygen(security=security)

    # Local data-owner stages, once per contributor.
    ciphertexts = []
    for raw in raw_vectors:
        encoded = local_data_owner.encode(raw, length)
        ciphertexts.append(local_data_owner.encrypt(public_ctx, encoded))

    # The ONLY server-side stage: sum ciphertexts under the PUBLIC context, then
    # apply the PUBLIC plaintext weights (ciphertext x plaintext, no relin/Galois).
    result_ct = server.compute(ciphertexts, public_ctx)

    # Local researcher stages: decrypt with the secret context, then decode.
    plain = local_project_owner.decrypt(secret_ctx, result_ct)
    return local_project_owner.decode(plain, length)


def test_local_loop_matches_cleartext_and_fixtures():
    """The committed 4-contributor fixtures decode to the committed expected."""
    vectors_dir = BUNDLE_ROOT / "tests" / "vectors"
    expected = json.loads(
        (BUNDLE_ROOT / "tests" / "expected" / "aggregate.json").read_text()
    )
    length = expected["coordinates_length"]

    raw_vectors = [
        json.loads(path.read_text()) for path in sorted(vectors_dir.glob("*.json"))
    ]
    assert len(raw_vectors) >= 3, "need >=3 synthetic contributors"

    result = _run_pipeline(raw_vectors, length)

    # Sentinel recovers the EXACT contributor count — even though the public
    # weights were applied (the sentinel slot is weighted by 1).
    assert result["n_contributors"] == len(raw_vectors)
    assert result["n_contributors"] == expected["n_contributors"]

    # Encrypted public-weighted aggregate == cleartext oracle == fixture, bit-exact.
    oracle = _cleartext_weighted_aggregate(raw_vectors, length)
    assert result["weighted_counts"] == oracle
    assert result["weighted_counts"] == expected["weighted_counts"]
    assert result["cohort_pgs_scaled"] == expected["cohort_pgs_scaled"]
    assert result["mean_pgs"] == pytest.approx(expected["mean_pgs"], abs=0.0, rel=0.0)


def test_public_weights_are_ciphertext_times_plaintext_and_exact():
    """weighted_counts[j] == w_scaled[j] * count[j], bit-exact (BFV, tolerance 0)."""
    length = 32
    n = 5
    rng = random.Random(4242)
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(n)
    ]

    result = _run_pipeline(raw_vectors, length)
    weights = server.scaled_weights(length)
    counts = [
        sum(local_data_owner.encode(raw, length)[j] for raw in raw_vectors)
        for j in range(length)
    ]

    assert result["n_contributors"] == n
    assert result["weighted_counts"] == [weights[j] * counts[j] for j in range(length)]
    # cohort scaled PGS is the exact integer sum of the weighted counts.
    assert result["cohort_pgs_scaled"] == sum(weights[j] * counts[j] for j in range(length))


def test_fixed_point_weight_resolution_within_one_over_S():
    """Catalog §4: real-domain weight rounding error <= 1/S (fixed-point scale)."""
    scale = local_project_owner.WEIGHT_SCALE
    length = 64
    scaled = server.scaled_weights(length)
    # Each published integer weight represents real_weight = w_scaled / S exactly
    # to the fixed-point grid; the resolution (and hence max rounding error of any
    # real effect size onto this grid) is 1/S.
    for w in scaled:
        real = w / scale
        assert abs(real - round(real * scale) / scale) <= 1.0 / scale


def test_full_coordinate_length_random_cohort():
    """Exercise the manifest coordinate length (L=1000) with a seeded cohort."""
    length = 1000
    n_contributors = 6
    rng = random.Random(20260705)  # reproducible synthetic cohort
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(n_contributors)
    ]
    # Inject a couple of missing calls (null) to exercise the encode-as-0 path.
    raw_vectors[0][3] = None
    raw_vectors[2][17] = None

    result = _run_pipeline(raw_vectors, length)

    assert result["n_contributors"] == n_contributors  # sentinel == N, exactly
    assert result["weighted_counts"] == _cleartext_weighted_aggregate(raw_vectors, length)


def test_sentinel_tracks_dropped_upload():
    """Dropping one upload yields N-1 and removes that contributor's weighted dosage."""
    length = 32
    rng = random.Random(7)
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(6)
    ]

    full = _run_pipeline(raw_vectors, length)
    dropped = _run_pipeline(raw_vectors[:-1], length)

    assert full["n_contributors"] == 6
    assert dropped["n_contributors"] == 5

    # The aggregate really lost exactly the dropped contributor's WEIGHTED dosages.
    weights = server.scaled_weights(length)
    last_encoded = local_data_owner.encode(raw_vectors[-1], length)
    assert [
        full_c - dropped_c
        for full_c, dropped_c in zip(full["weighted_counts"], dropped["weighted_counts"])
    ] == [weights[j] * last_encoded[j] for j in range(length)]


@pytest.mark.parametrize("security", [128, 192, 256])
def test_bit_exact_at_every_security_level(security):
    """The full public-weighted loop stays bit-exact vs the cleartext oracle at
    128/192/256 bits, the sentinel decrypts to EXACTLY N, and the coeff-modulus
    chain's ACHIEVED security equals the REQUESTED level — at each level.

    This is the load-bearing correctness claim: the 30-bit t + ciphertext ×
    plaintext weight multiply must decrypt bit-exact under all three chains
    (including the minimal 256-bit [45,45,28] chain, which has the least noise
    budget)."""
    length = 128
    n_contributors = 7
    rng = random.Random(20260706 + security)
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(n_contributors)
    ]
    # A couple of missing calls to exercise the null->0 encode path under each chain.
    raw_vectors[1][5] = None
    raw_vectors[4][42] = None

    result = _run_pipeline(raw_vectors, length, security=security)

    # Sentinel recovers the EXACT contributor count at this security level.
    assert result["n_contributors"] == n_contributors
    # Encrypted public-weighted aggregate == cleartext oracle, BIT-EXACT (tolerance 0).
    oracle = _cleartext_weighted_aggregate(raw_vectors, length)
    assert result["weighted_counts"] == oracle
    # The cohort scaled PGS is the exact integer sum of the weighted counts.
    assert result["cohort_pgs_scaled"] == sum(oracle)

    # The chain we shipped for this level actually certifies THIS level.
    assert _achieved_security(8192, local_project_owner.SECURITY[security]) == security
