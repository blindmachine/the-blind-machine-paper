"""Local-loop equivalence test for the `allele_frequency_with_variance` bundle.

Proves the full pinned pipeline end-to-end on synthetic contributors:

    keygen -> encode -> encrypt (N>=3) -> compute (SERVER SQUARES) -> decrypt -> decode

and asserts, per docs/simulation_mode.md's oracle claim:

    decode(decrypt(compute(encrypt(encode(raw)))))  ==  cleartext aggregate

**bit-exact** for BOTH integer aggregates (sum_g AND the server-squared sum_g2 —
BFV, precision_tolerance 0), AND that the append-1 sentinel decrypts to **exactly
N** in BOTH the sum path and the square path (docs/spec.md).

This is the multiplicative-depth benchmark arm: the server performs one ct x ct
square per contributor (relin keys retained in the public context, keygen). A
fourth test runs the **additive client-precompute benchmark VARIANT** (client
pre-squares g locally, server only sums) and asserts it yields a bit-identical
sum_g2 — the correctness half of the "what does one multiplicative level cost?"
comparison (cost itself is measured by `blind bench`; see BENCHMARK.md).

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


def _cleartext_moments(raw_vectors: list[list], length: int) -> tuple[list[int], list[int]]:
    """The correctness oracle: first and second moments in cleartext.

    sum_g[j]  = sum_i encode(raw_i)[j]
    sum_g2[j] = sum_i encode(raw_i)[j] ** 2   (square-then-sum, matching stage 30)
    """
    sum_g = [0] * length
    sum_g2 = [0] * length
    for raw in raw_vectors:
        for j, value in enumerate(local_data_owner.encode(raw, length)):
            sum_g[j] += value
            sum_g2[j] += value * value
    return sum_g, sum_g2


# The three HE security levels the keygen parametrizes over.
SECURITY_LEVELS = (128, 192, 256)

# HomomorphicEncryption.org coeff-modulus caps at N=16384 (this protocol's fixed
# ring): the strictest level L whose CAP the chain's Sigma clears. Used to assert
# the harness would compute `achieved == requested` for each SECURITY table row.
_CAP_N16384 = ((256, 237), (192, 305), (128, 438))


def _achieved_security(coeff_mod_bit_sizes: list[int]) -> int:
    """achieved(Sigma) = strictest level L with Sigma <= CAP[16384][L] (else 0)."""
    total = sum(coeff_mod_bit_sizes)
    for level, cap in _CAP_N16384:
        if total <= cap:
            return level
    return 0  # rejected: over the 128-bit ceiling


def _run_pipeline(raw_vectors: list[list], length: int, security: int = 128) -> dict:
    """keygen -> encode -> encrypt -> compute (server squares) -> decrypt -> decode."""
    secret_ctx, public_ctx = local_project_owner.keygen(security=security)

    # Local data-owner stages, once per contributor — a SINGLE ciphertext each.
    ciphertexts = []
    for raw in raw_vectors:
        encoded = local_data_owner.encode(raw, length)
        ciphertexts.append(local_data_owner.encrypt(public_ctx, encoded))

    # The ONLY server-side stage: fold ciphertexts into two moment aggregates
    # under the PUBLIC context (with relin keys, no secret key). Returns ONE
    # deterministic result.bin container (magic BMCT1) packing both moments.
    result_bytes = server.compute(ciphertexts, public_ctx)

    # Local researcher stages: unpack + decrypt both aggregates, then decode.
    plain = local_project_owner.decrypt(secret_ctx, result_bytes)
    return local_project_owner.decode(plain, length)


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

    # Both sentinels recover the EXACT contributor count (sum path AND square path).
    assert result["n_contributors"] == len(raw_vectors)
    assert result["n_contributors"] == expected["n_contributors"]

    # Encrypted aggregates == cleartext oracle == committed fixture, bit-exact.
    oracle_sum, oracle_sumsq = _cleartext_moments(raw_vectors, length)
    assert result["sum_g"] == oracle_sum
    assert result["sum_g2"] == oracle_sumsq
    assert result["sum_g"] == expected["sum_g"]
    assert result["sum_g2"] == expected["sum_g2"]

    # Derived real statistics match the committed fixture exactly.
    assert result["mean"] == pytest.approx(expected["mean"], abs=0.0, rel=0.0)
    assert result["variance"] == pytest.approx(expected["variance"], abs=0.0, rel=0.0)
    assert result["allele_frequency"] == pytest.approx(
        expected["allele_frequency"], abs=0.0, rel=0.0
    )


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

    oracle_sum, oracle_sumsq = _cleartext_moments(raw_vectors, length)
    assert result["n_contributors"] == n_contributors  # both sentinels == N, exactly
    assert result["sum_g"] == oracle_sum
    assert result["sum_g2"] == oracle_sumsq  # server-squared second moment, bit-exact


@pytest.mark.parametrize("security", SECURITY_LEVELS)
def test_local_loop_bit_exact_at_each_security_level(security):
    """Depth-1 ct x ct square decrypts BIT-EXACT at 128, 192, AND 256.

    The whole point of parametrizing keygen by `--security`: swapping the coeff
    modulus chain (the ONLY knob) must never break correctness. At every level the
    server-squared second moment (`sum_g2`) and the additive first moment
    (`sum_g`) equal the cleartext oracle bit-for-bit, and BOTH append-1 sentinels
    decrypt to exactly N. Also assert the chain the keygen ships for this level
    lands in that level's q-band (achieved == requested), matching the survey's
    authoritative SECURITY table.
    """
    # The keygen ships exactly the table's chain for this level, and that chain
    # certifies the requested level under the N=16384 caps.
    assert local_project_owner.SECURITY[security] == {
        128: [60, 60, 60, 60, 60, 60],
        192: [60, 60, 60, 60],
        256: [60, 40, 40, 60],
    }[security]
    assert _achieved_security(local_project_owner.SECURITY[security]) == security

    length = 128
    n_contributors = 5
    rng = random.Random(0xA11E1E + security)  # distinct seed per level
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(n_contributors)
    ]
    raw_vectors[1][7] = None  # exercise the encode-as-0 (missing call) path

    result = _run_pipeline(raw_vectors, length, security=security)

    oracle_sum, oracle_sumsq = _cleartext_moments(raw_vectors, length)
    # Both sentinels recover the EXACT contributor count at this security level.
    assert result["n_contributors"] == n_contributors
    # Both moments match the cleartext oracle bit-for-bit (BFV, tolerance 0).
    assert result["sum_g"] == oracle_sum
    assert result["sum_g2"] == oracle_sumsq


def test_square_is_not_square_of_sum():
    """Guard the mandatory square-then-sum: sum_i g_i^2 != (sum_i g_i)^2.

    A cohort where the distinction is visible per coordinate proves stage 30
    squares EACH contributor before summing, not the aggregate.
    """
    length = 4
    raw_vectors = [
        [2, 0, 1, 2],
        [2, 0, 1, 0],
        [2, 0, 0, 1],
    ]
    result = _run_pipeline(raw_vectors, length)
    oracle_sum, oracle_sumsq = _cleartext_moments(raw_vectors, length)

    assert result["sum_g"] == oracle_sum == [6, 0, 2, 3]
    assert result["sum_g2"] == oracle_sumsq == [12, 0, 2, 5]  # sum of squares
    # If the server had (wrongly) squared the sum, coord 0 would read 36, not 12.
    assert result["sum_g2"] != [s * s for s in oracle_sum]


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
    # And both aggregates really lost exactly the dropped contributor's moments.
    last_encoded = local_data_owner.encode(raw_vectors[-1], length)
    assert [
        full_c - dropped_c
        for full_c, dropped_c in zip(full["sum_g"], dropped["sum_g"])
    ] == last_encoded
    assert [
        full_c - dropped_c
        for full_c, dropped_c in zip(full["sum_g2"], dropped["sum_g2"])
    ] == [v * v for v in last_encoded]


def _additive_precompute_sum_g2(raw_vectors: list[list], length: int) -> tuple[list[int], int]:
    """BENCHMARK variant: client pre-squares g locally, server ONLY sums.

    This is the additive counterpart the paper measures beside the multiplicative
    version. Here it runs on the flagship's MINIMAL additive params (poly 8192,
    default coeff modulus, plain 1032193 which is exact for max sum_g2 = 4N) — no
    relin keys, no multiplicative level — to show the same sum_g2 is obtainable
    without a ct x ct multiply, just by moving the square to the client.

    Returns ``(sum_g2[:L], sentinel_N)``.
    """
    import tenseal as ts

    # Cheaper additive-tier context; NO relin/Galois needed (pure ct+ct fold).
    secret_ctx, public_ctx = local_project_owner.keygen(
        poly_modulus_degree=8192,
        plain_modulus=1032193,
        coeff_mod_bit_sizes=None,  # TenSEAL default coeff modulus (additive regime)
    )

    # Client pre-squares g locally, then encrypts g^2 (+ sentinel 1).
    squared_ciphers = []
    for raw in raw_vectors:
        encoded = local_data_owner.encode(raw, length)
        squared = [v * v for v in encoded]
        squared_ciphers.append(local_data_owner.encrypt(public_ctx, squared))

    # Server ONLY sums (no multiply): reuse the additive .add fold.
    context = ts.context_from(public_ctx)
    evaluator = server.BFVEvaluator(context)
    loaded = [evaluator.load(blob) for blob in squared_ciphers]
    acc = loaded[0]
    for item in loaded[1:]:
        acc = evaluator.add(acc, item)

    # ``acc.serialize()`` is a RAW single ciphertext (no BMCT1 container framing),
    # so use the lower-level per-blob decrypt rather than the container-aware
    # ``decrypt`` (which would reject the missing magic).
    ctx = ts.context_from(secret_ctx)
    plain = local_project_owner.decrypt_blob(ctx, acc.serialize())
    return plain[:length], int(plain[length])


def test_additive_client_precompute_variant_matches_multiplicative():
    """Additive client-precompute variant yields a bit-identical sum_g2.

    The whole "multiplicative-depth premium" comparison rests on the two paths
    computing the SAME statistic. This asserts correctness equivalence; `blind
    bench` measures the cost delta (16384 mult ring + relin + ct x ct square vs
    8192 additive ring). See BENCHMARK.md.
    """
    length = 64
    rng = random.Random(1234)
    raw_vectors = [
        [rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(4)
    ]

    multiplicative = _run_pipeline(raw_vectors, length)
    additive_sum_g2, additive_n = _additive_precompute_sum_g2(raw_vectors, length)

    _, oracle_sumsq = _cleartext_moments(raw_vectors, length)
    assert additive_n == len(raw_vectors)
    assert additive_sum_g2 == oracle_sumsq
    # Server-squared (multiplicative) == client-squared (additive), bit-for-bit.
    assert multiplicative["sum_g2"] == additive_sum_g2
