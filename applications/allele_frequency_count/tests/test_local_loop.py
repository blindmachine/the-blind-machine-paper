"""Local-loop equivalence test for the `allele_frequency_count` flagship bundle.

Proves the full pinned pipeline end-to-end on synthetic contributors:

    keygen -> encode -> encrypt (N>=3) -> compute -> decrypt -> decode

and asserts, per docs/simulation_mode.md's oracle claim:

    decode(decrypt(compute(encrypt(encode(raw)))))  ==  cleartext aggregate

**bit-exact** (BFV, precision_tolerance 0), AND that the append-1 sentinel
decrypts to **exactly N** (docs/spec.md).

The pure functions live in the author modules (server.py / local_project_owner.py
/ local_data_owner.py), grouped by role per docs/rfcs/0002. The numbered stage
files at the bundle root are kit-owned argparse shims that call these same
functions — so testing the functions directly exercises the identical logic the
shims (and the hosted worker, for compute) run. Run:

    uv --project signed/env run --group dev pytest tests/            # from bundle root
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


# HomomorphicEncryption.org coeff-modulus caps (max Σ coeff_mod_bit_sizes) at N.
# achieved(N, Σ) = strictest level L with Σ <= CAP[N][L]. Computed by the harness,
# NEVER read back from SEAL (SEAL only validates at tc128).
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


def _cleartext_aggregate(raw_vectors: list[list], length: int) -> list[int]:
    """The correctness oracle: sum encoded vectors coordinate-wise in cleartext."""
    counts = [0] * length
    for raw in raw_vectors:
        for j, value in enumerate(local_data_owner.encode(raw, length)):
            counts[j] += value
    return counts


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

    # Local project-owner stages: decrypt with the secret context, then decode.
    plain = local_project_owner.decrypt(secret_ctx, result_ct)
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

    # Sentinel recovers the EXACT contributor count.
    assert result["n_contributors"] == len(raw_vectors)
    assert result["n_contributors"] == expected["n_contributors"]

    # Encrypted aggregate == cleartext oracle == committed fixture, bit-exact.
    assert result["allele_counts"] == _cleartext_aggregate(raw_vectors, length)
    assert result["allele_counts"] == expected["allele_counts"]
    assert result["allele_frequencies"] == pytest.approx(
        expected["allele_frequencies"], abs=0.0, rel=0.0
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

    assert result["n_contributors"] == n_contributors  # sentinel == N, exactly
    assert result["allele_counts"] == _cleartext_aggregate(raw_vectors, length)


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
    # And the aggregate really lost exactly the dropped contributor's dosages.
    last_encoded = local_data_owner.encode(raw_vectors[-1], length)
    assert [
        full_c - dropped_c
        for full_c, dropped_c in zip(full["allele_counts"], dropped["allele_counts"])
    ] == last_encoded


@pytest.mark.parametrize("security", [128, 192, 256])
def test_bit_exact_at_every_security_level(security):
    """The full loop stays bit-exact vs the cleartext oracle at 128/192/256 bits,
    and the sentinel decrypts to EXACTLY N — at each level. Also asserts the
    coeff-modulus chain's ACHIEVED security equals the REQUESTED level."""
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
    # Encrypted aggregate == cleartext oracle, BIT-EXACT (BFV, tolerance 0).
    assert result["allele_counts"] == _cleartext_aggregate(raw_vectors, length)

    # The chain we shipped for this level actually certifies THIS level.
    assert _achieved_security(8192, local_project_owner.SECURITY[security]) == security
