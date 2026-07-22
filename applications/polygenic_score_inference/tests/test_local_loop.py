"""Local-loop equivalence test for the `polygenic_score_inference` bundle.

Proves the full pinned pipeline end-to-end on synthetic contributors:

    keygen -> encode -> encrypt (N>=3) -> compute -> decrypt -> decode

and asserts:

    decode(decrypt(compute(encrypt(encode(g_i)))))  ==  cleartext oracle

**bit-exact on every per-individual score** (BFV, tolerance 0), where the oracle
scores each contributor against the SAME PUBLIC integer-scaled weight vector the
server applies:

    PRS_scaled_i = sum_j w_scaled[j] * encode(g_i)[j]

This reproduces the computation of HEPRS (Knight et al., Cell Reports Methods
2026) — per-individual PRS — but under a PUBLIC model, so the server's per-SNP
product is ciphertext x PLAINTEXT (no relinearization, no ciphertext x
ciphertext) and the only extra homomorphism is the intra-vector rotate-sum
(Galois keys). Also asserts (a) SIGNED scores round-trip exactly (real GWAS betas
are signed); (b) the per-individual scores are independent (dropping a
contributor removes exactly that score); and (c) the loop stays bit-exact at HE
security 128/192/256.

The pure functions live in the author modules (server.py / local_project_owner.py
/ local_data_owner.py), grouped by role per docs/rfcs/0002. The numbered stage
files are kit-owned argparse shims that call these same functions — so testing
the functions directly exercises the identical logic the shims (and the hosted
worker, for compute) run. Run:

    uv --project signed/env run --group dev python -m pytest tests/   # from bundle root

If TenSEAL cannot be imported the whole module skips with a clear reason.
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

pytest.importorskip("tenseal", reason="TenSEAL not installed; sealed env not built")

import local_data_owner  # noqa: E402  (after sys.path insert)
import local_project_owner  # noqa: E402
import server  # noqa: E402


# Achieved-security caps (Σ coeff_mod_bit_sizes) per N, from the
# HomomorphicEncryption.org table. Computed here, NEVER read back from SEAL (SEAL
# only validates at tc128 and cannot report tc192/tc256).
_CAP = {
    8192: {256: 118, 192: 152, 128: 218},
    16384: {256: 237, 192: 305, 128: 438},
    32768: {256: 476, 192: 611, 128: 881},
}


def _achieved_security(poly_modulus_degree: int, coeff_bits: list[int]) -> int:
    total = sum(coeff_bits)
    caps = _CAP[poly_modulus_degree]
    for level in (256, 192, 128):
        if total <= caps[level]:
            return level
    raise AssertionError(f"Σ={total} exceeds even the 128 cap at N={poly_modulus_degree}")


def _oracle_scaled_scores(raw_vectors: list[list], length: int) -> list[int]:
    """The correctness oracle: each contributor's public-weighted dosage sum."""
    weights = server.scaled_weights(length)
    return [
        sum(local_data_owner.encode(raw, length)[j] * weights[j] for j in range(length))
        for raw in raw_vectors
    ]


def _run_pipeline(raw_vectors: list[list], length: int, security: int = 128) -> dict:
    """keygen -> encode -> encrypt -> compute (server) -> decrypt -> decode."""
    secret_ctx, public_ctx = local_project_owner.keygen(security=security)

    # Local data-owner stages, once per contributor.
    ciphertexts = []
    for raw in raw_vectors:
        encoded = local_data_owner.encode(raw, length)
        ciphertexts.append(local_data_owner.encrypt(public_ctx, encoded))

    # The ONLY server-side stage: score each contributor under the PUBLIC context
    # (ciphertext x plaintext + rotate-sum, no secret key present).
    result_ct = server.compute(ciphertexts, public_ctx)

    # Local researcher stages: decrypt with the secret context, then decode.
    plain = local_project_owner.decrypt(secret_ctx, result_ct)
    return local_project_owner.decode(plain, length, scale=local_project_owner.WEIGHT_SCALE)


def test_local_loop_matches_cleartext_and_fixtures():
    """The committed 4-contributor fixtures decode to the committed expected."""
    vectors_dir = BUNDLE_ROOT.parent / "tests" / "vectors"
    expected = json.loads(
        (BUNDLE_ROOT.parent / "tests" / "expected" / "inference.json").read_text()
    )
    length = expected["coordinates_length"]

    raw_vectors = [
        json.loads(path.read_text()) for path in sorted(vectors_dir.glob("*.json"))
    ]
    assert len(raw_vectors) >= 3, "need >=3 synthetic contributors"

    result = _run_pipeline(raw_vectors, length)

    assert result["n_contributors"] == expected["n_contributors"]
    # Per-individual encrypted scores == cleartext oracle == fixture, bit-exact.
    oracle = _oracle_scaled_scores(raw_vectors, length)
    assert result["scaled_scores"] == oracle
    assert result["scaled_scores"] == expected["scaled_scores"]
    assert result["mean_prs"] == pytest.approx(expected["mean_prs"], abs=0.0, rel=0.0)
    assert result["median_prs"] == pytest.approx(expected["median_prs"], abs=0.0, rel=0.0)


def test_signed_scores_round_trip_exactly():
    """Real GWAS betas are signed — a NEGATIVE per-individual score must decrypt
    exactly (residue > t/2 recovered as negative)."""
    length = 64
    weights = server.scaled_weights(length)
    # Construct a contributor whose weighted sum is negative: dosage 2 only where
    # the public weight is negative.
    raw = [2 if weights[j] < 0 else 0 for j in range(length)]
    expected = sum(2 * weights[j] for j in range(length) if weights[j] < 0)
    assert expected < 0  # this contributor's score is genuinely negative

    result = _run_pipeline([raw], length)
    assert result["scaled_scores"] == [expected]
    assert result["per_individual_prs"][0] == expected / server.WEIGHT_SCALE


def test_scores_are_independent_per_contributor():
    """Dropping one upload removes exactly that contributor's score, leaves others."""
    length = 128
    rng = random.Random(7)
    raw_vectors = [[rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(6)]

    full = _run_pipeline(raw_vectors, length)
    dropped = _run_pipeline(raw_vectors[:-1], length)

    assert full["n_contributors"] == 6
    assert dropped["n_contributors"] == 5
    # The first 5 scores are unchanged; the 6th is exactly the dropped contributor's.
    assert dropped["scaled_scores"] == full["scaled_scores"][:-1]
    assert full["scaled_scores"][-1] == _oracle_scaled_scores(raw_vectors[-1:], length)[0]


def test_multi_chunk_large_model_is_exact():
    """A model longer than one BFV ciphertext (L > CHUNK_SLOTS) splits into K chunks
    and still scores bit-exact — the path the 110k-SNP model exercises."""
    length = server.CHUNK_SLOTS * 2 + 137  # forces 3 chunks, last one partial
    rng = random.Random(99)
    raw_vectors = [[rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(3)]
    raw_vectors[1][CHUNK := server.CHUNK_SLOTS] = None  # missing call across a chunk boundary

    result = _run_pipeline(raw_vectors, length)
    assert result["scaled_scores"] == _oracle_scaled_scores(raw_vectors, length)


def test_missing_calls_encode_as_zero():
    """A dropped genotype call (null) encodes as 0 and contributes nothing."""
    length = 32
    weights = server.scaled_weights(length)
    raw = [1] * length
    raw_masked = list(raw)
    raw_masked[5] = None
    got = _run_pipeline([raw_masked], length)["scaled_scores"][0]
    expected = sum(weights) - weights[5]  # coordinate 5 dropped
    assert got == expected


@pytest.mark.parametrize("security", [128, 192, 256])
def test_bit_exact_at_every_security_level(security):
    """The full per-individual loop stays bit-exact vs the cleartext oracle at
    128/192/256 bits, and the coeff-modulus chain's ACHIEVED security equals the
    REQUESTED level. The rotate-sum's 12 rotations plus the plaintext-weight
    multiply must decrypt bit-exact under all three chains — including the minimal
    256-bit [45,45,28] chain, which has the least noise budget."""
    length = 128
    rng = random.Random(20260706 + security)
    raw_vectors = [[rng.choice((0, 1, 2)) for _ in range(length)] for _ in range(7)]
    raw_vectors[1][5] = None
    raw_vectors[4][42] = None

    result = _run_pipeline(raw_vectors, length, security=security)

    assert result["n_contributors"] == 7
    assert result["scaled_scores"] == _oracle_scaled_scores(raw_vectors, length)
    # The chain we shipped for this level actually certifies THIS level.
    assert _achieved_security(8192, local_project_owner.SECURITY[security]) == security
