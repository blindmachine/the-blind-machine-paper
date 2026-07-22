"""Local-loop equivalence test for the `gwas_chi_square` bundle.

Proves the full pinned pipeline end-to-end on synthetic case/control cohorts:

    keygen -> encode -> encrypt (N>=3) -> compute -> decrypt -> decode

and asserts, per docs/simulation_mode.md's oracle claim, that the decrypted
per-SNP sufficient statistics (Σg, Σg·y, #cases, N) are **bit-identical** (BFV,
tolerance 0) to an independent cleartext aggregate — and therefore that the
allelic chi-square, p-value and odds ratio derived from them (in cleartext) match
a cleartext GWAS exactly. This is the encrypted-equals-cleartext concordance the
paper reports as R^2 = 1.00 (Blatt et al., PNAS 2020), reproduced here bit-for-bit.

The pure functions live in the author modules (server.py / local_project_owner.py
/ local_data_owner.py), grouped by role per docs/rfcs/0002. Testing the functions
directly exercises the identical logic the kit shims (and the hosted worker, for
compute) run. Run:

    uv --project signed/env run --group dev pytest tests/            # from bundle root

If TenSEAL cannot be imported the whole module skips with a clear reason.
"""
from __future__ import annotations

import json
import math
import pathlib
import random
import sys

import pytest

BUNDLE_ROOT = pathlib.Path(__file__).resolve().parent.parent / "signed"
sys.path.insert(0, str(BUNDLE_ROOT))

pytest.importorskip("tenseal", reason="TenSEAL not installed; sealed env not built")

import local_data_owner  # noqa: E402  (after sys.path insert)
import local_project_owner  # noqa: E402
import server  # noqa: E402


# HomomorphicEncryption.org coeff-modulus caps (max Σ coeff_mod_bit_sizes) at N.
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


def _cleartext_sufficient_stats(records: list[dict], length: int) -> dict:
    """The correctness oracle: aggregate the sufficient statistics in pure Python."""
    sum_g = [0] * length
    sum_gy = [0] * length
    cases = 0
    for rec in records:
        encoded = local_data_owner.encode(rec, length)
        g, y = encoded["g"], encoded["y"]
        cases += y
        for j in range(length):
            sum_g[j] += g[j]
            sum_gy[j] += g[j] * y
    return {"sum_g": sum_g, "sum_gy": sum_gy, "cases": cases, "n": len(records)}


def _cleartext_decode(records: list[dict], length: int) -> dict:
    """Run the whole GWAS in cleartext (same chi-square helper decode uses)."""
    stats = _cleartext_sufficient_stats(records, length)
    n, cases = stats["n"], stats["cases"]
    chi2, pval, orat = [], [], []
    for j in range(length):
        c, p, o = local_project_owner._allelic_chi_square(
            stats["sum_gy"][j], stats["sum_g"][j], cases, n
        )
        chi2.append(c)
        pval.append(p)
        orat.append(o)
    return {**stats, "chi_square": chi2, "p_value": pval, "odds_ratio": orat}


def _run_pipeline(records: list[dict], length: int, security: int = 128) -> dict:
    """keygen -> encode -> encrypt -> compute (server) -> decrypt -> decode."""
    secret_ctx, public_ctx = local_project_owner.keygen(security=security)

    ciphertexts = []
    for rec in records:
        encoded = local_data_owner.encode(rec, length)
        ciphertexts.append(local_data_owner.encrypt(public_ctx, encoded))

    result_ct = server.compute(ciphertexts, public_ctx)

    plain = local_project_owner.decrypt(secret_ctx, result_ct)
    return local_project_owner.decode(plain, length)


def _assert_matches_cleartext(result: dict, records: list[dict], length: int) -> None:
    oracle = _cleartext_decode(records, length)
    # Integer sufficient statistics — the actual homomorphic claim — BIT-EXACT.
    assert result["n_contributors"] == oracle["n"]
    assert result["cases"] == oracle["cases"]
    assert result["minor_allele_count"] == oracle["sum_g"]
    assert result["minor_allele_count_in_cases"] == oracle["sum_gy"]
    # Derived statistics (pure cleartext function of the exact integers) — EXACT.
    assert result["chi_square"] == pytest.approx(oracle["chi_square"], abs=0.0, rel=0.0)
    assert result["p_value"] == pytest.approx(oracle["p_value"], abs=0.0, rel=0.0)
    for got, want in zip(result["odds_ratio"], oracle["odds_ratio"]):
        if math.isnan(want):
            assert math.isnan(got)
        else:
            assert got == pytest.approx(want, abs=0.0, rel=0.0)


def test_local_loop_matches_cleartext_and_fixtures():
    """The committed 4-contributor fixtures decode to the committed expected."""
    vectors_dir = BUNDLE_ROOT.parent / "tests" / "vectors"
    expected = json.loads(
        (BUNDLE_ROOT.parent / "tests" / "expected" / "gwas.json").read_text()
    )
    length = expected["coordinates_length"]

    records = [json.loads(p.read_text()) for p in sorted(vectors_dir.glob("*.json"))]
    assert len(records) >= 3, "need >=3 synthetic contributors"

    result = _run_pipeline(records, length)

    assert result["n_contributors"] == len(records)
    assert result["n_contributors"] == expected["n_contributors"]
    assert result["cases"] == expected["cases"]
    assert result["minor_allele_count"] == expected["minor_allele_count"]
    assert result["minor_allele_count_in_cases"] == expected["minor_allele_count_in_cases"]
    assert result["chi_square"] == pytest.approx(expected["chi_square"], abs=0.0, rel=0.0)
    assert result["p_value"] == pytest.approx(expected["p_value"], abs=0.0, rel=0.0)

    _assert_matches_cleartext(result, records, length)


def test_single_chunk_random_cohort():
    """L=1000 (< 8192 slots, one chunk per series), bit-exact vs cleartext."""
    length = 1000
    rng = random.Random(20260717)
    records = [
        {
            "genotype": [rng.choice((0, 1, 2)) for _ in range(length)],
            "phenotype": rng.choice((0, 1)),
        }
        for _ in range(9)
    ]
    # Inject a couple of missing calls (null) to exercise the encode-as-0 path.
    records[0]["genotype"][3] = None
    records[2]["genotype"][17] = None

    result = _run_pipeline(records, length)
    _assert_matches_cleartext(result, records, length)


def test_multi_chunk_crosses_slot_boundary():
    """L > SLOT_COUNT forces >1 ciphertext chunk per series — the key new path.

    L=9000 with SLOT_COUNT=8192 => 2 chunks; the last chunk (808 SNPs) is shorter
    than the first, exercising the ragged-tail reassembly in decode.
    """
    length = 9000
    assert length > local_data_owner.SLOT_COUNT  # genuinely multi-chunk
    rng = random.Random(424242)
    records = [
        {
            "genotype": [rng.choice((0, 1, 2)) for _ in range(length)],
            "phenotype": rng.choice((0, 1)),
        }
        for _ in range(6)
    ]
    result = _run_pipeline(records, length)
    assert len(result["minor_allele_count"]) == length
    _assert_matches_cleartext(result, records, length)


def test_dropped_upload_tracks_case_count_and_sums():
    """Dropping one upload yields N-1, and the aggregate loses exactly that record."""
    length = 64
    rng = random.Random(7)
    records = [
        {
            "genotype": [rng.choice((0, 1, 2)) for _ in range(length)],
            "phenotype": rng.choice((0, 1)),
        }
        for _ in range(6)
    ]

    full = _run_pipeline(records, length)
    dropped = _run_pipeline(records[:-1], length)

    assert full["n_contributors"] == 6
    assert dropped["n_contributors"] == 5
    # The dropped contributor's contribution is exactly the difference.
    last = local_data_owner.encode(records[-1], length)
    assert [f - d for f, d in zip(full["minor_allele_count"], dropped["minor_allele_count"])] == last["g"]
    assert full["cases"] - dropped["cases"] == last["y"]


@pytest.mark.parametrize("security", [128, 192, 256])
def test_bit_exact_at_every_security_level(security):
    """The full loop stays bit-exact vs the cleartext oracle at 128/192/256 bits,
    and the coeff-modulus chain's ACHIEVED security equals the REQUESTED level."""
    length = 200
    rng = random.Random(20260717 + security)
    records = [
        {
            "genotype": [rng.choice((0, 1, 2)) for _ in range(length)],
            "phenotype": rng.choice((0, 1)),
        }
        for _ in range(11)
    ]
    records[1]["genotype"][5] = None

    result = _run_pipeline(records, length, security=security)
    _assert_matches_cleartext(result, records, length)

    assert _achieved_security(8192, local_project_owner.SECURITY[security]) == security
