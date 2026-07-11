"""Local-loop equivalence test for the `genotype_phenotype_covariance` bundle.

Proves the full pinned pipeline end-to-end on synthetic contributors, exercising a
REAL ciphertext×ciphertext product (depth 1, relinearized) on the server stage:

    keygen -> encode -> encrypt (N>=3, one packed (g,y) blob each) -> compute
           -> decrypt -> decode

and asserts, per docs/simulation_mode.md's oracle claim:

    decode(decrypt(compute(encrypt(encode(raw)))))  ==  cleartext moment oracle

**bit-exact** for the integer moments (BFV, precision_tolerance 0), AND that the
append-1 sentinel decrypts to **exactly N** in ALL FOUR moments (docs/spec.md).

The oracle is run TWO ways that must agree:
  1. a direct cleartext computation of the four moments, and
  2. the SAME `aggregate()` function from server.py driven by a
     `PlaintextEvaluator` (add/mul on int lists) — the abstract-evaluator seam
     from docs/simulation_mode.md §1, so the encrypted and cleartext paths cannot
     drift.

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

import hashlib
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


class PlaintextEvaluator:
    """The oracle's evaluator: element-wise add/mul on plaintext int lists.

    Mirrors server.py's BFVEvaluator op-for-op, so the SAME `aggregate()` yields
    the cleartext moments when driven by it.
    """

    def zero(self, length: int):
        return [0] * length

    def add(self, a, b):
        return [x + y for x, y in zip(a, b)]

    def mul(self, a, b):
        return [x * y for x, y in zip(a, b)]


def _encoded_pairs_with_sentinel(raw_records: list[dict], length: int) -> list[tuple]:
    """encode + append-1 sentinel, as plaintext (g||1, y||1) pairs for the oracle."""
    pairs = []
    for raw in raw_records:
        enc = local_data_owner.encode(raw, length)
        g = local_data_owner.append_sentinel(enc["g"])
        y = local_data_owner.append_sentinel(enc["y"])
        pairs.append((g, y))
    return pairs


def _cleartext_moments(raw_records: list[dict], length: int) -> dict:
    """Direct correctness oracle: the four moments over length L (no sentinel)."""
    n = len(raw_records)
    sum_g = [0] * length
    sum_gy = [0] * length
    sum_y = 0
    sum_y2 = 0
    for raw in raw_records:
        enc = local_data_owner.encode(raw, length)
        y = enc["y"][0]  # broadcast scalar
        for j, g in enumerate(enc["g"]):
            sum_g[j] += g
            sum_gy[j] += g * y
        sum_y += y
        sum_y2 += y * y
    return {
        "n": n,
        "sum_g": sum_g,
        "sum_gy": sum_gy,
        "sum_y": sum_y,
        "sum_y2": sum_y2,
    }


# Achieved security = the strictest level L whose cap the chain's Σ stays under,
# per the HomomorphicEncryption.org table at n=16384 (the fixed ring for this
# depth-1 protocol). Computed here exactly as the benchmark harness does — never
# read back from SEAL (SEAL only ever validates at tc128).
_CAP_16384 = {256: 237, 192: 305, 128: 438}


def _achieved_security(coeff_mod_bit_sizes: list[int]) -> int:
    total = sum(coeff_mod_bit_sizes)
    for level in (256, 192, 128):
        if total <= _CAP_16384[level]:
            return level
    raise AssertionError(f"Σ={total} exceeds the 128-bit cap at n=16384")


def _run_pipeline(
    raw_records: list[dict], length: int, security: int | None = None
) -> dict:
    """keygen -> encode -> encrypt -> compute (server) -> decrypt -> decode."""
    if security is None:
        secret_ctx, public_ctx = local_project_owner.keygen()
    else:
        secret_ctx, public_ctx = local_project_owner.keygen(security=security)

    # Local data-owner stages, once per contributor: ONE packed (g, y) blob each.
    # Order-independent — the server unpacks each blob's own pair (see
    # test_result_is_order_independent_under_digest_sort).
    ciphertexts: list[bytes] = []
    for raw in raw_records:
        encoded = local_data_owner.encode(raw, length)
        ciphertexts.append(local_data_owner.encrypt(public_ctx, encoded))

    # The ONLY server-side stage: derive the moments under the PUBLIC context.
    result_ct = server.compute(ciphertexts, public_ctx)

    # Local researcher stages: decrypt with the secret context, then decode.
    plain = local_project_owner.decrypt(secret_ctx, result_ct)
    return local_project_owner.decode(plain, length)


def test_compute_oracle_agrees_with_direct_cleartext():
    """The shared aggregate() over a PlaintextEvaluator == the direct oracle."""
    length = 16
    raw_records = [
        json.loads(path.read_text())
        for path in sorted((BUNDLE_ROOT / "tests" / "vectors").glob("*.json"))
    ]
    pairs = _encoded_pairs_with_sentinel(raw_records, length)
    moments = server.aggregate(pairs, PlaintextEvaluator())

    direct = _cleartext_moments(raw_records, length)
    # Split the sentinel off the shared-code moments and compare to the direct one.
    assert moments["sum_g"][:length] == direct["sum_g"]
    assert moments["sum_gy"][:length] == direct["sum_gy"]
    assert moments["sum_y"][0] == direct["sum_y"]
    assert moments["sum_y2"][0] == direct["sum_y2"]
    # Every append-1 sentinel (last slot) recovers N through the shared code path.
    for name in ("sum_g", "sum_gy", "sum_y", "sum_y2"):
        assert moments[name][length] == direct["n"]


def test_local_loop_matches_cleartext_and_fixtures():
    """The committed 4-contributor fixtures decode to the committed expected."""
    expected = json.loads(
        (BUNDLE_ROOT / "tests" / "expected" / "aggregate.json").read_text()
    )
    length = expected["coordinates_length"]

    raw_records = [
        json.loads(path.read_text())
        for path in sorted((BUNDLE_ROOT / "tests" / "vectors").glob("*.json"))
    ]
    assert len(raw_records) >= 3, "need >=3 synthetic contributors"

    result = _run_pipeline(raw_records, length)
    oracle = _cleartext_moments(raw_records, length)

    # Sentinel recovers the EXACT contributor count (checked in ALL four moments
    # by decode()'s cross-check; here we assert the surfaced value).
    assert result["n_contributors"] == len(raw_records)
    assert result["n_contributors"] == expected["n_contributors"]

    # Encrypted moments == cleartext oracle == committed fixture, bit-exact.
    assert result["sum_g"] == oracle["sum_g"] == expected["sum_g"]
    assert result["sum_gy"] == oracle["sum_gy"] == expected["sum_gy"]
    assert result["sum_y"] == oracle["sum_y"] == expected["sum_y"]
    assert result["sum_y2"] == oracle["sum_y2"] == expected["sum_y2"]

    # Derived real-valued covariance matches the committed expected (exact — it is
    # a rational function of bit-exact integers).
    assert result["covariance"] == pytest.approx(
        expected["covariance"], abs=0.0, rel=0.0
    )
    assert result["mean_y"] == pytest.approx(expected["mean_y"], abs=0.0, rel=0.0)
    assert result["var_y"] == pytest.approx(expected["var_y"], abs=0.0, rel=0.0)


def test_result_is_order_independent_under_digest_sort():
    """The hosted Stager digest-sorts inputs (worker/lib/blind_worker/stager.rb:25).

    With ONE packed (g, y) blob per contributor the moment folds are order-
    independent, so a digest-sorted run must decode bit-identically to the
    submission-order run. This pins the exact invariant the Stager relies on — and
    the property whose ABSENCE (two separate, digest-sortable ciphertexts) was the
    original covariance pairing bug.
    """
    length = 16
    raw_records = [
        json.loads(path.read_text())
        for path in sorted((BUNDLE_ROOT / "tests" / "vectors").glob("*.json"))
    ]
    assert len(raw_records) >= 3, "need >=3 contributors for a meaningful permutation"
    secret_ctx, public_ctx = local_project_owner.keygen()
    blobs = [
        local_data_owner.encrypt(public_ctx, local_data_owner.encode(raw, length))
        for raw in raw_records
    ]
    # The exact order the hosted Stager would stage the inputs in.
    submission = sorted(blobs, key=lambda b: hashlib.sha256(b).hexdigest())
    assert submission != blobs, "digest order should differ from submission order"

    def run(order: list[bytes]) -> dict:
        ct = server.compute(order, public_ctx)
        plain = local_project_owner.decrypt(secret_ctx, ct)
        return local_project_owner.decode(plain, length)

    assert run(blobs) == run(submission)


def test_local_loop_full_coordinate_length_random_cohort():
    """Exercise the manifest coordinate length (L=1000) with a seeded cohort."""
    length = 1000
    n_contributors = 5
    rng = random.Random(20260705)  # reproducible synthetic cohort
    raw_records = []
    for _ in range(n_contributors):
        genotype = [rng.choice((0, 1, 2)) for _ in range(length)]
        raw_records.append({"genotype": genotype, "phenotype": rng.choice((0, 1))})
    # Inject a couple of missing calls (null) to exercise the encode-as-0 path.
    raw_records[0]["genotype"][3] = None
    raw_records[2]["genotype"][17] = None

    result = _run_pipeline(raw_records, length)
    oracle = _cleartext_moments(raw_records, length)

    assert result["n_contributors"] == n_contributors  # sentinel == N, exactly
    assert result["sum_g"] == oracle["sum_g"]
    assert result["sum_gy"] == oracle["sum_gy"]
    assert result["sum_y"] == oracle["sum_y"]
    assert result["sum_y2"] == oracle["sum_y2"]


@pytest.mark.parametrize("security", [128, 192, 256])
def test_local_loop_bit_exact_at_every_security_level(security):
    """The full ct×ct loop is bit-exact vs the cleartext oracle at 128/192/256.

    Only the coefficient-modulus chain changes across levels (N=16384 and
    t=786433 are fixed); a deeper chain just spends surplus noise budget, so the
    depth-1 product + relin must still decrypt bit-for-bit and the append-1
    sentinel must recover EXACTLY N in all four moments at every level.

    Also asserts the chain the keygen selected certifies the REQUESTED level
    (achieved == requested), computed from (N, Σbits) against the caps — the same
    way the benchmark harness does, never read back from SEAL.
    """
    # keygen picked the requested band: achieved == requested.
    chain = local_project_owner.SECURITY[security]
    assert _achieved_security(chain) == security, (
        f"security={security}: chain {chain} (Σ={sum(chain)}) certifies "
        f"{_achieved_security(chain)}, not {security}"
    )

    length = 24
    rng = random.Random(4096 + security)
    raw_records = []
    for _ in range(5):
        genotype = [rng.choice((0, 1, 2)) for _ in range(length)]
        raw_records.append({"genotype": genotype, "phenotype": rng.choice((0, 1))})
    # A missing call exercises the encode-as-0 path at every level too.
    raw_records[1]["genotype"][7] = None

    result = _run_pipeline(raw_records, length, security=security)
    oracle = _cleartext_moments(raw_records, length)

    # Sentinel decrypts to EXACTLY N at this level (checked across all four
    # moments by decode()'s cross-check; here we assert the surfaced count).
    assert result["n_contributors"] == len(raw_records)
    # Encrypted moments == cleartext oracle, bit-exact (BFV, tolerance 0).
    assert result["sum_g"] == oracle["sum_g"]
    assert result["sum_gy"] == oracle["sum_gy"]
    assert result["sum_y"] == oracle["sum_y"]
    assert result["sum_y2"] == oracle["sum_y2"]


def test_sentinel_tracks_dropped_upload():
    """Dropping one contributor's pair yields N-1 and removes exactly its moments."""
    length = 24
    rng = random.Random(11)
    raw_records = []
    for _ in range(6):
        genotype = [rng.choice((0, 1, 2)) for _ in range(length)]
        raw_records.append({"genotype": genotype, "phenotype": rng.choice((0, 1))})

    full = _run_pipeline(raw_records, length)
    dropped = _run_pipeline(raw_records[:-1], length)

    assert full["n_contributors"] == 6
    assert dropped["n_contributors"] == 5

    # The aggregate really lost exactly the dropped contributor's genotype dosages.
    last = local_data_owner.encode(raw_records[-1], length)
    assert [
        f - d for f, d in zip(full["sum_g"], dropped["sum_g"])
    ] == last["g"]
    # ... and exactly its g*y contribution in the product moment.
    y_last = last["y"][0]
    assert [
        f - d for f, d in zip(full["sum_gy"], dropped["sum_gy"])
    ] == [g * y_last for g in last["g"]]
    # ... and exactly its phenotype in the scalar moments.
    assert full["sum_y"] - dropped["sum_y"] == y_last
    assert full["sum_y2"] - dropped["sum_y2"] == y_last * y_last
