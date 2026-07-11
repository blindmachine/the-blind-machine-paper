"""Local-loop equivalence test for the `cohort_histogram` bundle.

Proves the full pinned pipeline end-to-end on synthetic contributors:

    keygen -> encode -> encrypt (N>=3) -> compute -> decrypt -> decode

and asserts, per docs/simulation_mode.md's oracle claim:

    decode(decrypt(compute(encrypt(encode(raw)))))  ==  cleartext aggregate

**bit-exact** (BFV, precision_tolerance 0), that the append-1 sentinel decrypts
to **exactly N**, and — the cross-check this one-hot protocol gets for free —
that the summed bucket counts total exactly N (`sum(counts) == sentinel`).

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


def _cleartext_aggregate(raw_indices: list[int], length: int) -> list[int]:
    """The correctness oracle: sum one-hot encodings coordinate-wise in cleartext."""
    counts = [0] * length
    for raw in raw_indices:
        for j, value in enumerate(local_data_owner.encode(raw, length)):
            counts[j] += value
    return counts


# The three certified HE security levels the keygen supports. Every local-loop
# assertion below is exercised at each one (the ONLY thing that varies is the
# coeff-modulus chain selected inside keygen; the payload arithmetic is fixed).
SECURITY_LEVELS = (128, 192, 256)


def _run_pipeline(raw_indices: list[int], length: int, security: int = 128) -> dict:
    """keygen -> encode -> encrypt -> compute (server) -> decrypt -> decode."""
    secret_ctx, public_ctx = local_project_owner.keygen(security=security)

    # Local data-owner stages, once per contributor.
    ciphertexts = []
    for raw in raw_indices:
        encoded = local_data_owner.encode(raw, length)
        ciphertexts.append(local_data_owner.encrypt(public_ctx, encoded))

    # The ONLY server-side stage: sum ciphertexts under the PUBLIC context.
    result_ct = server.compute(ciphertexts, public_ctx)

    # Local researcher stages: decrypt with the secret context, then decode.
    plain = local_project_owner.decrypt(secret_ctx, result_ct)
    return local_project_owner.decode(plain, length)


@pytest.mark.parametrize("security", SECURITY_LEVELS)
def test_local_loop_matches_cleartext_and_fixtures(security):
    """The committed 5-contributor fixtures decode to the committed expected.

    Runs at every certified security level: the encrypted histogram must equal
    the cleartext oracle AND the committed fixture bit-exact regardless of the
    coeff-modulus chain keygen selects.
    """
    vectors_dir = BUNDLE_ROOT / "tests" / "vectors"
    expected = json.loads(
        (BUNDLE_ROOT / "tests" / "expected" / "aggregate.json").read_text()
    )
    length = expected["buckets_length"]

    raw_indices = [
        json.loads(path.read_text()) for path in sorted(vectors_dir.glob("*.json"))
    ]
    assert len(raw_indices) >= 3, "need >=3 synthetic contributors"

    result = _run_pipeline(raw_indices, length, security=security)

    # Sentinel recovers the EXACT contributor count.
    assert result["n_contributors"] == len(raw_indices)
    assert result["n_contributors"] == expected["n_contributors"]

    # Encrypted histogram == cleartext oracle == committed fixture, bit-exact.
    assert result["counts"] == _cleartext_aggregate(raw_indices, length)
    assert result["counts"] == expected["counts"]

    # Free one-hot integrity cross-check: bucket counts total exactly N.
    assert sum(result["counts"]) == result["n_contributors"]


@pytest.mark.parametrize("security", SECURITY_LEVELS)
def test_local_loop_full_bucket_count_random_cohort(security):
    """Exercise the manifest bucket count (B=10) with a seeded larger cohort.

    Bit-exact at every certified security level; sentinel decrypts to exactly N.
    """
    length = 10
    n_contributors = 30  # >= manifest min_contributors (25)
    rng = random.Random(20260705)  # reproducible synthetic cohort
    raw_indices = [rng.randrange(length) for _ in range(n_contributors)]

    result = _run_pipeline(raw_indices, length, security=security)

    assert result["n_contributors"] == n_contributors  # sentinel == N, exactly
    assert result["counts"] == _cleartext_aggregate(raw_indices, length)
    assert sum(result["counts"]) == n_contributors  # one-hot => counts total N


@pytest.mark.parametrize("security", SECURITY_LEVELS)
def test_sentinel_tracks_dropped_upload(security):
    """Dropping one upload yields N-1 and decrements that contributor's bucket.

    Verified bit-exact at every certified security level.
    """
    length = 10
    rng = random.Random(7)
    raw_indices = [rng.randrange(length) for _ in range(8)]

    full = _run_pipeline(raw_indices, length, security=security)
    dropped = _run_pipeline(raw_indices[:-1], length, security=security)

    assert full["n_contributors"] == 8
    assert dropped["n_contributors"] == 7
    # And the histogram lost exactly the dropped contributor's single bucket.
    last_encoded = local_data_owner.encode(raw_indices[-1], length)
    assert [
        full_c - dropped_c
        for full_c, dropped_c in zip(full["counts"], dropped["counts"])
    ] == last_encoded


# HomomorphicEncryption.org coeff-modulus CAPs at N=8192: the max Σ coeff bits
# admissible at each RLWE security level. achieved(N, Σ) = strictest level L whose
# CAP[L] still covers Σ (smaller Σ => more secure). This is exactly how the
# benchmark harness computes the `security` column — never read back from SEAL,
# which always validates at tc128.
_CAP_8192 = {256: 118, 192: 152, 128: 218}


def _achieved_level(coeff_bits: list[int]) -> int:
    total = sum(coeff_bits)
    for level in (256, 192, 128):  # strictest first
        if total <= _CAP_8192[level]:
            return level
    raise AssertionError(f"Σ={total} exceeds even the 128-bit cap at N=8192")


@pytest.mark.parametrize("security", SECURITY_LEVELS)
def test_security_chain_certifies_requested_level(security):
    """The chain keygen selects lands in the requested level's q-band.

    i.e. the harness-computed achieved level == the requested level, so the
    benchmark's `security` column reads an honest, distinct 128/192/256.
    """
    assert _achieved_level(local_project_owner.SECURITY[security]) == security


def test_keygen_rejects_unsupported_security_level():
    """An unsupported level is rejected loudly (no silent fallback)."""
    with pytest.raises(ValueError, match="security"):
        local_project_owner.keygen(security=200)


def test_decode_rejects_non_one_hot_aggregate():
    """A tampered aggregate whose counts don't total N is rejected at decode."""
    length = 4
    # counts sum to 3 but sentinel claims N=4 -> integrity failure.
    plain = [1, 1, 1, 0, 4]
    with pytest.raises(ValueError, match="integrity"):
        local_project_owner.decode(plain, length)


def test_encode_rejects_out_of_range_and_missing_bucket():
    """A contributor must land in exactly one published bucket."""
    with pytest.raises(ValueError):
        local_data_owner.encode(10, 10)  # index == B is out of [0, B)
    with pytest.raises(ValueError):
        local_data_owner.encode(-1, 10)
    with pytest.raises(ValueError):
        local_data_owner.encode(None, 10)  # no "missing" escape hatch for one-hot
