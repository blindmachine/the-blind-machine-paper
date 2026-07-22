"""Canonical hashing is the trust substrate — reproducible + tamper-evident."""

from __future__ import annotations

from pathlib import Path

import pytest

from blind.hashing import (
    canonical_bundle_digest,
    certificate_hash,
    cohort_commitment,
    digests_match,
    env_lock_digest,
    normalize_digest,
    application_id,
    sha256_prefixed,
    short,
    split_application_id,
)

# The published reference vector for the flagship bundle (applications/README.md).
# Computed by the Ruby BlindWorker::BundleHasher (what the server pins) and the
# reference applications/hash_bundle.py. The CLI MUST agree or `applications install`
# fails closed on every real bundle — this test guards that cross-language
# invariant so the serialization can never silently drift again.
_FLAGSHIP_BUNDLE = Path(__file__).resolve().parents[2] / "applications" / "allele_frequency_count"
_FLAGSHIP_BUNDLE_DIGEST = (
    "sha256:b94bd9320ea0f15b2ec265ecd0cf855f273548ffb920f395212256f4d4664eed"
)


@pytest.mark.skipif(
    not (_FLAGSHIP_BUNDLE / "signed" / "manifest.yml").exists(),
    reason="flagship bundle not present (CLI checked out standalone)",
)
def test_flagship_bundle_digest_matches_reference_vector():
    assert canonical_bundle_digest(_FLAGSHIP_BUNDLE) == _FLAGSHIP_BUNDLE_DIGEST


def test_bundle_digest_is_reproducible_and_order_independent(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "manifest.yml").write_text("name: x\n")
    (a / "10_encode.py").write_text("print(1)\n")
    d1 = canonical_bundle_digest(a)
    d2 = canonical_bundle_digest(a)
    assert d1 == d2
    assert d1.startswith("sha256:")


def test_bundle_digest_excludes_signature_and_derived(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "manifest.yml").write_text("name: x\n")
    before = canonical_bundle_digest(a)
    (a / ".blind-signature").write_text("deadbeef\n")
    (a / ".digest").write_text(before + "\n")
    (a / "env_lock").write_text("sha256:abc\n")
    after = canonical_bundle_digest(a)
    assert before == after  # signature + derived files do not change identity


def test_bundle_digest_hashes_signed_payload_and_excludes_support_files(tmp_path):
    a = tmp_path / "a"
    signed = a / "signed"
    tests = a / "tests"
    signed.mkdir(parents=True)
    tests.mkdir()
    (signed / "manifest.yml").write_text("name: x\n")
    (signed / "server.py").write_text("def compute(inputs, public_context): return b''\n")
    (a / "README.md").write_text("# x\n")
    (a / "SECURITY.md").write_text("review notes\n")
    (a / "BENCHMARK.md").write_text("timings\n")
    (tests / "test_local_loop.py").write_text("def test_x(): assert True\n")

    before = canonical_bundle_digest(a)
    (tests / "test_local_loop.py").write_text("def test_x(): assert False\n")
    after_tests = canonical_bundle_digest(a)
    (a / "README.md").write_text("# renamed docs\n")
    (a / "SECURITY.md").write_text("new review notes\n")
    (a / "BENCHMARK.md").write_text("new timings\n")
    after_docs = canonical_bundle_digest(a)
    (signed / "server.py").write_text("def compute(inputs, public_context): return b'x'\n")
    after_signed = canonical_bundle_digest(a)

    assert before == after_tests
    assert before == after_docs
    assert before != after_signed


def test_new_contract_digest_is_stable_when_shims_are_materialized(tmp_path):
    """Regression (trust-loop exit 6): the six kit stage shims are materialized into a
    NEW-CONTRACT bundle (server.py) at encode/encrypt time and are never signed into
    it. The recomputed digest MUST stay equal to the author-only one — otherwise a
    contributor's 2nd upload from the same ~/.blind recomputes a different bundle
    digest and the RFC 0003 signed-invitation application-digest check fails closed."""
    from blind.runtime.shims import SHIM_NAMES

    author = tmp_path / "author_only"
    author.mkdir()
    (author / "manifest.yml").write_text("name: x\n")
    (author / "server.py").write_text("def compute(inputs, public_context): return b''\n")
    (author / "local_data_owner.py").write_text("def encode(x): return x\n")
    author_only_digest = canonical_bundle_digest(author)

    # what run_encode / run_encrypt do to the payload dir before a stage runs
    for name in SHIM_NAMES:
        (author / name).write_text("# kit-owned shim, materialized at run time\n")
    assert canonical_bundle_digest(author) == author_only_digest


def test_legacy_bundle_still_hashes_numbered_files(tmp_path):
    """A legacy self-contained bundle (no server.py) is NOT shim-excluded — its
    numbered files are the signed author code and must change the digest."""
    b = tmp_path / "legacy"
    b.mkdir()
    (b / "manifest.yml").write_text("name: y\n")
    before = canonical_bundle_digest(b)
    (b / "10_encode.py").write_text("print(1)\n")
    assert canonical_bundle_digest(b) != before


def test_bundle_digest_changes_when_a_stage_changes(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "manifest.yml").write_text("name: x\n")
    (a / "10_encode.py").write_text("print(1)\n")
    d1 = canonical_bundle_digest(a)
    (a / "10_encode.py").write_text("print(2)\n")
    d2 = canonical_bundle_digest(a)
    assert d1 != d2


def test_cohort_commitment_is_sort_invariant():
    hashes = ["sha256:cc", "sha256:aa", "sha256:bb"]
    c1 = cohort_commitment(hashes, "proj_1", "p@sha256:zz")
    c2 = cohort_commitment(list(reversed(hashes)), "proj_1", "p@sha256:zz")
    assert c1 == c2
    # binding to project + application changes the commitment
    assert c1 != cohort_commitment(hashes, "proj_2", "p@sha256:zz")
    assert c1 != cohort_commitment(hashes, "proj_1", "p@sha256:yy")


def test_certificate_hash_ignores_its_own_field():
    body = {"a": 1, "b": [1, 2], "certificate_hash": "sha256:stale"}
    h1 = certificate_hash(body)
    h2 = certificate_hash({"a": 1, "b": [1, 2]})
    assert h1 == h2


def test_env_lock_digest_reproducible():
    e1 = env_lock_digest(b"lock", b"3.11\n", "runner")
    e2 = env_lock_digest(b"lock", b"3.11\n", "runner")
    assert e1 == e2 and e1.startswith("sha256:")
    assert e1 != env_lock_digest(b"lock2", b"3.11\n", "runner")


def test_application_id_helpers():
    assert application_id("n", "sha256:ab") == "n@sha256:ab"
    assert application_id("n@sha256:ab", "sha256:cd") == "n@sha256:ab"
    assert split_application_id("n@sha256:ab") == ("n", "sha256:ab")
    assert split_application_id("n") == ("n", None)


def test_short_form():
    assert short("sha256:4d1e0000000000c0") == "sha256:4d1e…c0"
    assert sha256_prefixed(b"x").startswith("sha256:")


def test_normalize_digest_accepts_both_encodings():
    # The platform serves bare 64-hex; the CLI's canonical form is prefixed.
    hexval = "ab" * 32
    assert normalize_digest(f"sha256:{hexval}") == hexval
    assert normalize_digest(hexval) == hexval
    assert normalize_digest(f"SHA256:{hexval.upper()}") == hexval
    assert normalize_digest(None) == ""
    assert normalize_digest("") == ""


def test_digests_match_across_encodings():
    hexval = "ab" * 32
    assert digests_match(f"sha256:{hexval}", hexval)
    assert digests_match(hexval, f"sha256:{hexval}")
    assert digests_match(hexval, hexval)
    assert not digests_match(hexval, "cd" * 32)
    # absence of evidence is not a verification
    assert not digests_match(None, None)
    assert not digests_match("", "")
    assert not digests_match(hexval, None)
