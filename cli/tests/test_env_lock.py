"""env_lock convention pin: EMPTY runner metadata (the deps-only fingerprint).

This is the canonical convention — what applications/hash_bundle.py, the Ruby twin
(BlindWorker::BundleHasher), the server DB column, and the published reference
vector all compute. Runner/platform pinning travels in the @sha256:-pinned
runner image, never inside env_lock.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blind.hashing import env_lock_digest
from blind.runtime.bundle import load_bundle

# Repo layout: cli/tests/ → cli/ → repo root → applications/allele_frequency_count
FLAGSHIP = Path(__file__).resolve().parents[2] / "applications" / "allele_frequency_count"

# The published reference vector (applications/README.md "Reference test vector").
FLAGSHIP_ENV_LOCK = "sha256:afd4ed396fee544ee91774f8fe3cc1b9d26d6796558b0fa0897660655785963f"


def test_compute_env_lock_uses_empty_runner_metadata(make_bundle):
    src, _ = make_bundle()
    b = load_bundle(src)
    uv_lock = (src / "signed" / "env" / "uv.lock").read_bytes()
    pyver = (src / "signed" / "env" / ".python-version").read_bytes()
    assert b.compute_env_lock() == env_lock_digest(uv_lock, pyver, runner_meta="")
    # A non-empty runner metadata would produce a DIFFERENT digest — the bug
    # this pins against ("blind-runner/v1" drifted from the reference vector).
    assert b.compute_env_lock() != env_lock_digest(uv_lock, pyver, runner_meta="blind-runner/v1")


@pytest.mark.skipif(not FLAGSHIP.is_dir(), reason="flagship application bundle not present")
def test_flagship_env_lock_matches_published_reference_vector():
    b = load_bundle(FLAGSHIP)
    assert b.compute_env_lock() == FLAGSHIP_ENV_LOCK
