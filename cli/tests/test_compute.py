"""blind.runtime.compute — the local mirror of the SERVER compute invocation
(argparse --context/--inputs/--out, digest-sorted inputs, sealed-env-or-fallback)."""

from __future__ import annotations

import json

import pytest

from blind.errors import UsageError
from blind.hashing import sha256_file
from blind.runtime.compute import run_compute_stage, sort_inputs_by_digest


def _write_cohort(tmp_path, vectors):
    """Stub ciphertext files (the conftest bundle's value-preserving 'crypto')."""
    paths = []
    for i, vec in enumerate(vectors):
        p = tmp_path / f"ct{i}.ct"
        p.write_text(json.dumps({"vector": vec, "sentinel": 1}))
        paths.append(p)
    context = tmp_path / "public.context"
    context.write_text(json.dumps({"scheme": "stub-additive", "public": True}))
    return context, paths


def test_sort_inputs_by_digest_is_the_canonical_order(tmp_path):
    files = []
    for i in range(4):
        p = tmp_path / f"f{i}"
        p.write_text(f"payload-{i}")
        files.append(p)
    expected = [p for _, p in sorted((sha256_file(p), p) for p in files)]
    assert sort_inputs_by_digest(files) == expected
    # order-invariance: shuffled argument order → identical canonical order
    assert sort_inputs_by_digest(list(reversed(files))) == expected


def test_run_compute_stage_sums_vectors_via_argparse_convention(installed, tmp_path):
    store, bundle, application_id = installed
    context, cts = _write_cohort(tmp_path, [[1, 0, 2, 1], [0, 1, 1, 0], [2, 2, 0, 1]])
    res = run_compute_stage(bundle, context, cts, tmp_path / "result.bin")
    assert res.artifact.exists()
    assert res.sha256.startswith("sha256:")
    assert res.sha256 == sha256_file(res.artifact)
    data = json.loads(res.artifact.read_text())
    assert data["vector"] == [3, 3, 3, 2]
    assert data["sentinel"] == 3
    assert len(res.inputs) == 3


def test_run_compute_stage_is_deterministic_and_order_invariant(installed, tmp_path):
    store, bundle, application_id = installed
    context, cts = _write_cohort(tmp_path, [[1, 0], [0, 1], [2, 2]])
    r1 = run_compute_stage(bundle, context, cts, tmp_path / "r1.bin")
    r2 = run_compute_stage(bundle, context, list(reversed(cts)), tmp_path / "r2.bin")
    assert r1.sha256 == r2.sha256  # same cohort in any order → bit-identical result
    assert r1.inputs == r2.inputs  # both staged in the canonical digest-sorted order


def test_run_compute_stage_requires_context_and_inputs(installed, tmp_path):
    store, bundle, application_id = installed
    context, cts = _write_cohort(tmp_path, [[1]])
    with pytest.raises(UsageError):
        run_compute_stage(bundle, tmp_path / "missing.context", cts, tmp_path / "out.bin")
    with pytest.raises(UsageError):
        run_compute_stage(bundle, context, [], tmp_path / "out.bin")
    with pytest.raises(UsageError):
        run_compute_stage(bundle, context, [tmp_path / "missing.ct"], tmp_path / "out.bin")


def test_run_compute_stage_surfaces_nonzero_exit(installed, tmp_path):
    store, bundle, application_id = installed
    (bundle.root / "30_compute_encrypted.py").write_text(
        "import sys\nsys.stderr.write('boom')\nsys.exit(3)\n"
    )
    context, cts = _write_cohort(tmp_path, [[1, 2]])
    with pytest.raises(UsageError, match="exited 3"):
        run_compute_stage(bundle, context, cts, tmp_path / "out.bin")
