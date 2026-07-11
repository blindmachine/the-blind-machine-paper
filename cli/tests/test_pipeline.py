"""The local orchestration byte-paths: keygen → encode → encrypt → compute →
decrypt → decode via the numbered stage scripts, plus the equivalence harness."""

from __future__ import annotations

import json

from blind.runtime.stages import run_stage
from blind.simulate import (
    CohortSpec,
    assert_equivalence,
    generate_cohort,
    run_cleartext_oracle,
    run_encrypted_engine,
    simulate,
)
from blind.workspace import (
    run_encode,
    run_encrypt,
    run_keygen,
)


def test_full_stage_pipeline_sums_vectors(installed, tmp_path):
    store, bundle, application_id = installed
    project = "proj_pipe"
    kg = run_keygen(store, project, bundle)
    assert kg.public_context_path.exists()
    assert kg.public_context_sha256.startswith("sha256:")

    vectors = [[1, 0, 2, 1], [0, 1, 1, 0], [2, 2, 0, 1]]
    cts = []
    for i, vec in enumerate(vectors):
        raw = tmp_path / f"raw{i}.json"
        raw.write_text(json.dumps({"vector": vec}))
        enc, _ = run_encode(bundle, raw, tmp_path / f"enc{i}.enc-in")
        ct, _ = run_encrypt(bundle, enc, kg.public_context_path, tmp_path / f"ct{i}.ct")
        cts.append(str(ct))

    comp = run_stage(bundle, "compute",
                     {"inputs": cts, "out": str(tmp_path / "result.ct"),
                      "params": bundle.manifest.raw})
    result = json.loads(comp.artifact.read_text())
    assert result["vector"] == [3, 3, 3, 2]   # column sums
    assert result["sentinel"] == 3            # append-1 sentinel → exact N


def test_decrypt_decode_round_trip(installed, tmp_path):
    from blind.workspace import run_decrypt_decode

    store, bundle, application_id = installed
    project = "proj_dec"
    run_keygen(store, project, bundle)
    # a precomputed "result" ciphertext (value-preserving stub)
    result_ct = tmp_path / "result.ct"
    result_ct.write_text(json.dumps({"vector": [5, 4, 3, 2], "sentinel": 4}))
    out = tmp_path / "out"
    agg = run_decrypt_decode(store, project, bundle, result_ct, out)
    assert agg["vector"] == [5, 4, 3, 2]
    assert agg["sentinel_n"] == 4


def test_synthetic_cohort_is_seed_reproducible():
    spec = CohortSpec(n=10, length=8, seed=7)
    a = generate_cohort(spec)
    b = generate_cohort(spec)
    assert a == b
    c = generate_cohort(CohortSpec(n=10, length=8, seed=8))
    assert a != c
    assert all(all(0 <= g <= 2 for g in vec) for vec in a)


def test_cleartext_oracle_equals_encrypted_engine(installed):
    store, bundle, application_id = installed
    cohort = generate_cohort(CohortSpec(n=6, length=4, seed=42))
    oracle = run_cleartext_oracle(cohort, bundle.manifest.computation)
    encrypted = run_encrypted_engine(bundle, cohort)
    eq = assert_equivalence(oracle, encrypted, bundle.manifest.tolerance)
    assert eq.passed
    assert eq.max_error == 0  # BFV additive → bit-exact
    assert oracle == encrypted


def test_simulate_writes_non_authoritative_run(installed):
    store, bundle, application_id = installed
    spec = CohortSpec(n=5, length=4, seed=1)
    run = simulate(bundle, spec, encrypted=True, emit=["methods", "threat_model"],
                   out_root=store.home / "simulations")
    assert run.directory.exists()
    assert (run.directory / "config.yml").exists()
    assert (run.directory / "equivalence.json").exists()
    assert (run.directory / "provenance.json").exists()
    assert (run.directory / "methods.md").exists()
    assert (run.directory / "threat_model.md").exists()
    d = run.as_dict()
    assert d["authoritative"] is False
    assert d["object"] == "simulation_run"
    assert run.equivalence.passed
