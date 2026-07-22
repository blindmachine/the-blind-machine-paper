#!/usr/bin/env python3
"""E9 — Reproduce a published FHE-PRS study (HEPRS) on The Blind Machine.

Reproduces the per-individual polygenic-risk-score computation of Knight et al.,
"Homomorphic encryption enables privacy preserving polygenic risk scores"
(Cell Reports Methods, 2026; HEPRS, github.com/gersteinlab/HEPRS) — but with the
platform's `polygenic_score_inference` application, which scores under a PUBLIC
model (ciphertext x plaintext + rotate-sum, no ciphertext x ciphertext, no relin).

It runs on the HEPRS **public** example (10k SNP x 50 individual, vendored under
`example_data/` — MIT-licensed synthetic HAPGEN2 data, see PROVENANCE.md) and a
small synthetic scaling check, and asserts the MACHINE-INDEPENDENT invariants:

  * the decrypted per-individual score equals the plaintext oracle **bit-exact**
    (BFV, tolerance 0 — stronger than HEPRS's CKKS, which has a small MSE), and
  * our per-individual scores reproduce HEPRS's published plaintext predictions
    (`phenotype0_pred_...csv`) as a clean affine relation (slope 1, Pearson
    r > 0.9999): our PRS = HEPRS's SNP-weighted sum, up to the model's constant
    intercept and their float32 reference precision.

Timing, memory, and ciphertext sizes are REPORTED (hardware-dependent), not
asserted. Self-gates: SKIP (exit 0) if the bundle or TenSEAL is absent.

Run:  python3 run_study.py   (re-execs into a sealed TenSEAL env if needed)
"""
from __future__ import annotations

import csv
import json
import os
import resource
import sys
import time
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
STUDY_DIR = SCRIPT_PATH.parent
EXPERIMENTS_DIR = STUDY_DIR.parent
sys.path.insert(0, str(EXPERIMENTS_DIR))

from public_genomics_common import (  # noqa: E402
    _skip,
    ensure_tenseal_runtime,
    repo_root_from_experiment,
    require_bundle,
)

APP = "polygenic_score_inference"
REPO_ROOT = repo_root_from_experiment(STUDY_DIR)
RESULTS_DIR = STUDY_DIR / "results"
EXAMPLE_DIR = STUDY_DIR / "example_data"
WEIGHT_SCALE = 1_000_000  # fixed-point factor for the real (signed) betas


def _read_csv_rows(path: Path):
    return [row for row in csv.reader(path.open()) if row]


def peak_rss_mb() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / 1e6 if r > 1e7 else r / 1e3  # macOS bytes vs Linux KiB


def _score_one(do, server, public_ctx, evaluator, raw, length, weights_scaled):
    """Encrypt one contributor and score it with the EXPLICIT public weights.

    This is the exact server-side path (`server.score_individual` over a
    `BFVEvaluator`), with the real (HEPRS) model injected as the public weight
    vector — the same core `server.compute` runs, except `compute` loads its
    weights from the seed / `model_weights.json` rather than a caller-supplied
    vector, so a reproduction against arbitrary published betas injects them here.
    Returns (encoded, encrypted_blob, scored_result_bytes).
    """
    encoded = do.encode(raw, length)
    blob = do.encrypt(public_ctx, encoded)
    chunk_cts = [evaluator.load(c) for c in server.unframe(blob)[1:]]
    prs_ct = server.score_individual(chunk_cts, weights_scaled, evaluator)
    return encoded, blob, server.frame([prs_ct.serialize()])


def reproduce_example(do, po, server):
    """HEPRS public example: 10k SNP x 50 individuals, real signed betas."""
    geno = [[int(x) for x in row] for row in _read_csv_rows(EXAMPLE_DIR / "genotype_10kSNP_50individual.csv")]
    betas = [float(x) for x in _read_csv_rows(EXAMPLE_DIR / "beta_10kSNP_phenotype0.csv")[0]]
    their_pred = [float(row[0]) for row in _read_csv_rows(EXAMPLE_DIR / "phenotype0_pred_10kSNP_50individual.csv")]
    length = len(betas)
    if any(len(g) != length for g in geno):
        raise AssertionError("genotype/beta column mismatch in vendored example")

    w_scaled = [round(b * WEIGHT_SCALE) for b in betas]
    server._check_value_envelope(w_scaled)

    secret, public = po.keygen(security=128)
    evaluator = server.BFVEvaluator(__import__("tenseal").context_from(public))
    t0 = time.perf_counter()
    scores_scaled = []
    exact = True
    for g in geno:
        encoded, _blob, result = _score_one(do, server, public, evaluator, g, length, w_scaled)
        oracle = sum(encoded[j] * w_scaled[j] for j in range(length))
        got = po.decrypt(secret, result)[0]
        if got != oracle:
            exact = False
        scores_scaled.append(got)
    wall = time.perf_counter() - t0

    ours = [s / WEIGHT_SCALE for s in scores_scaled]
    n = len(ours)
    # affine fit of THEIR pred against OUR score (slope should be 1; the offset is
    # the model's constant Ridge intercept, which is a public post-decrypt add).
    mo = sum(ours) / n
    mp = sum(their_pred) / n
    sxx = sum((o - mo) ** 2 for o in ours)
    slope = sum((ours[i] - mo) * (their_pred[i] - mp) for i in range(n)) / sxx
    intercept = mp - slope * mo
    resid = max(abs(their_pred[i] - (slope * ours[i] + intercept)) for i in range(n))
    so = sxx ** 0.5
    sp = sum((p - mp) ** 2 for p in their_pred) ** 0.5
    pearson = sum((ours[i] - mo) * (their_pred[i] - mp) for i in range(n)) / (so * sp)

    return {
        "dataset": "HEPRS public example (10,000 SNP x 50 individuals, synthetic HAPGEN2)",
        "snps": length,
        "samples": n,
        "weight_scale": WEIGHT_SCALE,
        "encrypted_equals_plaintext_oracle_exact": exact,
        "pearson_r_vs_heprs_pred": pearson,
        "affine_slope_vs_heprs_pred": slope,
        "affine_intercept_vs_heprs_pred": intercept,
        "max_residual_after_intercept": resid,
        "wall_seconds": wall,
        "peak_rss_mb": peak_rss_mb(),
    }


def scaling_check(do, po, server):
    """A small synthetic scaling check (exactness is the invariant; time reported)."""
    import random

    secret, public = po.keygen(security=128)
    evaluator = server.BFVEvaluator(__import__("tenseal").context_from(public))
    rows = []
    for (L, N) in [(10000, 20), (50000, 20)]:
        rng = random.Random(42)
        w = [rng.choice((-1, 1)) * rng.randint(1, 2000) for _ in range(L)]
        server._check_value_envelope(w)
        exact = True
        t0 = time.perf_counter()
        for _ in range(N):
            g = [rng.choices((0, 1, 2), weights=(0.64, 0.29, 0.07))[0] for _ in range(L)]
            encoded, _blob, result = _score_one(do, server, public, evaluator, g, L, w)
            oracle = sum(encoded[j] * w[j] for j in range(L))
            got = po.decrypt(secret, result)[0]
            if got != oracle:
                exact = False
        wall = time.perf_counter() - t0
        rows.append({"snps": L, "samples": N, "exact": exact,
                     "wall_seconds": wall, "ms_per_individual": wall * 1000 / N})
    return rows


def main() -> int:
    ensure_tenseal_runtime(REPO_ROOT, SCRIPT_PATH)
    require_bundle(REPO_ROOT, APP)
    if not (EXAMPLE_DIR / "genotype_10kSNP_50individual.csv").is_file():
        _skip("HEPRS example data not vendored under example_data/")

    sys.path.insert(0, str(REPO_ROOT / "applications" / APP / "signed"))
    try:
        import local_data_owner as do  # noqa: E402
        import local_project_owner as po  # noqa: E402
        import server  # noqa: E402
    except Exception as exc:  # pragma: no cover
        _skip(f"could not import {APP} author modules: {exc}")

    print("E9 — HEPRS reproduction on The Blind Machine (`polygenic_score_inference`)")
    example = reproduce_example(do, po, server)
    scaling = scaling_check(do, po, server)

    ok = (
        example["encrypted_equals_plaintext_oracle_exact"]
        and example["pearson_r_vs_heprs_pred"] > 0.9999
        and abs(example["affine_slope_vs_heprs_pred"] - 1.0) < 1e-3
        and all(r["exact"] for r in scaling)
    )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "reproduction.json").write_text(
        json.dumps({"example": example, "scaling": scaling, "pass": ok}, indent=2)
    )
    (RESULTS_DIR / "provenance.json").write_text(json.dumps({
        "study": "heprs_prs_reproduction_2026_07_17",
        "reproduces": {
            "paper": "Knight et al., Homomorphic encryption enables privacy preserving "
                     "polygenic risk scores, Cell Reports Methods 2026",
            "doi": "10.1016/j.crmeth.2025.101271",
            "software": "https://github.com/gersteinlab/HEPRS",
        },
        "application": APP,
        "data": "HEPRS public example_data/ (MIT-licensed synthetic HAPGEN2; see PROVENANCE.md). "
                "The real PsychENCODE schizophrenia genotypes are controlled-access and are NOT used.",
        "security_bits": 128,
    }, indent=2))

    print(f"  example: exact={example['encrypted_equals_plaintext_oracle_exact']} "
          f"pearson_r={example['pearson_r_vs_heprs_pred']:.9f} slope={example['affine_slope_vs_heprs_pred']:.6f} "
          f"resid={example['max_residual_after_intercept']:.2e} peakRSS={example['peak_rss_mb']:.0f}MB")
    for r in scaling:
        print(f"  scaling L={r['snps']} N={r['samples']}: exact={r['exact']} {r['ms_per_individual']:.1f} ms/indiv")
    print("RESULT: PASS" if ok else "RESULT: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
