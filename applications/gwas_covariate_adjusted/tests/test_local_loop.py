"""Local-loop equivalence + concordance test for `gwas_covariate_adjusted`.

Two claims:

1. HOMOMORPHIC CORRECTNESS (bit-exact). The encrypted additive fold produces the
   same integer sufficient statistics as a pure-Python cleartext aggregate, so the
   covariate-adjusted score test decoded from them is bit-identical to the same
   score test decoded from the cleartext sums (BFV additive, tolerance 0). Verified
   at 128/192/256-bit security and across the multi-chunk (>8192-SNP) path.

2. STATISTICAL CONCORDANCE. Against a cleartext numpy regression that uses the TRUE
   (unrounded) covariates, the fixed-point (SCALE=1024) pipeline reproduces the
   per-SNP -log10(p) with R^2 >= 0.999 — the paper reports R^2 = 1.00 vs exact
   logistic; the residual here is only the covariate fixed-point rounding.

Run:  uv --project signed/env run --group dev pytest tests/     # from bundle root
"""
from __future__ import annotations

import math
import pathlib
import random
import sys

import pytest

BUNDLE_ROOT = pathlib.Path(__file__).resolve().parent.parent / "signed"
sys.path.insert(0, str(BUNDLE_ROOT))

pytest.importorskip("tenseal", reason="TenSEAL not installed; sealed env not built")
np = pytest.importorskip("numpy")

import local_data_owner as ldo  # noqa: E402
import local_project_owner as lpo  # noqa: E402
import server  # noqa: E402

K = 4  # intercept + 3 covariates (sex, age, age²) — the LRA shape
_CAP = {8192: {256: 118, 192: 152, 128: 218}}


def _achieved_security(coeff_bits):
    total = sum(coeff_bits)
    for level in (256, 192, 128):
        if total <= _CAP[8192][level]:
            return level
    raise AssertionError("chain exceeds 128 cap")


def _synthetic(n, m, seed):
    rng = random.Random(seed)
    mafs = [rng.uniform(0.05, 0.5) for _ in range(m)]
    causal = rng.sample(range(m), max(3, m // 400))
    betas = {j: rng.choice((-1, 1)) * rng.uniform(0.7, 1.2) for j in causal}
    recs = []
    for _ in range(n):
        g = [int(rng.random() < p) + int(rng.random() < p) for p in mafs]
        sex = rng.choice((0, 1))
        age = rng.uniform(0.2, 0.9)
        cov = [sex, age, age * age]
        logit = -0.1 + 0.5 * sex + sum(betas[j] * (g[j] - 2 * mafs[j]) for j in causal)
        y = 1 if rng.random() < 1.0 / (1.0 + math.exp(-logit)) else 0
        recs.append({"genotype": g, "phenotype": y, "covariates": cov})
    return recs


def _cleartext_plain(records, length, k):
    """The integer sufficient-statistic sums in the exact shape `decrypt` returns."""
    names = ldo.container_names(length, k)
    sums = {name: None for name in names}
    for rec in records:
        enc = ldo.encode(rec, length, covariate_count=k)
        g, y, x = enc["g"], enc["y"], enc["x"]
        vecs = {"scalars": ldo._scalars_vector(x, y)}
        for c in range(k):
            for ch, chunk in enumerate(ldo._chunk([gj * x[c] for gj in g])):
                vecs[f"xg{c}_{ch}"] = chunk
        for ch, chunk in enumerate(ldo._chunk([gj * y for gj in g])):
            vecs[f"gy_{ch}"] = chunk
        for ch, chunk in enumerate(ldo._chunk([gj * gj for gj in g])):
            vecs[f"gg_{ch}"] = chunk
        for name in names:
            sums[name] = list(vecs[name]) if sums[name] is None else [
                a + b for a, b in zip(sums[name], vecs[name])
            ]
    return sums


def _run_pipeline(records, length, security=128):
    secret_ctx, public_ctx = lpo.keygen(security=security)
    cts = [ldo.encrypt(public_ctx, ldo.encode(r, length, covariate_count=K)) for r in records]
    result_ct = server.compute(cts, public_ctx)
    plain = lpo.decrypt(secret_ctx, result_ct)
    return lpo.decode(plain, length)


def _assert_bit_exact_vs_cleartext(result, records, length):
    oracle = lpo.decode(_cleartext_plain(records, length, K), length)
    assert result["n_contributors"] == oracle["n_contributors"]
    assert result["cases"] == oracle["cases"]
    assert result["covariate_count"] == oracle["covariate_count"] == K
    # Same integer sums -> identical float score test, exactly.
    assert result["p_value"] == oracle["p_value"]
    assert result["score_chi_square"] == oracle["score_chi_square"]
    assert result["z"] == oracle["z"]


def _float_reference_p(records, length):
    """Cleartext regression with the TRUE (unrounded) covariates."""
    X = np.array([[1.0, *r["covariates"]] for r in records])
    y = np.array([r["phenotype"] for r in records], dtype=float)
    G = np.array([ldo.encode_genotype(r["genotype"], length) for r in records], dtype=float)
    n, k = X.shape
    A = X.T @ X; Ainv = np.linalg.inv(A); b = X.T @ y; yy = float(y @ y)
    XtG = X.T @ G; gy = G.T @ y; gg = (G * G).sum(0)
    Ainv_XtG = Ainv @ XtG
    gpp = gg - np.einsum("cm,cm->m", XtG, Ainv_XtG)
    gpy = gy - XtG.T @ (Ainv @ b)
    ok = gpp > 1e-6
    rss_null = yy - float(b @ (Ainv @ b))
    beta = np.where(ok, gpy / np.where(ok, gpp, 1), 0.0)
    rss_full = rss_null - np.where(ok, gpy ** 2 / np.where(ok, gpp, 1), 0.0)
    sig2 = np.maximum(rss_full, 0) / (n - k - 1)
    se = np.sqrt(sig2 / np.where(ok, gpp, 1))
    z = np.where(ok & (se > 0), beta / np.where(se > 0, se, 1), 0.0)
    p = np.array([math.erfc(abs(float(zi)) / math.sqrt(2)) for zi in z]); p[~ok] = 1.0
    return p, ok


def test_bit_exact_vs_cleartext_and_concordant():
    length = 2048
    records = _synthetic(160, length, seed=1)
    result = _run_pipeline(records, length)
    _assert_bit_exact_vs_cleartext(result, records, length)

    # statistical concordance vs true-covariate float regression
    p_ref, ok = _float_reference_p(records, length)
    nlp_enc = np.array([(-math.log10(p) if p > 0 else 50.0) for p in result["p_value"]])
    nlp_ref = np.array([(-math.log10(p) if p > 0 else 50.0) for p in p_ref])
    r2 = float(np.corrcoef(nlp_enc[ok], nlp_ref[ok])[0, 1] ** 2)
    assert r2 >= 0.999, f"concordance R^2={r2} below 0.999"


def test_multi_chunk_crosses_slot_boundary():
    length = 9000
    assert length > ldo.SLOT_COUNT
    records = _synthetic(120, length, seed=2)
    result = _run_pipeline(records, length)
    assert len(result["p_value"]) == length
    _assert_bit_exact_vs_cleartext(result, records, length)


@pytest.mark.parametrize("security", [128, 192, 256])
def test_bit_exact_at_every_security_level(security):
    length = 512
    records = _synthetic(80, length, seed=100 + security)
    result = _run_pipeline(records, length, security=security)
    _assert_bit_exact_vs_cleartext(result, records, length)
    assert _achieved_security(lpo.SECURITY[security]) == security


def test_singular_covariate_design_raises_clean_error():
    """A single-sex cohort makes the sex column constant (collinear with the
    intercept), so X^T X is singular; decode must raise a clean domain ValueError,
    not a bare numpy LinAlgError."""
    length = 128
    rng = random.Random(9)
    records = []
    for _ in range(40):
        g = [int(rng.random() < 0.3) + int(rng.random() < 0.3) for _ in range(length)]
        age = rng.uniform(0.2, 0.9)
        records.append({
            "genotype": g, "phenotype": rng.choice((0, 1)),
            "covariates": [0, age, age * age],  # sex constant 0 -> singular design
        })
    with pytest.raises(ValueError, match="singular"):
        _run_pipeline(records, length)


def test_out_of_range_covariate_rejected_before_encrypt():
    """An un-normalized covariate (age in years, not [0,1]) is refused at encode
    time — a clean local error instead of a silent plaintext-modulus overflow."""
    with pytest.raises(ValueError, match="normalized range|overflow"):
        ldo.encode(
            {"genotype": [0, 1, 2], "phenotype": 1, "covariates": [0, 65.0, 4225.0]},
            3, covariate_count=4,
        )
