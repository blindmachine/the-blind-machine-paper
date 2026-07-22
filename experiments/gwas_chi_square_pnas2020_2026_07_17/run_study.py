#!/usr/bin/env python3
"""E10 — Reproduce Duality's Chi-Square GWAS (Blatt et al., PNAS 2020) on The Blind Machine.

Reproduces the one-degree-of-freedom **allelic chi-square GWAS** of

    M. Blatt, A. Gusev, Y. Polyakov, S. Goldwasser. "Secure large-scale
    genome-wide association studies using homomorphic encryption." PNAS 117(21):
    11608-11613, 2020. doi:10.1073/pnas.1918257117.
    Reference prototype: gitlab.com/duality-technologies-public/palisade-gwas-demos
    (`demo-chi2.cpp`).

with the platform's `gwas_chi_square` application, which recasts the SAME statistic
for the multiparty setting: each data owner forms the case/control cross term g*y
LOCALLY (they hold both g and y), so the encrypted circuit is **additive-only BFV**
(no ciphertext x ciphertext multiply, no relin keys), and the chi-square / odds
ratio / p-value are computed in cleartext after decryption.

It runs the full trust loop on a seeded synthetic case/control cohort (default
N=200 x M=16,384 SNPs — the shape of Duality's public `data/random_sample.csv`),
and asserts the MACHINE-INDEPENDENT invariant:

  * the decrypted per-SNP sufficient statistics (Sum g, Sum g*y, #cases, N) equal
    the cleartext aggregate **bit-exact** (BFV, tolerance 0 — the paper reports
    R^2 = 1.00 vs cleartext; here it is bit-identical), so the derived chi-square /
    p-value / odds ratio match a cleartext GWAS exactly.

Point it at Duality's own public CSV to reproduce on their exact data:
    BLIND_GWAS_CSV=/path/to/random_sample.csv python3 run_study.py

Timing, memory and ciphertext sizes are REPORTED (hardware-dependent), not
asserted. Self-gates: SKIP (exit 3) if the bundle or TenSEAL is absent.

Run:  python3 run_study.py   (re-execs into the sealed TenSEAL env if needed)
"""
from __future__ import annotations

import csv
import json
import math
import os
import random
import resource
import sys
import time
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
STUDY_DIR = SCRIPT_PATH.parent
EXPERIMENTS_DIR = STUDY_DIR.parent
sys.path.insert(0, str(EXPERIMENTS_DIR))

from public_genomics_common import (  # noqa: E402
    import_module,
    repo_root_from_experiment,
    require_bundle,
)

APP = "gwas_chi_square"
SEED = 42
REPO_ROOT = repo_root_from_experiment(STUDY_DIR)
RESULTS_DIR = STUDY_DIR / "results"


def _ensure_tenseal() -> None:
    """Run under a TenSEAL-capable interpreter: re-exec into the bundle's OWN sealed
    env if the launching python lacks TenSEAL. Self-contained (does not depend on
    any other bundle's env being sealed). SKIP (exit 3) if neither is available."""
    try:
        import tenseal  # noqa: F401
        return
    except ImportError:
        pass
    venv_py = REPO_ROOT / "applications" / APP / "signed" / "env" / ".venv" / "bin" / "python"
    if os.environ.get("_GWAS_REEXEC") == "1" or not venv_py.is_file():
        print(
            f"SKIP: TenSEAL runtime unavailable (no importable tenseal and no sealed "
            f"env at {venv_py}). Build it with "
            f"`uv --project applications/{APP}/signed/env sync`, then re-run.",
            flush=True,
        )
        raise SystemExit(3)
    os.environ["_GWAS_REEXEC"] = "1"
    os.execv(str(venv_py), [str(venv_py), str(SCRIPT_PATH), *sys.argv[1:]])


def peak_rss_mb() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / 1e6 if r > 1e7 else r / 1e3  # macOS bytes vs Linux KiB


def synthetic_cohort(n: int, m: int, seed: int) -> list[dict]:
    """A seeded case/control cohort with real signal: HWE genotypes at random MAF,
    covariates (sex, age, age²) with their own effect, phenotype drawn from a
    logistic model on a handful of 'causal' SNPs plus the covariates, so a few SNPs
    are genuinely associated and covariate adjustment matters. Records carry
    `covariates` so both the chi-square (which ignores them) and the covariate-
    adjusted app can run on the identical cohort."""
    rng = random.Random(seed)
    mafs = [rng.uniform(0.05, 0.5) for _ in range(m)]
    n_causal = max(5, m // 1500)
    causal = rng.sample(range(m), n_causal)
    betas = {j: rng.choice((-1, 1)) * rng.uniform(0.6, 1.1) for j in causal}

    records = []
    for _ in range(n):
        dosage = [int(rng.random() < p) + int(rng.random() < p) for p in mafs]
        sex = rng.choice((0, 1))
        age = rng.uniform(0.2, 0.9)  # normalized to ~[0,1], like the demo covariates
        logit = (-0.1 + 0.5 * sex + 0.3 * (age - 0.5)
                 + sum(betas[j] * (dosage[j] - 2 * mafs[j]) for j in causal))
        y = 1 if rng.random() < 1.0 / (1.0 + math.exp(-logit)) else 0
        records.append({"genotype": dosage, "phenotype": y,
                        "covariates": [sex, age, age * age]})
    return records


def load_csv_cohort(path: Path, m: int) -> list[dict]:
    """Duality's random_sample.csv shape: id, y, gender, age, age2, then SNPs."""
    records = []
    with path.open(newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        m = min(m, len(header) - 5)
        for row in reader:
            if len(row) < 6:
                continue
            y = int(float(row[1]))
            cov = [float(row[2]), float(row[3]), float(row[4])]  # sex, age, age²
            g = []
            for v in row[5:5 + m]:
                try:
                    d = int(float(v))
                except ValueError:
                    d = None
                g.append(d if d in (0, 1, 2) else (None if d is None else max(0, min(2, d))))
            records.append({"genotype": g, "phenotype": 1 if y else 0, "covariates": cov})
    return records


def cleartext_oracle(ldo, lpo, records, m):
    sum_g = [0] * m
    sum_gy = [0] * m
    cases = 0
    for r in records:
        enc = ldo.encode(r, m)
        g, y = enc["g"], enc["y"]
        cases += y
        for j in range(m):
            sum_g[j] += g[j]
            sum_gy[j] += g[j] * y
    n = len(records)
    chi2 = [lpo._allelic_chi_square(sum_gy[j], sum_g[j], cases, n)[0] for j in range(m)]
    p = [lpo._allelic_chi_square(sum_gy[j], sum_g[j], cases, n)[1] for j in range(m)]
    return {"sum_g": sum_g, "sum_gy": sum_gy, "cases": cases, "n": n, "chi2": chi2, "p": p}


def r2(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    sxx = sum((a - mx) ** 2 for a in xs)
    syy = sum((b - my) ** 2 for b in ys)
    return sxy * sxy / (sxx * syy) if sxx > 0 and syy > 0 else 1.0


def main() -> int:
    require_bundle(REPO_ROOT, APP)  # SKIP (exit 3) if the bundle is absent
    _ensure_tenseal()

    signed = REPO_ROOT / "applications" / APP / "signed"
    ldo = import_module("gwas_ldo", signed / "local_data_owner.py")
    lpo = import_module("gwas_lpo", signed / "local_project_owner.py")
    server = import_module("gwas_server", signed / "server.py")

    m = int(os.environ.get("BLIND_GWAS_M", "16384"))
    csv_env = os.environ.get("BLIND_GWAS_CSV")
    if csv_env and Path(csv_env).is_file():
        records = load_csv_cohort(Path(csv_env), m)
        m = len(records[0]["genotype"])
        source = f"Duality public CSV {Path(csv_env).name}"
    else:
        n = int(os.environ.get("BLIND_GWAS_N", "200"))
        records = synthetic_cohort(n, m, SEED)
        source = f"seeded synthetic case/control cohort (seed {SEED})"

    n = len(records)
    cases = sum(r["phenotype"] for r in records)
    print(f"[E10] gwas_chi_square — reproduce Blatt et al. PNAS 2020 (allelic chi-square)")
    print(f"[E10] data: {source} | N={n} individuals | M={m} SNPs | cases={cases} controls={n - cases}")

    def timed(label, fn):
        t = time.perf_counter()
        out = fn()
        dt = time.perf_counter() - t
        print(f"[E10] {label}: {dt:.3f}s")
        return out, dt

    (secret_ctx, public_ctx), t_keygen = timed("keygen (project owner)", lambda: lpo.keygen(security=128))

    def do_encrypt():
        return [ldo.encrypt(public_ctx, ldo.encode(r, m)) for r in records]
    blobs, t_enc = timed(f"encode+encrypt {n} contributors (parallel across owners)", do_encrypt)

    result_ct, t_compute = timed("server.compute (BLIND additive aggregation)", lambda: server.compute(blobs, public_ctx))

    def do_decode():
        plain = lpo.decrypt(secret_ctx, result_ct)
        return lpo.decode(plain, m)
    result, t_decode = timed("decrypt+decode (chi2/p/OR per SNP, cleartext)", do_decode)

    # ---- machine-independent invariant: encrypted == cleartext, BIT-EXACT ----
    orc = cleartext_oracle(ldo, lpo, records, m)
    checks = {
        "sum_g_bit_exact": result["minor_allele_count"] == orc["sum_g"],
        "sum_gy_bit_exact": result["minor_allele_count_in_cases"] == orc["sum_gy"],
        "cases_exact": result["cases"] == orc["cases"],
        "n_exact": result["n_contributors"] == orc["n"],
        "chi2_exact": result["chi_square"] == orc["chi2"],
        "p_exact": result["p_value"] == orc["p"],
    }
    xs = [(-math.log10(p) if p > 0 else 50.0) for p in result["p_value"]]
    ys = [(-math.log10(p) if p > 0 else 50.0) for p in orc["p"]]
    concordance = r2(xs, ys)

    per_cell_us = t_compute / (n * m) * 1e6
    peak = peak_rss_mb()

    # top hits
    order = sorted(range(m), key=lambda j: result["p_value"][j])[:10]
    top = [
        {
            "snp_index": j,
            "chi_square": round(result["chi_square"][j], 4),
            "p_value": result["p_value"][j],
            "neg_log10_p": round(result["neg_log10_p"][j], 4),
            "odds_ratio": (None if math.isnan(result["odds_ratio"][j]) else round(result["odds_ratio"][j], 4)),
        }
        for j in order
    ]

    all_ok = all(checks.values()) and concordance >= 0.999999
    print(f"[E10] INVARIANT bit-exact sufficient statistics: {checks}")
    print(f"[E10] concordance -log10(p) encrypted-vs-cleartext R^2 = {concordance:.6f}")
    print(f"[E10] top SNP idx={top[0]['snp_index']} chi2={top[0]['chi_square']} "
          f"p={top[0]['p_value']:.3e} OR={top[0]['odds_ratio']}")
    print(f"[E10] timing: keygen {t_keygen:.2f}s | encrypt {t_enc:.2f}s ({t_enc/n*1000:.1f} ms/contrib) "
          f"| compute {t_compute:.3f}s | decrypt+decode {t_decode:.3f}s | peak {peak:.0f} MiB")

    # ---- linear extrapolation to the paper's headline sizes (like the paper) ----
    def project(bn, bm, threads=1):
        return per_cell_us * bn * bm / 1e6 / threads
    extrap = {
        "per_contributor_snp_us": round(per_cell_us, 4),
        "n15000_m16384_s": round(project(15000, 16384), 1),
        "n100000_m16384_s": round(project(100000, 16384), 1),
        "n100000_m500000_min_1thread": round(project(100000, 500000) / 60, 1),
        "n100000_m500000_min_31workers": round(project(100000, 500000, 31) / 60, 2),
        "amd_26737_m263941_min_1thread": round(project(26737, 263941) / 60, 1),
    }
    print(f"[E10] extrapolation (server aggregation, O(N*M), single thread): "
          f"100k x 500k = {extrap['n100000_m500000_min_1thread']} min (1 thread), "
          f"{extrap['n100000_m500000_min_31workers']} min (31 SNP-block workers). "
          f"Paper: 5.6 h / 11 min-on-31-nodes.")

    # ---- also reproduce their covariate-adjusted (LRA) protocol, if present ----
    cov_summary = None
    cov_ok = True
    cov_signed = REPO_ROOT / "applications" / "gwas_covariate_adjusted" / "signed"
    if (cov_signed / "server.py").is_file():
        import numpy as np
        cldo = import_module("cov_ldo", cov_signed / "local_data_owner.py")
        clpo = import_module("cov_lpo", cov_signed / "local_project_owner.py")
        cserver = import_module("cov_server", cov_signed / "server.py")
        t = time.perf_counter()
        csec, cpub = clpo.keygen(security=128)
        cblobs = [cldo.encrypt(cpub, cldo.encode(r, m, covariate_count=4)) for r in records]
        cres = cserver.compute(cblobs, cpub)
        cout = clpo.decode(clpo.decrypt(csec, cres), m)
        cov_wall = time.perf_counter() - t
        # concordance vs a cleartext regression on the TRUE (unrounded) covariates
        Xc = np.array([[1.0, *r["covariates"]] for r in records])
        yc = np.array([r["phenotype"] for r in records], dtype=float)
        Gc = np.array([cldo.encode_genotype(r["genotype"], m) for r in records], dtype=float)
        Ac = Xc.T @ Xc; Ai = np.linalg.inv(Ac); bc = Xc.T @ yc; yyc = float(yc @ yc)
        XtGc = Xc.T @ Gc; gyc = Gc.T @ yc; ggc = (Gc * Gc).sum(0)
        gpp = ggc - np.einsum("cm,cm->m", XtGc, Ai @ XtGc); gpy = gyc - XtGc.T @ (Ai @ bc)
        okc = gpp > 1e-6
        rss = (yyc - float(bc @ (Ai @ bc))) - np.where(okc, gpy ** 2 / np.where(okc, gpp, 1), 0.0)
        beta = np.where(okc, gpy / np.where(okc, gpp, 1), 0.0)
        sig2 = np.maximum(rss, 0.0) / (n - 4 - 1); se = np.sqrt(sig2 / np.where(okc, gpp, 1))
        zc = np.where(okc & (se > 0), beta / np.where(se > 0, se, 1), 0.0)
        pref = np.array([math.erfc(abs(float(zi)) / math.sqrt(2)) for zi in zc]); pref[~okc] = 1.0
        penc = np.array(cout["p_value"])
        nE = np.array([(-math.log10(p) if p > 0 else 50.0) for p in penc])
        nR = np.array([(-math.log10(p) if p > 0 else 50.0) for p in pref])
        cov_r2 = float(np.corrcoef(nE[okc], nR[okc])[0, 1] ** 2)
        cov_ok = cov_r2 >= 0.999
        ctop = sorted(range(m), key=lambda j: penc[j])[:5]
        print(f"[E10] covariate-adjusted (LRA) reproduction: -log10(p) concordance R^2 = {cov_r2:.6f} "
              f"(fixed-point covariates) | full loop {cov_wall:.2f}s wall | "
              f"top SNP idx={ctop[0]} -log10p={nE[ctop[0]]:.2f}")
        cov_summary = {
            "application": "gwas_covariate_adjusted",
            "baseline": "Blatt et al. PNAS 2020 (demo-logistic / LRA, semi-parallel score test)",
            "neg_log10_p_r2_vs_cleartext": round(cov_r2, 6),
            "concordant_not_bit_exact": True,
            "covariates": ["sex", "age", "age2"],
            "wall_s": round(cov_wall, 3),
            "per_contributor_blob_kib": round(len(cblobs[0]) / 1024, 1),
            "top_hits_idx": [int(j) for j in ctop],
        }
    else:
        print("[E10] gwas_covariate_adjusted bundle absent — skipping the covariate-adjusted (LRA) half")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary = {
        "experiment": "E10_gwas_chi_square_pnas2020",
        "baseline": "Blatt/Gusev/Polyakov/Goldwasser, PNAS 2020, doi:10.1073/pnas.1918257117 (demo-chi2)",
        "application": APP,
        "data_source": source,
        "n_individuals": n, "m_snps": m, "cases": cases, "controls": n - cases,
        "security_bits": 128,
        "invariant_bit_exact": bool(all(checks.values())),
        "checks": checks,
        "neg_log10_p_r2_vs_cleartext": round(concordance, 6),
        "timing_s": {
            "keygen": round(t_keygen, 3), "encrypt_total": round(t_enc, 3),
            "encrypt_ms_per_contributor": round(t_enc / n * 1000, 2),
            "server_compute": round(t_compute, 3), "decrypt_decode": round(t_decode, 3),
        },
        "peak_rss_mib": round(peak, 0),
        "per_contributor_blob_kib": round(len(blobs[0]) / 1024, 1),
        "aggregate_result_kib": round(len(result_ct) / 1024, 1),
        "extrapolation": extrap,
        "paper_reported": {
            "chi2_n15000_m16384_s": 98,
            "chi2_full_n25000_m49152_min": 8,
            "lra_n15000_m16384_h": 1.1,
            "headline_n100000_m500000": "5.6 h single node / 11 min on 31 nodes",
            "hardware": "2x14-core Xeon E5-2680 v4, 500 GB RAM",
        },
        "top_hits": top,
        "covariate_adjusted": cov_summary,
    }
    (RESULTS_DIR / "gwas_chi_square_pnas2020.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (RESULTS_DIR / "gwas_top_hits.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["snp_index", "chi_square", "p_value", "neg_log10_p", "odds_ratio"])
        w.writeheader()
        w.writerows(top)
    print(f"[E10] wrote {RESULTS_DIR/'gwas_chi_square_pnas2020.json'}")

    if not (all_ok and cov_ok):
        print("[E10] RESULT: FAIL — encrypted GWAS did not match the cleartext reference "
              f"(chi_square_ok={all_ok}, covariate_adjusted_ok={cov_ok})")
        return 1
    print("[E10] RESULT: PASS — allelic chi-square GWAS is bit-identical to cleartext"
          + (", covariate-adjusted GWAS concordant at R^2>=0.999" if cov_summary else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
