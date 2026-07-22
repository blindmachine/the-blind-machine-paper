# E9 data provenance — HEPRS public example

This study reproduces the per-individual polygenic-risk-score computation of:

> E. Knight, J. Li, M. Jensen, I. Yolou, C. Kockan, and M. Gerstein.
> **"Homomorphic encryption enables privacy preserving polygenic risk scores."**
> *Cell Reports Methods*, 2026. DOI [10.1016/j.crmeth.2025.101271](https://doi.org/10.1016/j.crmeth.2025.101271).
> Software: <https://github.com/gersteinlab/HEPRS> (MIT). Preprint: bioRxiv 2024.05.26.595961.

## What is vendored under `example_data/`

The files below are the **public example dataset** shipped in the HEPRS repository
(`example_data/`), redistributed here **unmodified** under HEPRS's MIT licence
(`example_data/HEPRS_LICENSE`). They are **synthetic** genotypes generated with
HAPGEN2 (Su et al. 2011) — there is **no real human genetic data** here.

| File | What it is |
|------|------------|
| `genotype_10kSNP_50individual.csv` | 50 individuals × 10,000 SNPs + 1 intercept column; additive dosages {0,1,2}. |
| `beta_10kSNP_phenotype0.csv` | The PRS model: 10,001 Ridge-regression betas (signed reals; the intercept slot is 0). |
| `phenotype0_pred_10kSNP_50individual.csv` | HEPRS's own **plaintext** PRS predictions (the reference we reproduce). |
| `phenotype0_true_10kSNP_50individual.csv` | The simulated true phenotype (`h² = 0.3`), for context. |
| `HEPRS_LICENSE` | HEPRS's MIT licence, carried alongside the redistributed data. |

## What is NOT here (controlled access)

HEPRS's headline real-data result is a **110,258-SNP schizophrenia model on 1,146
PsychENCODE individuals** (493 cases / 653 controls). Those genotypes are
**controlled-access** and are **not** redistributed. E9 instead (a) reproduces the
public example above exactly, (b) runs a synthetic HAPGEN2-style scaling sweep at
matched sizes (up to the 110k-SNP × 1,146-sample compute scale; see
`applications/polygenic_score_inference/BENCHMARK.md`), and (c) **cites** HEPRS's
published real-data accuracy — never re-running their controlled-access cohort.

## The reproduction claim

Our `polygenic_score_inference` scores each individual as `Σ_j w_j·g_ij` under the
public model, bit-exact in BFV. Against HEPRS's `phenotype0_pred` this is a clean
affine relation with **slope 1** — our encrypted score equals HEPRS's plaintext
SNP-weighted sum; the only offset is the model's constant Ridge intercept (a public
post-decrypt add), and after accounting for it the residual is at their float32
reference precision. `run_study.py` asserts exactness + Pearson r > 0.9999.
