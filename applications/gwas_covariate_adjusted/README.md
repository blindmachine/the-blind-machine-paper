# `gwas_covariate_adjusted` — encrypted covariate-adjusted GWAS

A curated Blind Machine application that runs a **covariate-adjusted genome-wide
association study** over encrypted genotypes: a per-SNP **semi-parallel score test**
(after Sikorska et al.) for case/control association, adjusted for covariates
(sex, age, age²) — with per-SNP effect size, score chi-square, and p-value.

It reproduces the **Logistic Regression Approximation (LRA)** protocol of

> Marcelo Blatt, Alexander Gusev, Yuriy Polyakov, Shafi Goldwasser.
> *Secure large-scale genome-wide association studies using homomorphic
> encryption.* PNAS 117(21):11608–11613, 2020.
> [doi:10.1073/pnas.1918257117](https://doi.org/10.1073/pnas.1918257117) ·
> reference prototype
> [`palisade-gwas-demos`](https://gitlab.com/duality-technologies-public/palisade-gwas-demos)
> (`demo-logistic.cpp`)

which fits the covariate (null) model once and derives a per-SNP score statistic —
the same "fit once, then O(k) per SNP" structure realized here. See
[`BENCHMARK.md`](BENCHMARK.md) for the head-to-head comparison.

## The idea: form every product locally, keep the server additive

A covariate-adjusted GWAS needs three kinds of product: the covariate Gram matrix
`XᵀX` (k×k), the covariate/phenotype term `Xᵀy`, and, per SNP, the covariate/
genotype cross term `Xᵀg` (plus `gᵀy`, `gᵀg`). In the Duality prototype these are
formed under CKKS with a homomorphic **matrix inverse** and ciphertext×ciphertext
products (multiplicative depth ~15). Here **each data owner holds their own
genotype `g`, phenotype `y`, and covariates `x`**, so every one of those products
is formed **locally, in the clear**, before encryption. What reaches the blind
server is only sums-to-be-taken, so its whole circuit is **additive-only BFV** — no
ciphertext×ciphertext multiply, no relinearization keys, no Galois keys, no
encrypted matrix inverse. The k×k covariate inverse and the per-SNP score test run
on the project owner's machine, in cleartext, after decryption.

The semi-parallel decomposition (Sikorska et al.), all in cleartext post-decrypt:

```
g⊥ᵀg⊥ = gᵀg − (Xᵀg)ᵀ A⁻¹ (Xᵀg)          # genotype variance orthogonal to covariates
g⊥ᵀy  = gᵀy − (Xᵀg)ᵀ A⁻¹ (Xᵀy)          # A = XᵀX (k×k), inverted once
β      = g⊥ᵀy / g⊥ᵀg⊥                     # covariate-adjusted effect
z      = β / SE(β),   p = erfc(|z|/√2)    # score ~ χ²₁
```

## Fixed point, so concordant rather than bit-exact

The covariates (age, age²) are continuous, so they are encoded in **fixed point**
(scale 1024). The homomorphic sums are still exact BFV; the residual is only the
covariate rounding. On Duality's demo cohort this reproduces the cleartext
regression's per-SNP −log₁₀(p) with **R² = 0.99997** (the paper reports R² = 1.00
vs exact logistic). Genotype/phenotype terms (`gᵀy`, `gᵀg`, #cases, N) stay exact
integers.

## Roles and flow (RFC 0002 `aggregate` scenario)

- **Data owner** (`local_data_owner.py`) — `encode` a `{"genotype":[...],
  "phenotype":0|1,"covariates":[sex,age,age²]}` record (covariates **normalized to
  [-1, 1]**, enforced at encode time); `encrypt` it into ONE packed BMCT1 blob of
  additive sufficient-statistic ciphertexts. Public context only.
- **Server** (`server.py`) — `compute`: stream-fold every contributor's blob into
  one aggregate by additive homomorphic sum. Public context + ciphertexts only.
- **Project owner** (`local_project_owner.py`) — `keygen`; `decrypt` the aggregate
  (secret key, local only); `decode` = invert the k×k covariate matrix and run the
  per-SNP score test in cleartext.

## Test / run

```bash
cd applications/gwas_covariate_adjusted
uv --project signed/env sync --group dev
uv --project signed/env run --group dev python -m pytest tests/
```

The tests assert the encrypted additive fold is **bit-exact** vs the cleartext
integer aggregate (so the decoded score test is bit-identical) at 128/192/256-bit
security and across the multi-chunk path, plus **R² ≥ 0.999** concordance with a
numpy regression on the true (unrounded) covariates.
