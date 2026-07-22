# Benchmark — `gwas_covariate_adjusted` vs Blatt et al. (PNAS 2020)

`gwas_covariate_adjusted` reproduces the **covariate-adjusted GWAS** (Logistic
Regression Approximation / semi-parallel score test) of

> M. Blatt, A. Gusev, Y. Polyakov, S. Goldwasser. *Secure large-scale
> genome-wide association studies using homomorphic encryption.* PNAS 117(21):
> 11608–11613, 2020. doi:10.1073/pnas.1918257117.
> Reference prototype: `palisade-gwas-demos/demo-logistic.cpp` (3 covariates:
> sex, age, age²).

on the same public demo dataset (`random_sample.csv`: 200 individuals, 16,384 SNPs,
binary phenotype, 3 covariates), adjusting each SNP's association for the covariates.

## What is compared

| | Blatt et al. 2020 (PALISADE, LRA) | `gwas_covariate_adjusted` (The Blind Machine) |
|---|---|---|
| Statistic | covariate-adjusted per-SNP association (semi-parallel score test) | identical decomposition |
| Covariates | sex, age, age² (fit once) | sex, age, age² (fit once, in cleartext) |
| HE scheme | CKKS, ring 2¹⁵, **multiplicative depth ~15** | **additive-only BFV**, ring 2¹³, depth 0 |
| Covariate matrix inverse | homomorphic (encrypted k×k inverse) | **cleartext, post-decrypt** (k×k) |
| Where products are formed | on the server (ciphertext×ciphertext) | **locally by each data owner (cleartext)** |
| Server-side work | full encrypted score test + matrix inverse | **coordinate-wise sum only** |

Because every product a semi-parallel GWAS needs is owned by a single contributor
(who holds their own g, y, and covariates), it moves off the server, and the
encrypted matrix inverse the Duality prototype performs disappears entirely — the
k×k covariate inverse is a cleartext operation on the decrypted aggregate.

## Correctness (concordance)

The covariates are continuous, so they are fixed-point encoded (scale 1024); the
homomorphic sums are exact BFV and the residual is only the covariate rounding. The
paper reports its LRA reproduces exact logistic regression with R² = 1.00; here the
per-SNP −log₁₀(p) reproduces the cleartext regression with **R² = 0.99997** (max
−log₁₀(p) difference 0.023 on the demo cohort). Genotype/phenotype sufficient
statistics are exact integers. The local-loop test asserts the encrypted fold is
bit-exact vs the cleartext integer aggregate (so the decoded score test is
bit-identical) at 128/192/256-bit security.

## Measured performance

Dataset: `random_sample.csv` — N = 200, M = 16,384 SNPs, 3 covariates, 101 cases /
99 controls. 128-bit HE security, single core (Apple silicon), TenSEAL 0.3.16.
Blatt et al.'s LRA was measured on a 2×14-core Xeon E5-2680 v4, 500 GB RAM.

| stage | time | notes |
|---|---|---|
| keygen (project owner) | 0.08 s | additive context (38-bit plaintext modulus), no relin/Galois keys |
| encode + encrypt (per data owner) | 58 ms | ~3× the chi-square app (k covariate cross-series); parallel across owners |
| **server homomorphic aggregation** | **0.56 s** | additive fold, streamed |
| decrypt + decode (k×k inverse + score test per SNP) | 0.05 s | project owner, cleartext |
| peak RAM (whole loop) | ~0.85 GiB | streamed fold |

Per-contributor upload **3.3 MiB**, aggregate result **3.3 MiB**.

## Extrapolation to the paper's headline sizes

The additive fold is O(N·M). Scaling the measured 200×16,384 aggregation linearly:

| GWAS size | Blatt et al. 2020 (LRA, 28-core node) | `gwas_covariate_adjusted` server aggregation |
|---|---|---|
| 15,000 × 16,384 | 1.1 h | ≈ 0.7 min |
| **100,000 × 16,384** | **7.7 h (their extrapolation)** | **≈ 5 min single core** |
| 100,000 × 500,000 | ~235 h (linear projection of their 7.7 h) | ≈ 2.4 h single core / ≈ 5 min on 31 SNP-block workers |

As with the chi-square app, the comparison is not FHE-vs-FHE at the same task: the
covariate-adjusted association's products and its k×k matrix inverse are done by the
parties that own the plaintext (each contributor locally; the analyst on the
decrypted aggregate), leaving the blind server an additive-only job. The scientific
output is the covariate-adjusted association, concordant with the cleartext
regression at R² = 0.99997.

## Reproduce

```bash
cd applications/gwas_covariate_adjusted
uv --project signed/env run --group dev python -m pytest tests/
# paper-facing experiment (runs the chi-square and covariate-adjusted apps together):
bash docs/paper/experiments/e10_gwas_chi_square.sh
```
