# Benchmark — `gwas_chi_square` vs Blatt et al. (PNAS 2020)

`gwas_chi_square` reproduces the **Chi-Square GWAS protocol** of

> M. Blatt, A. Gusev, Y. Polyakov, S. Goldwasser. *Secure large-scale
> genome-wide association studies using homomorphic encryption.* PNAS 117(21):
> 11608–11613, 2020. doi:10.1073/pnas.1918257117.
> Reference prototype: <https://gitlab.com/duality-technologies-public/palisade-gwas-demos>
> (`demo-chi2.cpp`).

— the one-degree-of-freedom **allelic association test** — on the SAME public
dataset their prototype ships (`data/random_sample.csv`: 200 individuals, 16,384
SNPs, binary case/control phenotype), and gives **bit-identical** results.

This is not a re-implementation of their cryptography. It is the SAME statistic
recast for The Blind Machine's multiparty model, where **each data owner holds
their own genotype AND phenotype**. That lets the cross term `g·y` be formed
**locally, in the clear**, so the encrypted circuit collapses to the weakest HE
operation there is — **additive-only BFV** (the flagship `allele_frequency_count`
circuit): no ciphertext×ciphertext multiply, no relinearization keys, no Galois
keys. The chi-square ratio, odds ratio and p-value are computed on the project
owner's machine after decryption.

## What is compared

| | Blatt et al. 2020 (PALISADE) | `gwas_chi_square` (The Blind Machine) |
|---|---|---|
| Statistic | 1-df allelic chi-square, odds ratio, p-value | identical |
| Trust model | one data holder encrypts everything to one key | N independent data owners, 1 project owner |
| HE scheme | CKKS (RNS), ring 2^15, depth ~16 | **additive-only BFV**, ring 2^13, depth 0 |
| Where `g·y` is formed | on the server (ciphertext×ciphertext) | **locally by each data owner (cleartext)** |
| Server-side work | full encrypted contingency-table + chi-square | **coordinate-wise sum only** |
| p-value / odds ratio | under encryption | in cleartext, post-decryption |
| Covariates | none (their chi-square is unadjusted) | none (faithful) |

Because we move the only multiplication off the server, we are comparing our
**additive aggregation** against their **full encrypted chi-square circuit** — a
different work split, not a faster FHE engine. The scientific output is the same,
and here it is bit-for-bit identical.

## Correctness (concordance)

The paper reports its encrypted chi-square reproduces the cleartext statistic with
**R² = 1.00**. Because our sufficient statistics are exact integers (BFV in Z_t,
`t = 1032193 > 2N`), our concordance is not merely R² = 1.00 but **bit-exact**:

```
sufficient stats (Σg, Σg·y, #cases, N) bit-exact vs cleartext : True
-log10(p) encrypted-vs-cleartext R²                            : 1.000000
```

The full local-loop equivalence test (`tests/test_local_loop.py`) asserts this at
128/192/256-bit security, across the single- and multi-chunk (>8192-SNP) paths.

## Measured performance

Dataset: Duality's `data/random_sample.csv` — **N = 200 individuals, M = 16,384
SNPs** (101 cases / 99 controls). 128-bit HE security. Single thread, one modern
laptop-class core (Apple Silicon, TenSEAL 0.3.16). Their numbers were measured on
a 2×14-core Xeon E5-2680 v4 server node with 500 GB RAM.

| stage | time | notes |
|---|---|---|
| keygen (project owner, once) | 0.19 s | additive context, no relin/Galois keys |
| encode + encrypt (per data owner) | **18.5 ms** | run on each owner's own machine, fully parallel across owners |
| encrypt, all 200 (if serialized) | 3.7 s | 200 × 18.5 ms |
| **server homomorphic aggregation** | **0.23–0.28 s** | additive fold, streamed (O(1) memory in N) |
| decrypt + decode (χ²/p/OR per SNP) | 0.02 s | project owner, cleartext |
| peak RAM (whole loop, one process) | ~0.65 GiB | streamed fold; the hosted worker stages inputs from disk |

Artifact sizes: per-contributor upload **1.28 MiB**, aggregate result **1.28 MiB**,
public context 1.15 MiB.

## Extrapolation to the paper's headline sizes

`server.compute` is structurally **O(N · M)** — exactly `(N−1)·⌈M/8192⌉`
full-slot ciphertext additions plus one deserialize per contributor ciphertext
(deserialize, at 125 µs, dominates the 32 µs add). Scaling the measured 200×16,384
aggregation linearly (and, like the paper, noting it is embarrassingly parallel
across SNP blocks — 500,000 / 16,384 ≈ 31 blocks):

| GWAS size | Blatt et al. 2020 (28-core node) | `gwas_chi_square` blind aggregation (extrapolated) |
|---|---|---|
| N=15,000, M=16,384 | 98 s (chi-square) | ~15 s single-thread |
| N=25,000, M=49,152 (full cohort) | 8 min | ~1.4 min single-thread |
| N=100,000, M=16,384 | 11 min | ~1–2 min single-thread |
| **N=100,000, M=500,000 (headline)** | **5.6 h single node / 11 min on 31 nodes** | **~0.5–1 h single-thread / ~1–2 min across 31 SNP-block workers** |
| N=26,737, M=263,941 (their real AMD cohort) | — | ~5–10 min single-thread |

(The paper's real data — a dbGaP-gated 26,737-individual age-related macular
degeneration cohort, `phs001039.v1.p1` — is access-controlled, so we replicate on
the public demo cohort they ship and extrapolate the way they did: a linear
projection in N and M.)

The takeaway is **not** "our FHE is an order of magnitude faster." It is that, in a
multiparty setting where each contributor owns their own data, the association
test's only multiplication can be done locally, leaving the blind server an
additive-only job that runs in seconds at demo scale and well under an hour, or a
few parallel minutes, at the paper's largest extrapolated size — while producing
the **identical, bit-exact** allelic chi-square result.

## Reproduce

```bash
# from the repo root, with the sealed env built (uv --project signed/env sync):
cd applications/gwas_chi_square
uv --project signed/env run --group dev python -m pytest tests/        # bit-exact equivalence
# and the paper-facing GWAS-replication experiment (from the repo root):
bash docs/paper/experiments/e10_gwas_chi_square.sh
#   or against Duality's own data:  BLIND_GWAS_CSV=/path/random_sample.csv bash docs/paper/experiments/e10_gwas_chi_square.sh
```
