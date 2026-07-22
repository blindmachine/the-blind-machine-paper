# Security notes — `gwas_covariate_adjusted`

## Trust boundary

`server.py::compute(inputs, public_context)` is the only server-side code. It has
**no secret-key parameter**, defensively refuses a private context, and runs in the
network-isolated sandbox (`--network none`, read-only fs, non-root, `--cap-drop
ALL`, resource limits) with the **public context and ciphertexts only**. The secret
key is generated, held, and used for decryption **only on the project owner's
machine**. Data owners touch the **public context only**.

## Additive-only ⇒ smallest possible attack surface

Every product a covariate-adjusted (semi-parallel) GWAS needs — the covariate Gram
`x·xᵀ`, `x·y`, and per-SNP `x·g`, `g·y`, `g·g` — is formed by the contributor who
owns the plaintext, locally and in the clear. The server therefore does **only
homomorphic addition**: the public context carries **no relinearization keys and no
Galois keys**, and there is **no encrypted matrix inverse** (unlike the single-key
CKKS prototype, which inverts the k×k covariate matrix homomorphically). The k×k
inverse and the per-SNP score test are cleartext operations on the decrypted
aggregate.

## What is released, and to whom

Only the **aggregate sufficient statistics** are ever decrypted (`aggregate_only:
true`): the covariate Gram `Σ x·xᵀ` (k×k), `Σ x·y`, `Σ y²`, and per-SNP `Σ x·g`,
`Σ g·y`, `Σ g·g`, over a cohort of at least `min_contributors` (=20). These are
cohort-level sums — the covariate-adjusted association summaries a GWAS
meta-analysis already shares — from which the project owner derives per-SNP effect
sizes and p-values in the clear. No individual genotype, phenotype, or covariate is
ever decrypted; every individual-level value stays encrypted end to end.

## Fixed-point exactness envelope

The continuous covariates are fixed-point encoded at scale `S = 1024`, and
**enforced to `|x| ≤ 1` at encode time** (`encode_covariates` refuses an
out-of-range covariate locally — the common "age in years, not [0,1]" mistake — so
it can never silently wrap the plaintext modulus). The largest homomorphic moment is
then the covariate Gram's intercept diagonal `Σ S² = S²·N`; the 38-bit plaintext
modulus `t = 274877562881` keeps every sum **exact in Z_t for N up to ≈ 260,000**
(`S²·N < t`). `decode` additionally **refuses a cohort whose `S²·N` reaches `t`**,
turning the envelope from a footnote into a self-enforcing guard. Beyond the
envelope a larger cohort needs a larger `t` (a different, re-signed bundle). Within the
envelope the homomorphic result is bit-exact; the only approximation is the
covariate quantization at encode time, which makes the released statistic
**concordant** with the cleartext regression (R² = 0.99997 on the demo cohort)
rather than bit-identical — the same order of approximation the paper's own LRA
carries (R² = 1.00 vs exact logistic).

## Cohort integrity & determinism

The `scalars` ciphertext carries an append-1 sentinel that folds to the exact
contributor count `N` (a dropped upload lowers it); `decode` cross-checks `N > k+1`.
BFV addition is deterministic, so the same ordered inputs reproduce a bit-identical
result — verify-by-re-execution holds on the additive fold.
