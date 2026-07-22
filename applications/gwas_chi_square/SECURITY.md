# Security notes — `gwas_chi_square`

## Trust boundary

`server.py::compute(inputs, public_context)` is the only code that runs
server-side. It has **no secret-key parameter** — structurally incapable of
receiving one — and defensively refuses a context that carries a secret key
(`context.is_private()`). It runs in the network-isolated sandbox (`--network
none`, read-only fs, non-root, `--cap-drop ALL`, manifest resource limits) with
the **public context and ciphertexts only**. The server never sees a plaintext
genotype or phenotype.

The secret key is generated, held, and used for decryption **only on the project
owner's machine** (`local_project_owner.keygen` / `decrypt`). Data owners touch
the **public context only** (`local_data_owner.encrypt`).

## Additive-only ⇒ the smallest possible attack surface

Each data owner forms the cross term `g·y` locally, so the server does **only
homomorphic addition**. The public context therefore carries **no relinearization
keys and no Galois keys** — the server literally cannot multiply or rotate
ciphertexts. This is a strictly smaller cryptographic surface than the
`genotype_phenotype_covariance` protocol (which ships relin keys for a server-side
ct×ct product).

## What is released, and to whom

Only the **aggregate sufficient statistics** are ever decrypted (`release_policy.
aggregate_only: true`): per-SNP `Σg` and `Σg·y`, and the scalars `#cases` and `N`.
No individual contribution is ever decrypted.

These are **cohort-level sums over ≥ `min_contributors` (=20) individuals** — the
same per-SNP association sufficient statistics routinely shared across GWAS
consortia in meta-analysis. The released chi-square / p-value / odds ratio are a
deterministic cleartext function of them, and are exactly the intended scientific
output of a GWAS.

**Disclosure granularity vs the paper.** Blatt et al. decrypt only the final
per-SNP p-values; here the project owner decrypts the sufficient statistics and
computes the p-values locally. The two are informationally close — the p-value is a
deterministic function of the sufficient statistics, and the sufficient statistics
are the standard shareable summary — but a downstream policy that must release
*only* p-values should note this difference. Both models keep every **individual**
genotype and phenotype encrypted end to end.

## Cohort integrity

The `meta` ciphertext folds to `[Σy, N]`. Its `N` slot is a live **contributor
count** (a dropped or withheld upload lowers `N`), decrypted and checked in
`decode` (`N > 0`, `0 ≤ cases ≤ N`). It is an integrity/corruption check, **not** a
MAC. Governance (cohort freeze, `min_contributors`, `allowed_runs_per_project: 1`)
is enforced by the platform, not this bundle; the single-run cap is a differencing
*mitigation*, not a cryptographic defense.

## Exactness envelope

BFV is exact in `Z_t`. The sufficient statistics are at most `2N` (dosage ≤ 2,
phenotype ≤ 1), so with `t = 1032193` the result is **bit-exact for N up to
≈ 500,000** (`2N < t`). Beyond that a coordinate could wrap mod `t`; a larger
cohort needs a larger plaintext modulus (a different, re-signed bundle). Within the
envelope the encrypted result is bit-identical to the cleartext statistic
(verified at 128/192/256-bit security in `tests/test_local_loop.py`).

## Determinism

BFV addition is deterministic, so the same ordered set of input ciphertexts always
yields the same result bytes (encryption is randomized; the *compute* is not).
Re-running the aggregation on the same inputs reproduces a bit-identical result
digest.
