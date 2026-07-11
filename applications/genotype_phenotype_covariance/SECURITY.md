# Security notes — `genotype_phenotype_covariance`

Scoped to this bundle. The platform-wide threat model lives in
`docs/manifesto.md`, `docs/requirements.md`, and `docs/simulation_mode.md` §5.
Kerckhoffs applied to a product: **no guarantee rests on the secrecy — or the
honesty — of the server.** Don't trust, verify.

## Trust classes (what may cross the wire)

| class | example artifact | may leave the owner's machine? |
|-------|------------------|-------------------------------|
| RAW | `raw.json` (genotype + phenotype) | **no** |
| ENCODED | `encoded.json` (`g`, broadcast `y`) | **no** |
| PRIVATE | `secret_context.tenseal` (secret key), `plain.json` | **no, ever** |
| ENCRYPTED | `cipher.bin` (packed `(g,y)` pair), `result.bin` | yes |
| PUBLIC | `public_context.tenseal` (relin keys, **no secret key**) | yes |

Only ENCRYPTED and PUBLIC are ever uploaded. `00_keygen.py` writes the secret key
to `secret_context.tenseal`, used **only** by `40_decrypt.py` on the researcher's
machine. There is no `/api/v1` endpoint that accepts a secret key.

## Server holds no secret key — and it computes an encrypted PRODUCT

`30_compute_encrypted.py` — the only server-side stage, a kit shim that runs
`server.py`'s `compute` — loads the **public** context (which carries
**relinearization keys but no secret key**) plus the
paired genotype/phenotype ciphertexts, and homomorphically forms
`Σ_i enc(g_i)·enc(y_i)` and `Σ_i enc(y_i)²` (depth-1 ciphertext × ciphertext,
relinearized) alongside the additive `Σ enc(g_i)` and `Σ enc(y_i)`. It defensively
refuses a context that carries a secret key (`context.is_private()` → error). The
relin keys let the server *multiply and relinearize* ciphertexts; they do **not**
let it decrypt. The server therefore never sees a single plaintext genotype or
phenotype — it operates on ciphertext and returns ciphertext. Decryption happens
only where the secret key lives: locally.

**No Galois keys.** The phenotype is broadcast across all slots at encode time, so
every product is element-wise and no cross-slot rotation is ever performed. The
public context ships **no** rotation (Galois) keys — the server cannot permute
slots even if it wanted to.

## The append-1 sentinel is NOT a MAC

Every contribution appends a trailing `1` to both the genotype and phenotype
vectors, so all four decrypted moments' last slot recovers the exact contributor
count N (`sum_g`/`sum_y`: `Σ1=N`; `sum_gy`/`sum_y2`: `Σ 1·1 = N`), and `50_decode.py`
**cross-checks that all four sentinels agree** — a stronger corruption check than
the single-sentinel additive flagship. Dropping one upload yields N−1 (test:
`test_sentinel_tracks_dropped_upload`). It catches **mechanical corruption /
miscounting / a dropped contribution** — it gives **no** guarantee that
contributions are distinct, genuine, or non-Sybil. Call it what it is: an integrity
check, not authenticity.

## Pairing integrity

A contributor's genotype and phenotype are **co-packed into ONE ciphertext blob at
encrypt time** — a `BMCT1` container holding that owner's `(cipher_g, cipher_y)`
pair (`20_encrypt.py`), which `30_compute_encrypted.py` unpacks back to the pair
before the fold. Pairing is therefore enforced *structurally*, not by input
ordering: because there is exactly one blob per contributor, the hosted worker's
`Stager` (which digest-sorts every staged ciphertext,
`worker/lib/blind_worker/stager.rb`) can only permute whole contributors, never
separate a `(g, y)` pair. The moment folds are order-independent across
contributors, so any staged order yields the identical result (pinned by
`test_result_is_order_independent_under_digest_sort`).

This closes a real bug in the earlier "two separate ciphertexts, interleaved
`(g_0, y_0, g_1, y_1, …)`" design: the Stager's digest-sort reordered those
independent `g`/`y` blobs into an arbitrary permutation, so the server paired
genotype-with-genotype and phenotype-with-phenotype by digest parity — and the
append-1 sentinel did **not** catch it (every blob carries a trailing `1`, so all
four moments still reconciled to N on corrupt output). Co-packing removes the whole
failure mode.

The only residual mis-pairing is a **dishonest owner** who packs `g_a` with `y_b`
in their *own* blob — the pre-existing honest-encoding assumption. As with all
inputs, correctness of the *released statistic* assumes contributors encode
honestly against the published definition; the platform's cohort-freeze + min-N +
run-cap governance bounds *differencing*, not per-contributor honesty.

## What FHE here does and does not hide

- **Hides:** individual genotype vectors AND phenotype values from the server
  (both inputs are ciphertext; the product is derived under encryption).
- **Does not hide:** the released aggregate moments/covariance themselves, and
  metadata (researcher identity, participant count/timing, ciphertext sizes,
  protocol choice, the phenotype coding scheme — which is public).
- **Differencing (K vs K+1):** the *statistic* leaks an individual if you can
  compute `A_{K+1} − A_K`. `aggregate_only` + `min_contributors ≥ 30` +
  `allowed_runs_per_project: 1` (cohort freeze + min-N + run cap) **mitigate**
  this; they are not a complete defense. With a covariance run an attacker who can
  difference two cohorts recovers `g_target · y_target` per variant AND
  `y_target` (from `sum_y`), so the min-N floor is raised to 30 for this protocol.
  Overlapping/Sybil differencing across separately frozen cohorts needs DP +
  cross-job query budgets (v2). Documented, not hand-waved — see
  `docs/simulation_mode.md` §5.
- **Verify-by-re-execution is determinism, not zero-knowledge.** Re-running
  `30_compute_encrypted.py` on the same ciphertexts reproduces a bit-identical
  result digest (BFV add and relinearized multiply are deterministic; the container
  order is fixed); it proves the computation, it is not a ZK proof.

## Exactness / parameter safety

BFV is exact in `Z_t`. The plaintext modulus must exceed the largest moment value.
For a **binary** (case/control) phenotype the max is `sum_gy ≤ 2·N` (`g≤2`, `y≤1`),
so the default `t = 786433` (a 20-bit batching prime, valid at `poly=16384` because
`786433 = 24·32768 + 1 ≡ 1 (mod 2·16384)`) stays exact for N up to ~196k; the four
sentinels are all N, always ≪ t. A **quantized trait** `y ∈ {0..Q}` raises the
envelope to `sum_y2 ≤ N·Q²` and `sum_gy ≤ 2·N·Q`, which can cross `t` quickly (e.g.
Q=100 overflows at N≈78) — such a deployment must pick a larger ~30-bit batching
prime `≡ 1 (mod 32768)` sized to the `(N, Q)` envelope, or the simulation
feasibility sweep will report `infeasible-at-these-params` on overflow. The
multiplicative depth is fixed at 1 (one ct×ct level), well within the
`coeff_mod_bit_sizes = [60,40,40,60]` chain's two-level budget, so noise-budget
exhaustion is not a concern at these params.
