# Benchmark — `polygenic_score_inference` vs HEPRS

Head-to-head reproduction of **HEPRS** (Knight et al., *Homomorphic encryption
enables privacy preserving polygenic risk scores*, Cell Reports Methods 2026;
`github.com/gersteinlab/HEPRS`) on The Blind Machine's `polygenic_score_inference`
application. Both compute per-individual `PRS_i = Σ_j w_j·g_ij` over encrypted
genotypes; HEPRS encrypts the model too (CKKS, `ct×ct` + relin), while we take the
common case of a **public** model (BFV, `ct×plaintext` + one rotate-sum).

## Method

- **Our numbers:** measured on this repo's `signed/` bundle at 128-bit security,
  **single-threaded**, contributors **streamed one at a time** (constant memory).
  Machine: Apple-silicon, 12 cores, 34 GB RAM. keygen (amortized once) 0.43 s;
  public context (with Galois keys) 20.1 MB. Wall = encrypt + server-compute +
  decrypt across the whole cohort; "server" is the evaluator's cost alone.
- **HEPRS numbers:** as reported in their paper (single CPU, Intel Xeon 6234,
  CKKS ring 2¹³). CPUs differ, so **time** is indicative, not a controlled
  comparison; **memory** and **exactness** are architectural, not hardware.
- Reproduction data: HEPRS's own public example + synthetic HAPGEN2-style dosage
  matrices at matched sizes. The real 110k-SNP schizophrenia cohort is
  controlled-access — we run the **synthetic** 110,258 × 1,146 point at that scale
  and cite HEPRS's real-data accuracy.

## Head-to-head

| Configuration | HEPRS (reported) | The Blind Machine (measured) | Memory ratio |
|---|---|---|---|
| 1 individual × 110k SNP | 4.9 s, 3.3 GB | **0.13 s** (95 ms enc + 38 ms srv), exact | — |
| 10,000 SNP × 50 | 5 s, 0.8 GB | 2.2 s wall (srv 0.73 s), **427 MB**, exact | 1.9× |
| 130,000 SNP × 50 | 36 s, 9 GB | 8.0 s wall (srv 2.3 s), **427 MB**, exact | 21× |
| 130,000 SNP × 200 | 1.5 min, 17 GB | 35 s wall (srv 9.6 s), **427 MB**, exact | 40× |
| 130,000 SNP × 2,000 | 12.5 min, 125 GB | **5.7 min** wall (srv 95 s), **427 MB**, exact | **293×** |
| **110,258 SNP × 1,146** (schizophrenia scale) | **6 min, 65 GB** | **2.5 min** wall (srv **43 s**), **436 MB**, exact | **≈150×** |

Per-contributor upload (ciphertext): 0.79 MB @ 10k SNP → 7.1 MB @ 110k → 8.4 MB @
130k. All points **bit-exact** (`tolerance 0`) — the decrypted score equals the
plaintext oracle exactly, where HEPRS's CKKS carries a small MSE (~1e-8; ~2e-6 on
the real model).

## What the numbers say

- **Memory is flat, not linear.** Peak RSS stays ~**427 MB regardless of cohort
  size** (contributors are scored and freed one at a time), where HEPRS grows to
  65–125 GB because it holds the whole encrypted cohort *and* model in RAM. At the
  110k × 1,146 schizophrenia scale that is **65 GB → 436 MB (~150×)**; at 130k ×
  2,000 it is **125 GB → 427 MB (~293×)**. The result: a job that needs a
  large-memory server for HEPRS runs on a laptop here. (Holding all 1,146 blobs at
  once — the non-streaming mode — would still be only ~8 GB, already ~8× under
  HEPRS.)
- **Faster end-to-end and much less server work.** End-to-end (encrypt + compute +
  decrypt, single core) is ~2.4× faster at the schizophrenia scale (**2.5 vs 6
  min**); the *server's* homomorphic compute alone is **43 s** for 1,146 × 110k.
  The computation is embarrassingly parallel (each contributor independent), so
  across the 12 cores it drops to well under a minute — the reported numbers are
  the conservative single-core figures.
- **Exact, not approximate.** Every score is bit-exact in BFV; HEPRS's CKKS is
  approximate.
- **The win is the public model.** Making the model public turns the per-SNP
  `ct×ct` (relin, model ciphertext, the multiplicative tier) into a `ct×plaintext`
  multiply plus one rotate-sum — no relin keys, no model ciphertext, streamable.
  This is "push work local, use the least-powerful HE that does the job."

## Accuracy vs HEPRS's published predictions

On HEPRS's public 10k × 50 example, our per-individual scores reproduce their
plaintext predictions (`phenotype0_pred`) with **Pearson r = 0.99999999** and an
affine **slope of exactly 1.000000** — our encrypted score *is* HEPRS's
SNP-weighted sum. The only offset is the model's constant Ridge intercept (+0.262,
a public post-decrypt add); after accounting for it the residual is **3.6e-5**,
i.e. HEPRS's own float32 reference precision. And our encrypted result equals our
plaintext oracle **exactly**.

Regenerate: `docs/paper/experiments/e9_heprs_prs_reproduction.sh` (asserts
exactness + reproduction); the full sweep harness is
`docs/paper/experiments/heprs_prs_reproduction_2026_07_17/`.
