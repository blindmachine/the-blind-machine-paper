# Security notes — `polygenic_score_aggregate`

Scoped to this bundle. The platform-wide threat model lives in
`docs/manifesto.md`, `docs/requirements.md`, and `docs/simulation_mode.md` §5.
Kerckhoffs applied to a product: **no guarantee rests on the secrecy — or the
honesty — of the server.** Don't trust, verify.

## Trust classes (what may cross the wire)

| class | example artifact | may leave the owner's machine? |
|-------|------------------|-------------------------------|
| RAW | `raw.json` genotypes | **no** |
| ENCODED | `encoded.json` dosage vector | **no** |
| PRIVATE | `secret_context.tenseal` (secret key), `plain.json` | **no, ever** |
| ENCRYPTED | `cipher.bin`, `result.bin` | yes |
| PUBLIC | `public_context.tenseal`, the effect weights (`manifest.yml`) | yes |

Only ENCRYPTED and PUBLIC are ever uploaded. `00_keygen.py` writes the secret key
to `secret_context.tenseal`, which is used **only** by `40_decrypt.py` on the
researcher's machine. There is no `/api/v1` endpoint that accepts a secret key.
The effect weights are **already public** (published in the manifest, folded into
the digest) — they are not a secret and are applied in the clear.

## Server holds no secret key

`30_compute_encrypted.py` — the only server-side stage, a kit shim that runs
`server.py`'s `compute` — loads the **public** context plus ciphertexts,
homomorphically adds them, and applies the public
effect weights as a **plaintext-scalar multiply**. It defensively refuses a
context that carries a secret key (`context.is_private()` → error). The server
therefore never sees a single plaintext genotype; it operates on ciphertext (and
public plaintext weights) and returns ciphertext. Decryption happens only where
the secret key lives: locally.

## Public weights → additive tier, no ciphertext × ciphertext

The statistic is a weighted sum `Σ_j w_j·g_j`, but the weights are **public**, so
the multiply is **ciphertext × plaintext**, not ciphertext × ciphertext. That
distinction is load-bearing:

- A plaintext multiply does not raise ciphertext degree, so **no relinearization
  keys** are generated or shipped in the public context.
- Every op is element-wise; there is no cross-slot rotation, so **no Galois
  keys**. The cohort reduction `Σ_j` is computed **post-decrypt in the CLI**,
  never under encryption.

If the weights were themselves private (a different, out-of-scope protocol), the
multiply would be ciphertext × ciphertext, would need relin keys, and would move
to the multiplication-supporting tier (protocols 5–6). They are not.

## The append-1 sentinel is NOT a MAC

The trailing sentinel slot decrypts to the exact contributor count N, and
dropping one upload yields N−1 (test: `test_sentinel_tracks_dropped_upload`). The
one subtlety this protocol adds: the server weights that slot by **1** (unscaled),
so it survives the plaintext-weight multiply intact and still reads N. It catches
**mechanical corruption / miscounting** — it gives **no** guarantee that
contributions are distinct, genuine, or non-Sybil. Call it what it is: an
integrity check, not authenticity.

## What FHE here does and does not hide

- **Hides:** individual genotype vectors from the server (inputs are ciphertext).
- **Does not hide:** the released public-weighted aggregate itself, the **effect
  weights** (public by construction), and metadata (researcher identity,
  participant count/timing, ciphertext sizes, protocol choice).
- **Differencing (K vs K+1):** the released *statistic* leaks an individual if you
  can compute `A_{K+1} − A_K` — and because the weights are public and invertible
  (each `w_scaled[j] ≥ 1`), the per-coordinate weighted difference divides back to
  the target's exact dosage. `aggregate_only` + `min_contributors ≥ 20` +
  `allowed_runs_per_project: 1` (cohort freeze + min-N + run cap) **mitigate**
  this; they are not a complete defense. Overlapping/Sybil differencing across
  separately frozen cohorts needs DP + cross-job query budgets (v2). Documented,
  not hand-waved — see `docs/simulation_mode.md` §5.
- **Verify-by-re-execution is determinism, not zero-knowledge.** Re-running
  `30_compute_encrypted.py` on the same ciphertexts reproduces a bit-identical
  result digest; it proves the computation, it is not a ZK proof.

## Exactness / parameter safety

BFV is exact in `Z_t`. The plaintext modulus must satisfy `t > max slot value`,
which **after the public-weight multiply** is `max_j(w_scaled[j]) · 2·N` (dosage
≤ 2). The flagship's 20-bit `t = 1032193` is **under-sized** for weighted sums;
this bundle uses the 30-bit batching prime `t = 1073692673` (≡ 1 mod 16384),
exact for the published envelope `S = 1000`, `w_scaled ≤ 2000`, N up to ~250k. A
run outside that `(S, weight range, N)` envelope must raise `t` (or the
simulation feasibility sweep reports `infeasible-at-these-params` on overflow).
The sentinel sum is N, always ≪ t. The released real values are exact to the
fixed-point resolution `1/S` of the published scale.
