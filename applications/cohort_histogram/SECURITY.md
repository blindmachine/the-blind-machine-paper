# Security notes — `cohort_histogram`

Scoped to this bundle. The platform-wide threat model lives in
`docs/manifesto.md`, `docs/requirements.md`, and `docs/simulation_mode.md` §5.
Kerckhoffs applied to a product: **no guarantee rests on the secrecy — or the
honesty — of the server.** Don't trust, verify.

## Trust classes (what may cross the wire)

| class | example artifact | may leave the owner's machine? |
|-------|------------------|-------------------------------|
| RAW | `raw.json` bucket index | **no** |
| ENCODED | `encoded.json` one-hot vector | **no** |
| PRIVATE | `secret_context.tenseal` (secret key), `plain.json` | **no, ever** |
| ENCRYPTED | `cipher.bin`, `result.bin` | yes |
| PUBLIC | `public_context.tenseal` | yes |

Only ENCRYPTED and PUBLIC are ever uploaded. `00_keygen.py` writes the secret key
to `secret_context.tenseal`, which is used **only** by `40_decrypt.py` on the
researcher's machine. There is no `/api/v1` endpoint that accepts a secret key.

## Server holds no secret key

`30_compute_encrypted.py` — the only server-side stage, a kit shim that runs
`server.py`'s `compute` — loads the **public**
context plus ciphertexts and homomorphically adds. It defensively refuses a
context that carries a secret key (`context.is_private()` → error). The server
therefore never sees a single plaintext bucket membership; it operates on
ciphertext and returns ciphertext. Decryption happens only where the secret key
lives: locally.

## The append-1 sentinel is NOT a MAC

The trailing sentinel slot decrypts to the exact contributor count N, and
dropping one upload yields N−1 (test: `test_sentinel_tracks_dropped_upload`).
Because contributions are one-hot, the per-bucket counts must **also** total N,
so `50_decode.py` asserts `sum(counts) == N` and rejects any aggregate that
fails it (test: `test_decode_rejects_non_one_hot_aggregate`). Both checks catch
**mechanical corruption / miscounting** — they give **no** guarantee that
contributions are distinct, genuine, or non-Sybil. Call them what they are:
integrity checks, not authenticity. A malicious client could still submit a valid
one-hot vote for the wrong bucket; nothing here proves a contributor's raw value
was truthfully bucketed.

## What FHE here does and does not hide

- **Hides:** each contributor's individual bucket membership from the server
  (inputs are ciphertext).
- **Does not hide:** the released histogram itself, and metadata (researcher
  identity, participant count/timing, ciphertext sizes, protocol choice, the
  published bucket definition).
- **Small-bucket / rare-category leakage:** a bucket whose count is 1 pinpoints
  that a single contributor is in that category. The released statistic is the
  histogram, so a rare bucket is inherently identifying — a stronger version of
  the flagship's differencing concern. `aggregate_only` + `min_contributors ≥ 25`
  (higher than the flagship) + `allowed_runs_per_project: 1` **mitigate** this;
  they are not a complete defense. Per-bucket suppression / k-anonymity thresholds
  and DP noise on the counts are the v2 answer (documented, not hand-waved).
- **Differencing (K vs K+1):** the histogram leaks an individual if you can
  compute `H_{K+1} − H_K` (the differenced vector is that contributor's one-hot).
  Same cohort-freeze + min-N + run-cap mitigation as the flagship; overlapping /
  Sybil differencing across separately frozen cohorts needs DP + cross-job query
  budgets (v2). See `docs/simulation_mode.md` §5.
- **Verify-by-re-execution is determinism, not zero-knowledge.** Re-running
  `30_compute_encrypted.py` on the same ciphertexts reproduces a bit-identical
  result digest; it proves the computation, it is not a ZK proof.

## Exactness / parameter safety

BFV is exact in `Z_t`. The plaintext modulus must satisfy `t > max bucket count`.
Because every contribution is one-hot, a single bucket holds at most N, so the
largest coordinate value is N — a *wider* margin than the flagship's `2·N`
envelope. The default `t = 1032193` (a 20-bit batching prime) stays exact for N
up to ~1M; a real run at larger N must raise `t` (or the simulation feasibility
sweep will report `infeasible-at-these-params` on overflow). The sentinel sum is
N, always ≪ t, and equals `sum(counts)` by construction.
