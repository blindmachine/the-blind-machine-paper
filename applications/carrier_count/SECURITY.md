# Security notes — `carrier_count`

Scoped to this bundle. The platform-wide threat model lives in
`docs/manifesto.md`, `docs/requirements.md`, and `docs/simulation_mode.md` §5.
Kerckhoffs applied to a product: **no guarantee rests on the secrecy — or the
honesty — of the server.** Don't trust, verify.

`carrier_count` reuses the flagship's coordinate definition and additive circuit
verbatim; only the client-side encoding differs (dosage thresholded to a carrier
indicator *before* encryption). The leakage boundary is therefore the flagship's,
with one narrowing: the server — and the released aggregate — see only carrier
*indicators*, never the underlying dosage. Thresholding `2 -> 1` and `1 -> 1`
happens locally, so whether a carrier is heterozygous or homozygous never leaves
the owner's machine in any form.

## Trust classes (what may cross the wire)

| class | example artifact | may leave the owner's machine? |
|-------|------------------|-------------------------------|
| RAW | `raw.json` dosage genotypes | **no** |
| ENCODED | `encoded.json` carrier-indicator vector | **no** |
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
therefore never sees a single plaintext carrier indicator; it operates on
ciphertext and returns ciphertext. Decryption happens only where the secret key
lives: locally.

## The append-1 sentinel is NOT a MAC

The trailing sentinel slot decrypts to the exact contributor count N, and
dropping one upload yields N−1 (test: `test_sentinel_tracks_dropped_upload`). It
catches **mechanical corruption / miscounting** — it gives **no** guarantee that
contributions are distinct, genuine, or non-Sybil. Call it what it is: an
integrity check, not authenticity.

`carrier_count` admits one extra, free integrity check the flagship does not: a
carrier count is a headcount, so every released `carrier_count[j]` must lie in
`[0, N]`. `50_decode.py` asserts this; a value outside the range means corruption
or an out-of-domain contribution slipped past encoding. (It is not a stronger
constraint than the sentinel — a malicious over-1 contribution could still fall
inside `[0, N]` — but it catches the common corruption mode for free.)

## What FHE here does and does not hide

- **Hides:** individual carrier vectors from the server (inputs are ciphertext),
  and — because thresholding is local — the underlying dosage entirely (hom vs
  het is never encoded or transmitted).
- **Does not hide:** the released aggregate itself, and metadata (researcher
  identity, participant count/timing, ciphertext sizes, protocol choice).
- **Differencing (K vs K+1):** the *statistic* leaks an individual if you can
  compute `A_{K+1} − A_K`. `aggregate_only` + `min_contributors ≥ 20` +
  `allowed_runs_per_project: 1` (cohort freeze + min-N + run cap) **mitigate**
  this; they are not a complete defense. Overlapping/Sybil differencing across
  separately frozen cohorts needs DP + cross-job query budgets (v2). Documented,
  not hand-waved — see `docs/simulation_mode.md` §5.
- **Verify-by-re-execution is determinism, not zero-knowledge.** Re-running
  `30_compute_encrypted.py` on the same ciphertexts reproduces a bit-identical
  result digest; it proves the computation, it is not a ZK proof.

## Exactness / parameter safety

BFV is exact in `Z_t`. The plaintext modulus must satisfy `t > max coordinate
sum = N` (each contributor adds a 0/1 indicator per coordinate). The default
`t = 1032193` (a 20-bit batching prime) stays exact for N up to ~1M — an even
wider margin than the flagship's `2N` ceiling, since carriers cap at 1 per
coordinate. A real run at implausibly large N must raise `t` (or the simulation
feasibility sweep will report `infeasible-at-these-params` on overflow). The
sentinel sum is N, always ≪ t.
