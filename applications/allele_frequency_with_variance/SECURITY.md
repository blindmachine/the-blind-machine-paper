# Security notes — `allele_frequency_with_variance`

Scoped to this bundle. The platform-wide threat model lives in
`docs/manifesto.md`, `docs/requirements.md`, and `docs/simulation_mode.md` §5.
Kerckhoffs applied to a product: **no guarantee rests on the secrecy — or the
honesty — of the server.** Don't trust, verify.

This is the multiplication-supporting sibling of the flagship: same inputs, but
the server SQUARES an encrypted value. The trust boundary is unchanged — the
server still holds no secret key and still returns only ciphertext.

## Trust classes (what may cross the wire)

| class | example artifact | may leave the owner's machine? |
|-------|------------------|-------------------------------|
| RAW | `raw.json` genotypes | **no** |
| ENCODED | `encoded.json` dosage vector | **no** |
| PRIVATE | `secret_context.tenseal` (secret key), `plain.json` | **no, ever** |
| ENCRYPTED | `cipher.bin`, `result.bin` (one BMCT1 container packing sum_g + sum_g2) | yes |
| PUBLIC | `public_context.tenseal` (secret key stripped; relin keys retained) | yes |

Only ENCRYPTED and PUBLIC are ever uploaded. `00_keygen.py` writes the secret key
to `secret_context.tenseal`, which is used **only** by `40_decrypt.py` on the
researcher's machine. There is no `/api/v1` endpoint that accepts a secret key.

## The public context carries relin keys — and that is safe

Unlike the additive flagship, the published public context includes
**relinearization keys**. Relin keys are a public evaluation key: they let the
server relinearize a degree-3 product ciphertext (the result of ct × ct) back to
degree 2. They reveal **nothing** about any plaintext and cannot decrypt — only
the secret key can. The server needs them purely to perform the square. **No
Galois (rotation) keys are generated**: the square is element-wise per slot, so
there is never a cross-slot rotation. Withholding Galois keys keeps the server's
capability minimal — it can add and element-wise square, nothing else.

## Server holds no secret key

`30_compute_encrypted.py` — the only server-side stage, a kit shim that runs
`server.py`'s `compute` — loads the **public**
context plus ciphertexts, homomorphically adds, and homomorphically squares
(relin). It defensively refuses a context that carries a secret key
(`context.is_private()` → error). The server therefore never sees a single
plaintext genotype; it operates on ciphertext and returns ciphertext (two blobs:
`sum_g` and the server-derived `sum_g2`). Decryption happens only where the
secret key lives: locally.

## Server-derived second moment — integrity, not blind trust

`sum_g2` is computed **by the server, under encryption**, from the same `g`
ciphertexts. The researcher never has to trust the server got the square right:
the released `sum_g2` is bit-exact-verifiable against the cleartext oracle in
simulation (`docs/simulation_mode.md`), and the compute is deterministic, so
re-execution reproduces a bit-identical result digest. Squaring server-side (vs
the client sending `g²`) means the contributor payload stays minimal and the
second moment can never be a client-fabricated value inconsistent with `g`.

## The append-1 sentinel is NOT a MAC

Both result vectors' trailing sentinel slot decrypts to the exact contributor
count N (sum path `Σ 1 = N`; square path `Σ 1² = N`), and `50_decode.py`
cross-checks that the two agree. Dropping one upload yields N−1 in both (test:
`test_sentinel_tracks_dropped_upload`). It catches **mechanical corruption /
miscounting** — it gives **no** guarantee that contributions are distinct,
genuine, or non-Sybil. Call it what it is: an integrity check, not authenticity.

## What FHE here does and does not hide

- **Hides:** individual genotype vectors from the server (inputs are ciphertext),
  and the individual second moments (the server never decrypts `g²` per person).
- **Does not hide:** the released aggregates themselves (`sum_g`, `sum_g2`, and
  the derived mean/variance), and metadata (researcher identity, participant
  count/timing, ciphertext sizes, protocol choice).
- **Differencing (K vs K+1):** the *statistics* leak an individual if you can
  compute `A_{K+1} − A_K` — and because BOTH moments are released, an attacker who
  can difference recovers both `g` and `g²` for the marginal contributor.
  `aggregate_only` + `min_contributors ≥ 30` (higher than the flagship's 20) +
  `allowed_runs_per_project: 1` (cohort freeze + min-N + run cap) **mitigate**
  this; they are not a complete defense. Overlapping/Sybil differencing across
  separately frozen cohorts needs DP + cross-job query budgets (v2). Documented,
  not hand-waved — see `docs/simulation_mode.md` §5.
- **Verify-by-re-execution is determinism, not zero-knowledge.** Re-running
  `30_compute_encrypted.py` on the same ciphertexts reproduces bit-identical
  result digests; it proves the computation, it is not a ZK proof.

## Exactness / parameter safety

BFV is exact in `Z_t`. The plaintext modulus must satisfy `t > max coordinate
value`. Here the second moment dominates: `max sum_g2 = 4·N` (each `g² ≤ 4`). The
default `t = 786433` (a 20-bit batching prime, `≡ 1 (mod 32768)` as required at
n=16384) stays exact for N up to ~196k; a real run at larger N must raise `t` (or
the simulation feasibility sweep will report `infeasible-at-these-params` on
overflow). Per-contributor `g² ≤ 4` and the sentinel sum N are both `≪ t`.

**Noise budget:** the coeff-modulus chain `[60, 40, 40, 60]` gives two
multiplicative levels; the single depth-1 square consumes one, leaving headroom.
A depth-2 circuit would need a longer chain (and a larger ring for the same
security), which is precisely the cost the benchmark matrix quantifies.
