# Benchmark note — the additive client-precompute variant

> `allele_frequency_with_variance` is the paper's **money-comparison row**
> (`docs/protocol_catalog.md` §5, `docs/spec.md` line 45–47). It ships one way of
> computing `sum_g2` — the server squares under encryption — and is measured
> beside a second way that computes the **same** `sum_g2` without a multiplicative
> level. This note defines that second way. It is a **benchmark arm, not a
> separate registry protocol**: there is no second manifest, no second bundle
> identity. Only the multiplicative version is a registered protocol.

## The two arms

Both arms release the identical aggregate `sum_g2[j] = Σ_i g_ij²`. They differ
only in **who squares** and therefore in **which crypto tier** is needed.

| | **Multiplicative arm** (this registered protocol) | **Additive client-precompute arm** (benchmark only) |
|---|---|---|
| who squares | the **server**, under encryption (`Σ_i enc(g_ij)²`) | the **client**, locally in cleartext (`g² = g·g`) before encrypting |
| server op | ct + ct **and** ct × ct (square) | ct + ct **only** |
| relin keys | **required** (public context carries them) | **not needed** |
| Galois keys | none | none |
| `poly_modulus_degree` | **16384** (multiplication-supporting) | **8192** (minimal, additive — same as the flagship) |
| `coeff_mod_bit_sizes` | `[60, 40, 40, 60]` (2 levels) | default (additive regime) |
| `plain_modulus` | `786433` (`≡ 1 mod 32768`, required at n=16384) | `1032193` (the flagship's 20-bit prime; exact for `max sum_g2 = 4N`) |
| contributor payload | **1 ciphertext** (`enc(g)`); server derives the square | **2 ciphertexts** (`enc(g)` for `sum_g` **and** `enc(g²)` for `sum_g2`) |
| integrity of `sum_g2` | server-derived from `g` — cannot be a client value inconsistent with `g` | client-asserted — a dishonest client could send `g²` inconsistent with its `g` |

## What the comparison isolates

Because the two arms share the **same inputs, same coordinate definition, and
same released statistic**, the benchmark matrix (`blind bench`) isolates a single
variable: **the price of one BFV multiplicative level.**

- **Cost of the multiplicative arm:** the larger ring (16384 vs 8192), the
  explicit 2-prime coeff-modulus chain, relin-key storage in the public context,
  and the per-contributor ct × ct square. Concretely, on this machine the depth-1
  square runs at `poly_modulus_degree=16384` with ~640 KB ciphertexts (see the
  end-to-end run in `README.md`); the additive arm at 8192 produces ~2–4× smaller
  ciphertexts and does no multiply.
- **What the multiplicative arm buys:** (1) **server-derived-quantity
  integrity** — `sum_g2` is provably a function of the encrypted `g`, not a
  client-supplied number; (2) a **smaller contributor payload** — one ciphertext,
  not two; and (3) an explicit **encrypted-computation** path that generalizes to
  circuits the client cannot precompute (the covariance protocol's genuine
  encrypted × encrypted product, protocol 6).
- **The "additive-suffices" caveat:** for a single contributor who holds `g`,
  `g²` is trivially client-computable, so the additive arm is *feasible*. The
  paper states this honestly: v1 ships the multiplicative version for integrity,
  payload, and as the bridge to cross-party products — not because the additive
  arm is impossible. This is the same honesty the catalog applies to protocol 6.

## Where the arms are exercised

- **Correctness (this bundle):**
  `tests/test_local_loop.py::test_additive_client_precompute_variant_matches_multiplicative`
  runs the additive arm on the minimal 8192 additive context (client pre-squares,
  server only sums) and asserts its `sum_g2` is **bit-identical** to the
  multiplicative arm's server-squared `sum_g2`, and to the cleartext oracle. The
  comparison only means something because the two paths agree exactly.
- **Cost (platform):** `blind bench` and `blind simulate`
  (`docs/simulation_mode.md`) run both arms across `N × L × security level` on
  synthetic cohorts and record runtime, ciphertext size, peak memory, CPU-seconds,
  and cloud cost. Those feasibility numbers — not this bundle's tests — are what
  populate the paper's cost-of-multiplicative-depth table. The bundle's job is to
  prove the two arms compute the same thing; the platform's job is to price them.

## Reproducing the additive arm by hand

The additive arm needs no new stage files — it reuses this bundle's `10_encode`,
`20_encrypt` (on a locally squared vector), and the additive `.add` fold inside
`30_compute_encrypted.BFVEvaluator`, against a minimal 8192 context from
`00_keygen.keygen(poly_modulus_degree=8192, plain_modulus=1032193,
coeff_mod_bit_sizes=None)`. See the `_additive_precompute_sum_g2` helper in
`tests/test_local_loop.py` for the exact ~15-line recipe.
