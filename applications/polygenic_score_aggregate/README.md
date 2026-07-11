# `polygenic_score_aggregate` — Blind Machine curated protocol

> tenseal-BFV, **minimal (additive-tier) params**. The clearest "looks
> multiplicative, remains additive" example: a public-weighted polygenic score
> `Σ_j w_j·g_j` computed as an additive homomorphic fold **plus one
> plaintext-scalar multiply** by the PUBLIC effect-weight vector — never a
> ciphertext × ciphertext multiply. See `docs/protocol_catalog.md` §4.

## What it computes

Each contributor holds an alt-allele **dosage vector** `g ∈ {0,1,2}^L` over the
same fixed, published coordinate definition as the flagship (ordered variants
`(chrom,pos,ref,alt)`), missing calls encoded as 0. The protocol also fixes a
**public effect-weight vector** `w ∈ ℝ^L`, integer-scaled by a published
fixed-point factor `S` (`w_scaled[j] = round(w_j·S)`) and folded into the bundle
digest. The cohort aggregate released is the per-coordinate **public-weighted**
sum:

```
weighted_counts[j] = w_scaled[j] · Σ_i g_i[j]        (integer, exact in Z_t)
cohort_pgs_scaled  = Σ_j weighted_counts[j]          (integer)
mean_PGS           = cohort_pgs_scaled / (S·N)       (real, post-decrypt)
```

where each contributor's polygenic score is `PGS_i = Σ_j (w_scaled[j]/S)·g_ij`.

**Why it stays additive.** Every weight is **public**, so the server applies them
as a **ciphertext × plaintext** multiply, which does not raise ciphertext degree
(no relinearization) and involves no rotation (no Galois keys). The
cross-coordinate reduction `Σ_j` is done **post-decrypt in the CLI**, never under
encryption — that is what keeps the protocol on the same minimal BFV params as
the flagship. This is the catalog's canonical demonstration that a statistic can
*look* multiplicative and still be served by additive-tier BFV.

**Exactness:** BFV is exact in `Z_t`; the integer-scaled aggregate equals the
cleartext sum **bit-for-bit** (`tolerance: 0`). The released real values carry
the fixed-point resolution of `S` (per-weight rounding error `≤ 1/S`).

**Append-1 sentinel (one subtlety this protocol adds):** encryption appends a
trailing `1` slot to every contribution, so the homomorphic sum's last slot is
`N`. The server's plaintext-weight multiply uses **weight `1` on that sentinel
slot**, so it is left unscaled and still decrypts to **exactly N**. It is an
integrity/corruption check, **not a MAC** (see `SECURITY.md`).

## BFV parameters

Params are unchanged from the flagship except the plaintext modulus (which must
grow to fit the weight-inflated value envelope) and the coeff-modulus chain
(selected by `--security`, below):

| param | value | why |
|-------|-------|-----|
| `poly_modulus_degree` | 8192 | 8192 slots ≫ L+1; FIXED across all security levels (batching prime valid only at N=8192, depth-0 needs no bump). |
| `plain_modulus` | 1073692673 | 30-bit batching prime (≡ 1 mod 16384). Max slot after the weight multiply is `max_j(w_scaled[j])·2N`; the flagship's 20-bit `t` is under-sized. Exact for `S=1000`, `w_scaled ≤ 2000`, N up to ~250k. FIXED — a function of the value envelope, not security. |
| `coeff_mod_bit_sizes` | see `--security` | selects the q-band that fixes the achieved HE security level. |
| relin / Galois keys | **none** | ciphertext × plaintext only; no rotation |

### `--security {128,192,256}` (default 128)

`--security` is the ONLY knob that varies with the requested HE security level;
it selects the `coeff_mod_bit_sizes` chain. At **fixed N=8192** the security
level is the q-band: **smaller Σbits ⇒ more secure**, so certifying a *higher*
level spends a *smaller* modulus. This is correct RLWE behaviour, not a bug — the
depth-0 noise floor for this payload sits in the 256 band, so 128/192 carry
surplus modulus (bigger/slower ciphertexts) than 256 (the "256 is cheaper than
128" inversion).

| `--security` | `coeff_mod_bit_sizes` | Σ bits | achieved |
|---|---|---|---|
| 128 (default) | `[60, 60, 60]` | 180 | 128 |
| 192 | `[50, 50, 50]` | 150 | 192 |
| 256 | `[45, 45, 28]` | 118 | 256 |

**Why 3-prime chains (not 2).** TenSEAL reserves the LAST coeff prime as a
key-switching *special* prime, so the effective ciphertext modulus = Σ(all but
last). This protocol's 30-bit `t` combined with the ciphertext × plaintext weight
multiply (scale up to ~2000) needs an **effective q ≳ 80 bits**, so a 2-prime
chain (e.g. `[60,60]`, effective 60) FAILS to decrypt; every level ships a
3-prime chain (effective 120 / 100 / 90). All four additive protocols standardize
on these same PGS-safe chains so the `SECURITY` table is byte-identical across
bundles. The `security` benchmark column is computed by the harness as the
strictest level whose HomomorphicEncryption.org cap the chain fits under —
**never** read back from SEAL (SEAL only validates at tc128). Every level
decrypts the public-weighted aggregate **bit-exact** (verified, TenSEAL 0.3.16).

Downstream stages `ts.context_from(...)` the serialized context, so the chain
flows through unchanged — they stay security-agnostic.

## Public weights (deterministic, content-addressed)

`manifest.yml` declares `weights: { scale: 1000, values: { kind:
synthetic_weights, seed: blind-v1-pgs-weights, range: [1, 2000] } }`.
`30_compute_encrypted.py`'s `scaled_weights(length)` regenerates the exact
integer weight vector from that seed (stable `random.Random(seed)`), so the
server and the cleartext oracle score every contributor against the identical
vector, and any change to the seed/scale/generator changes the protocol digest.
No separate weight file is shipped (per `docs/protocol_structure.md`: public
weights live in the manifest for synthetic v1 protocols).

## Stage lifecycle & I/O contract

The author's logic lives in three pure-function files, grouped by role: `server.py`
(`compute`, the only server-side function), `local_project_owner.py`
(`keygen`/`decrypt`/`decode`), and `local_data_owner.py` (`encode`/`encrypt`) —
these are what sibling `tests/` import. The six numbered files are materialized into `signed/` at run time and are
**kit-owned shims** (thin argparse wrappers; do not edit) that map each stage's CLI
(`python NN_*.py --help`) onto those functions, keeping the lifecycle visible
without opening a subdirectory.

| stage | runs | trust in → out | I/O |
|-------|------|----------------|-----|
| `00_keygen.py` | local (researcher) | — → PRIVATE + PUBLIC context | `--out-dir DIR [--security {128,192,256}]` → `secret_context.tenseal` (never upload), `public_context.tenseal` (uploadable) |
| `10_encode.py` | local (data owner) | RAW → ENCODED | `--raw raw.json --length L --out encoded.json` (validate {0,1,2}, null→0, pad to L — identical to flagship) |
| `20_encrypt.py` | local (data owner) | ENCODED → ENCRYPTED | `--context public_context.tenseal --encoded encoded.json --out cipher.bin` (appends sentinel, BFV-encrypts) |
| `30_compute_encrypted.py` | **SERVER** | ENCRYPTED → ENCRYPTED | `--context public_context.tenseal --inputs c0.bin c1.bin … --out result.bin` (homomorphic sum **then public plaintext-weight multiply**; **no secret key present**) |
| `40_decrypt.py` | local (researcher) | ENCRYPTED → PRIVATE | `--context secret_context.tenseal --result result.bin --out plain.json` (length L+1) |
| `50_decode.py` | local (researcher) | PRIVATE → RELEASED | `--plain plain.json --length L [--scale S] --out result.json` (splits sentinel→N, weighted counts, cohort/mean PGS) |

Inter-stage formats: contexts and ciphertexts are TenSEAL's raw serialized bytes
(binary); raw/encoded/plain are JSON int lists; the released result is JSON with
`n_contributors`, `weighted_counts`, `cohort_pgs_scaled`, `cohort_pgs_sum`,
`mean_pgs`.

`server.py`'s `compute` is written **once** against an abstract evaluator `E`
(`zero`/`add`/`scalar_mul`), so `docs/simulation_mode.md`'s cleartext correctness
oracle swaps a `PlaintextEvaluator` for the same `compute` and cannot drift from
this encrypted path. Determinism gives verify-by-re-execution: the same ordered
ciphertexts in → a bit-identical result digest out (compute is deterministic;
encryption is not).

## Run the full loop by hand

```bash
cd protocols/polygenic_score_aggregate
D=/tmp/pgs && mkdir -p "$D"
R() { (cd signed && uv --project env run python "$@"); }

R 00_keygen.py --out-dir "$D"
for i in 00 01 02 03; do
  R 10_encode.py  --raw ../tests/vectors/contributor_$i.json --length 16 --out "$D/enc_$i.json"
  R 20_encrypt.py --context "$D/public_context.tenseal" --encoded "$D/enc_$i.json" --out "$D/c_$i.bin"
done
R 30_compute_encrypted.py --context "$D/public_context.tenseal" \
  --inputs "$D/c_00.bin" "$D/c_01.bin" "$D/c_02.bin" "$D/c_03.bin" --out "$D/result.bin"
R 40_decrypt.py --context "$D/secret_context.tenseal" --result "$D/result.bin" --out "$D/plain.json"
R 50_decode.py  --plain "$D/plain.json" --length 16 --out "$D/result.json"
cat "$D/result.json"
```

## Test (local-loop equivalence)

```bash
uv --project signed/env run --group dev python -m pytest tests/
```

Proves keygen → encode → encrypt (≥3 synthetic contributors) → compute → decrypt
→ decode equals the cleartext oracle (same public weights) **bit-exact on the
integer-scaled aggregate**, and the sentinel decrypts to **exactly N** despite
the weight multiply (weight 1 on the sentinel slot), including that dropping one
upload yields N−1 and removes exactly that contributor's weighted dosage. A
parametrized case (`test_bit_exact_at_every_security_level`) re-runs the full
public-weighted loop at **`--security` 128, 192, and 256**, asserting bit-exact
correctness and sentinel==N under each coeff-modulus chain, and that each chain's
achieved security equals the requested level. Skips with a clear reason only if
TenSEAL cannot be imported.

## Coordinate & weight definition & synthetic data

For the synthetic v1 demo both the `L=1000` coordinate list and the public
weight vector are generated deterministically from `manifest.yml` seeds
(`input.coordinates.seed`, `weights.values.seed`). The invariant that matters is
that every contributor encodes against the **same** published coordinate
definition and is scored against the **same** published weights, and that both
are folded into the bundle SHA-256. All data here is synthetic integer/real
vectors; no real genomic data is used anywhere.
