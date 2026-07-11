# `genotype_phenotype_covariance` — Blind Machine protocol (v1 encrypted×encrypted anchor)

> tenseal-BFV, **multiplication-supporting params**, depth 1. The protocol that
> justifies shipping the multiplication tier at all: the server derives a genuine
> **ciphertext × ciphertext** product under encryption (`enc(g) · enc(y)`), which
> the additive tier structurally cannot do. Same trust loop as the flagship
> (`freeze cohort → encrypted moments → min-N release → certificate`), one
> relinearized multiplicative level deeper. See `docs/protocol_catalog.md` §6.

## What it computes

Each contributor holds a genotype **dosage vector** `g ∈ {0,1,2}^L` over a fixed,
published coordinate definition (ordered variants `(chrom,pos,ref,alt)`; missing
calls → 0) **and** an integer-coded **phenotype scalar** `y` (binary
case/control in `{0,1}` by default, or a quantized trait in `{0..Q}`). Both are
encrypted and co-packed into **one blob per contributor** (a `BMCT1` container
carrying that owner's `(cipher_g, cipher_y)` pair) so the server forms the product
itself. One blob per contributor is the platform's canonical contribution shape —
it keeps the pair inseparable through the hosted worker's digest-sorting Stager
(see [Contribution shape](#contribution-shape-one-packed-gy-blob)). The cohort
aggregate released is four moments:

```
sum_g[j]  = Σ_i g_ij                 (additive)
sum_gy[j] = Σ_i g_ij · y_i           (ciphertext × ciphertext, depth 1)
sum_y     = Σ_i y_i                  (additive, read from a broadcast slot)
sum_y2    = Σ_i y_i²                 (ciphertext × ciphertext, depth 1)
```

and, post-decrypt, the per-variant genotype/phenotype covariance:

```
cov[j] = sum_gy[j]/N − (sum_g[j]/N)·(sum_y/N)
```

(plus the cohort phenotype mean `sum_y/N` and variance `sum_y2/N − (sum_y/N)²`).

**Phenotype broadcast.** At encode time the scalar `y` is broadcast to all `L`
slots, so the element-wise `cipher_g · cipher_y` yields `g_j · y` per coordinate
with **no cross-slot rotation** — which is why this protocol needs **relin keys
but no Galois keys**. `sum_y` / `sum_y²` are therefore constant across the leading
slots (any slot is the scalar); decode reads one and cross-checks uniformity.

**Exactness:** BFV is exact in `Z_t`. With a binary phenotype the largest moment
is `~2N` (`sum_gy`, `g≤2·y≤1`), so `plain_modulus t = 786433` (a 20-bit batching
prime valid at `poly=16384`) stays exact for `N` up to ~196k. `tolerance: 0` — the
encrypted integer moments equal the cleartext moments **bit-for-bit**. A quantized
trait `y ∈ {0..Q}` raises the envelope to `~N·Q²` and needs a larger `t` (a per-
deployment build decision; see `SECURITY.md`).

**Append-1 sentinel:** encryption appends a trailing `1` to BOTH the genotype and
the broadcast-phenotype vectors, so all four moments' last slot decrypts to
**exactly N** (`sum_g`/`sum_y`: `Σ1=N`; `sum_gy`/`sum_y2`: `Σ 1·1 = N`). decode
cross-checks that all four sentinels agree — a stronger integrity check than the
single-sentinel additive flagship — but it is an integrity check, **not a MAC**
(see `SECURITY.md`).

<a name="contribution-shape-one-packed-gy-blob"></a>
**Contribution shape — one packed `(g,y)` blob.** Each contributor uploads a
**single** ciphertext blob that co-packs its `(cipher_g, cipher_y)` pair into a
deterministic `BMCT1` container (magic `BMCT1\n`, names `{g, y}` — the same
container format stage 30 uses for the four moment ciphertexts). This is
load-bearing, not cosmetic: the hosted worker's `Stager` digest-sorts every
staged ciphertext (`worker/lib/blind_worker/stager.rb`), so two *separate* `g` and
`y` ciphertexts would be reordered into an arbitrary permutation and the server's
positional pairing would break — silently, because every moment's append-1
sentinel still reconciles to N. Co-packing the pair at encrypt time makes that
mis-pairing **structurally impossible**: the digest-sort can only permute whole
contributors, never split a pair, and the moment folds in stage 30 are order-
independent across contributors (pinned by
`test_result_is_order_independent_under_digest_sort`).

## Why encrypted × encrypted (honest note)

For a **single** contributor who holds both `g` and `y`, the product `g·y` is
client-precomputable — so the same covariance *could* be served by additive BFV
with a client-supplied `g·y`. v1 ships the multiplicative version deliberately, and
the paper states the actual benefit plainly (`docs/protocol_catalog.md` §6):
**server-derived-quantity integrity** (the server, not a possibly-malformed client,
forms the product), **minimal contributor payload** (one packed blob carrying two
ciphertexts, no precomputed cross-terms), and it is the **bridge to future
cross-party products**
where `g` and `y` are held by *different* parties and no single client can
precompute `g·y`. It is not mathematical necessity — it is the least-powerful
configuration that exercises the encrypted-multiply path v2 will need.

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
| `00_keygen.py` | local (researcher) | — → PRIVATE + PUBLIC context | `--out-dir DIR` → `secret_context.tenseal` (never upload), `public_context.tenseal` (+relin keys, uploadable) |
| `10_encode.py` | local (data owner) | RAW → ENCODED | `--raw raw.json --length L --out encoded.json` → `{g:[L], y:[L broadcast]}` |
| `20_encrypt.py` | local (data owner) | ENCODED → ENCRYPTED | `--context public_context.tenseal --encoded encoded.json --out cipher.bin` (appends sentinel to both, BFV-encrypts, packs the (g,y) pair into ONE BMCT1 blob) |
| `30_compute_encrypted.py` | **SERVER** | ENCRYPTED → ENCRYPTED | `--context public_context.tenseal --inputs ct0 ct1 … --out result.bin` (one packed (g,y) blob per contributor; unpacks each; **encrypted products**; order-independent; **no secret key present**) |
| `40_decrypt.py` | local (researcher) | ENCRYPTED → PRIVATE | `--context secret_context.tenseal --result result.bin --out plain.json` (unpacks 4 moments, each length L+1) |
| `50_decode.py` | local (researcher) | PRIVATE → RELEASED | `--plain plain.json --length L --out result.json` (splits sentinels, cross-checks N, computes covariance) |

Inter-stage formats: contexts and ciphertexts are TenSEAL's raw serialized bytes
(binary); `raw` is `{"genotype":[…], "phenotype":y}`; `encoded` is `{"g":[…],
"y":[…]}`; `plain` is a labelled dict of four int vectors; the released result is
JSON with `sum_g`, `sum_gy`, `sum_y`, `sum_y2`, `mean_g`, `mean_y`, `var_y`,
`covariance`, `n_contributors`.

**Server I/O contract preserved.** Stage 30 keeps the flagship's exact
`--context/--inputs/--out` CLI (that is what the server worker invokes), writing
ONE opaque `result.bin` FILE that the hosted worker content-addresses. The four
moment ciphertexts are packed into that single `--out` artifact as a
deterministic, self-describing binary container — magic `BMCT1\n` (Blind Machine
multi-CipherText container v1), a uint8 count then, in fixed
`MOMENT_ORDER = (sum_g, sum_gy, sum_y, sum_y2)`, each moment as a length-prefixed
name + length-prefixed raw ciphertext (`pack_results`/`unpack_results`). This is
the SAME container format `allele_frequency_with_variance` uses (each bundle
carries its own verbatim copy — bundles are self-contained). The moments cannot
be folded into one ciphertext without cross-slot masking (rotation/Galois), which
this protocol deliberately avoids, so one artifact carries four labelled
ciphertexts.

`server.py`'s `compute` is written **once** against an abstract evaluator `E`
(`add`/`mul`), so `docs/simulation_mode.md`'s cleartext correctness oracle swaps a
`PlaintextEvaluator` for the same `compute` and cannot drift from this encrypted
path. Determinism (BFV add and relinearized multiply are deterministic; the
container order is fixed) gives verify-by-re-execution: the same ordered
ciphertexts in → a bit-identical result digest out.

## Run the full loop by hand

```bash
cd protocols/genotype_phenotype_covariance
D=/tmp/gpc && mkdir -p "$D"
R() { (cd signed && uv --project env run python "$@"); }

R 00_keygen.py --out-dir "$D"
inputs=()
for i in 00 01 02 03; do
  R 10_encode.py  --raw ../tests/vectors/contributor_$i.json --length 16 --out "$D/enc_$i.json"
  R 20_encrypt.py --context "$D/public_context.tenseal" --encoded "$D/enc_$i.json" \
    --out "$D/ct_$i.bin"          # ONE packed (g,y) blob per contributor
  inputs+=("$D/ct_$i.bin")
done
R 30_compute_encrypted.py --context "$D/public_context.tenseal" \
  --inputs "${inputs[@]}" --out "$D/result.bin"   # input order does not matter
R 40_decrypt.py --context "$D/secret_context.tenseal" --result "$D/result.bin" --out "$D/plain.json"
R 50_decode.py  --plain "$D/plain.json" --length 16 --out "$D/result.json"
cat "$D/result.json"
```

## Test (local-loop equivalence)

```bash
uv --project signed/env run --group dev python -m pytest tests/
```

Proves keygen → encode → encrypt (≥3 synthetic contributors, one packed (g,y) blob
each) → compute (a **real ct×ct product**) → decrypt → decode equals the cleartext
moment oracle **exactly**, that the SAME `compute()` run over a `PlaintextEvaluator`
agrees with a direct cleartext oracle (the abstract-evaluator seam), that the
sentinel decrypts to **exactly N** in all four moments (including that dropping one
upload yields N−1 and removes exactly that contributor's moments), and that
**digest-sorting the contributor blobs — the exact reordering the hosted Stager
performs — does not change the decoded result**. Skips with a clear reason only if
TenSEAL cannot be imported.

## Crypto parameters

| param | value | why |
|-------|-------|-----|
| `poly_modulus_degree` | 16384 | multiplication-supporting ring; 16384 slots ≫ L+1. **Fixed** across all three security levels (the depth-1 noise floor cannot fit under the 152/118 caps at n=8192) |
| `coeff_mod_bit_sizes` | **selected by `--security`** | the ONLY security knob (see table below); all three land under the 438-bit cap at n=16384 with ≥2 interior primes for the one multiplicative level |
| `plain_modulus` | 786433 | 20-bit batching prime ≡ 1 (mod 2·16384); **fixed** per protocol (function of the value envelope + depth, not of security). The flagship's 1032193 is INVALID at this ring size |
| relin keys | **yes** | to relinearize each ct×ct product (depth 1) |
| Galois keys | **no** | every op is element-wise; the phenotype is broadcast, so no rotation |

### `--security {128,192,256}` (default 128)

`00_keygen.py` accepts `--security` to select the coefficient-modulus chain. `N`
(16384) and `plain_modulus` (786433) are fixed — only the chain moves the achieved
level, which flows unchanged through every later stage (they all
`ts.context_from(...)`).

| `--security` | `coeff_mod_bit_sizes` | Σ bits | achieved | q-band (n=16384) |
|---|---|---|---|---|
| 128 (default) | `[60, 60, 60, 60, 60, 60]` | 360 | **128** | 306–438 |
| 192 | `[60, 60, 60, 60]` | 240 | **192** | 238–305 |
| 256 | `[60, 40, 40, 60]` | 200 | **256** | ≤237 |

**The intentional inversion:** at fixed `N`, security level == the q-band, so a
*smaller* coefficient modulus is *more* secure. The depth-1 noise floor for the
binary payload sits in the 256 band, so certifying 128/192 means spending *surplus*
modulus (bigger, slower ciphertexts). The 128-bit config is therefore the **largest
and slowest**, not the cheapest — correct RLWE behaviour, not a bug (see
`SECURITY.md`). All three decrypt **bit-exact** vs the cleartext oracle
(`test_local_loop_bit_exact_at_every_security_level`, TenSEAL 0.3.16), with the
append-1 sentinel recovering exactly N in all four moments at each level.

```bash
python 00_keygen.py --out-dir "$D" --security 192   # 192-bit context
```

**Escape hatch (§3, quantized trait / oversized cohort).** A quantized phenotype
`y ∈ {0..Q}` needs `t > ~N·Q²` (a ~30-bit batching prime), whose fatter depth-1
noise budget breaches the 256 cap at n=16384 and forces `N=32768`. That per-
deployment build is reachable by overriding the fixed knobs directly:
`--poly-modulus-degree 32768 --plain-modulus 537133057 --coeff-mod-bit-sizes 60 40 40 60`
(the explicit `--coeff-mod-bit-sizes` overrides `--security`). Not part of the
default table.

## Coordinate definition & synthetic data

For the synthetic v1 demo the `L=1000` coordinate list and the phenotype coding
scheme are generated/declared deterministically from `manifest.yml` (`input`
block) rather than enumerated inline. The invariant that matters is that every
contributor encodes against the **same** published definition (variants +
phenotype coding) and that definition is folded into the bundle SHA-256. All data
here is synthetic integer vectors; no real genomic or phenotype data is used
anywhere.
