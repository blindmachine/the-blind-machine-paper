# `carrier_count` — Blind Machine curated protocol

> tenseal-BFV, **minimal (additive-only) params**. A coordinate-wise homomorphic
> vector add over the flagship's exact published coordinate definition — but with
> a **different client-side encoding**. It is the registry-composability proof:
> one published coordinate definition and one additive primitive drive a second
> registered protocol without touching the trust loop. See
> `docs/protocol_catalog.md` §2.

## What it computes

Each contributor starts from the same alt-allele **dosage vector** `g ∈ {0,1,2}^L`
as the flagship, over the same fixed, published coordinate definition (ordered
variants `(chrom,pos,ref,alt)`). Encoding then thresholds each coordinate to a
**carrier indicator** *locally, before encryption*:

```
c[j] = 1 if g[j] >= 1 else 0        (missing call -> 0)
```

The cohort aggregate released is the per-coordinate **carrier count** — how many
participants carry at least one alt allele at each coordinate:

```
carrier_count[j] = Σ_i c_i[j]         (integer, exact, in [0, N])
carrier_rate[j]  = carrier_count[j] / N   (derived post-decrypt; people, not alleles → no ×2)
```

The contrast with the flagship is the whole point. Same raw genotypes, same
homomorphic circuit — but the flagship sums *dosages* (`sum_g / 2N` allele
frequency) while this sums *thresholded indicators* (`n / N` carrier rate). The
`tests/vectors/` fixtures are byte-identical to the flagship's so you can diff
the two released statistics from one input set.

**Exactness:** BFV is exact in `Z_t` with plaintext modulus `t > max sum = N`
(a carrier indicator is ≤ 1). `tolerance: 0` — the encrypted result equals the
cleartext sum **bit-for-bit**. The default `t = 1032193` stays exact for N up to
~1M (a larger margin than the flagship's `2N` ceiling).

**Append-1 sentinel:** encryption appends a trailing `1` slot to every
contribution, so the homomorphic sum's last slot decrypts to **exactly N**, the
contributor count. It is an integrity/corruption check, **not a MAC** — it says
nothing about whether contributors are distinct or genuine (see `SECURITY.md`).
Note a free cross-check this protocol admits: every `carrier_count[j]` must lie
in `[0, N]` (a headcount can't exceed the cohort), and `50_decode.py` asserts it.

## Security levels (`--security {128,192,256}`)

`00_keygen.py` takes `--security` (default `128`) to certify the context at a
chosen HE security level. It selects the coeff-modulus chain **only**; the ring
`N = 8192` and plaintext modulus `t = 1032193` are fixed (functions of the value
envelope and depth-0 circuit, not of security). Downstream stages read the
context and stay security-agnostic.

| `--security` | `coeff_mod_bit_sizes` | Σ bits | achieved (N=8192 caps 118/152/218) |
|--------------|-----------------------|--------|-------------------------------------|
| 128 (default) | `[60, 60, 60]` | 180 | **128** (band 153–218) |
| 192 | `[50, 50, 50]` | 150 | **192** (band 119–152) |
| 256 | `[45, 45, 28]` | 118 | **256** (band ≤118) |

At fixed `N`, security level == the q-band and a **smaller** coeff modulus is
**more** secure. This protocol's depth-0 noise floor sits in the 256 band, so
certifying 128/192 spends *surplus* modulus — the 128-bit chain is intentionally
**larger** (bigger, slower ciphertexts) than the 256-bit chain. That inversion is
correct RLWE behaviour, not a bug. The chain uses the PGS-safe 3-prime layout so
the `SECURITY` table is byte-identical across all four additive protocols. All
three levels decrypt **bit-exact** vs the cleartext oracle (parametrized in
`tests/test_local_loop.py`); the `security` column is computed from `(N, Σbits)`
against the HomomorphicEncryption.org table, never read back from SEAL.

```bash
(cd signed && uv --project env run python 00_keygen.py --out-dir "$D" --security 256)
```

## Reuse map (vs the flagship `allele_frequency_count`)

| stage | change |
|-------|--------|
| `00_keygen.py` | **verbatim** — same BFV params (8192 / 1032193) + shared `--security` table, no relin/Galois |
| `10_encode.py` | **one-line threshold** — emit `1 if dosage >= 1 else 0` instead of the dosage |
| `20_encrypt.py` | **verbatim** — append-1 sentinel + `bfv_vector` |
| `30_compute_encrypted.py` | **verbatim** — pure additive fold (`--context/--inputs/--out`) |
| `40_decrypt.py` | **verbatim** — one BFV integer vector, length L+1 |
| `50_decode.py` | **math only** — carrier rate `= n/N` (drop the diploid ×2), bound-check `[0,N]` |

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
| `10_encode.py` | local (data owner) | RAW → ENCODED | `--raw raw.json --length L --out encoded.json` (validate dosage {0,1,2}, null→0, threshold to {0,1}, pad to L) |
| `20_encrypt.py` | local (data owner) | ENCODED → ENCRYPTED | `--context public_context.tenseal --encoded encoded.json --out cipher.bin` (appends sentinel, BFV-encrypts) |
| `30_compute_encrypted.py` | **SERVER** | ENCRYPTED → ENCRYPTED | `--context public_context.tenseal --inputs c0.bin c1.bin … --out result.bin` (homomorphic sum; **no secret key present**) |
| `40_decrypt.py` | local (researcher) | ENCRYPTED → PRIVATE | `--context secret_context.tenseal --result result.bin --out plain.json` (length L+1) |
| `50_decode.py` | local (researcher) | PRIVATE → RELEASED | `--plain plain.json --length L --out result.json` (splits sentinel→N, carrier counts, rates) |

Inter-stage formats: contexts and ciphertexts are TenSEAL's raw serialized bytes
(binary); raw/encoded/plain are JSON int lists; the released result is JSON with
`n_contributors`, `carrier_counts`, `carrier_rates`.

`server.py`'s `compute` is written **once** against an abstract evaluator `E`
(`zero`/`add`), so `docs/simulation_mode.md`'s cleartext correctness oracle swaps
a `PlaintextEvaluator` for the same `compute` and cannot drift from this encrypted
path. Determinism gives verify-by-re-execution: the same ordered ciphertexts in →
a bit-identical result digest out (compute is deterministic; encryption is not).

## Run the full loop by hand

```bash
cd protocols/carrier_count
D=/tmp/cc && mkdir -p "$D"
R() { (cd signed && uv --project env run python "$@"); }

R 00_keygen.py --out-dir "$D"
for i in 00 01 02; do
  R 10_encode.py  --raw ../tests/vectors/contributor_$i.json --length 16 --out "$D/enc_$i.json"
  R 20_encrypt.py --context "$D/public_context.tenseal" --encoded "$D/enc_$i.json" --out "$D/c_$i.bin"
done
R 30_compute_encrypted.py --context "$D/public_context.tenseal" \
  --inputs "$D/c_00.bin" "$D/c_01.bin" "$D/c_02.bin" --out "$D/result.bin"
R 40_decrypt.py --context "$D/secret_context.tenseal" --result "$D/result.bin" --out "$D/plain.json"
R 50_decode.py  --plain "$D/plain.json" --length 16 --out "$D/result.json"
cat "$D/result.json"
```

## Test (local-loop equivalence)

```bash
uv --project signed/env run --group dev python -m pytest tests/
```

Proves keygen → encode → encrypt (≥3 synthetic contributors) → compute → decrypt
→ decode equals the cleartext carrier-count aggregate **exactly**, that the
distinguishing encoding thresholds dosage → {0,1}, and that the sentinel decrypts
to **exactly N** (including that dropping one upload yields N−1). Skips with a
clear reason only if TenSEAL cannot be imported.

## Coordinate definition & synthetic data

For the synthetic v1 demo the `L=1000` coordinate list is generated
deterministically from `manifest.yml`'s `input.coordinates.seed` — the **same**
seed (`blind-v1-demo-coordinates`) as the flagship, because this protocol reuses
that exact coordinate definition. The invariant that matters is that every
contributor encodes against the same published definition and that definition is
folded into the bundle SHA-256. All data here is synthetic integer vectors; no
real genomic data is used anywhere.
