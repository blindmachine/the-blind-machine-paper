# `allele_frequency_with_variance` — Blind Machine multiplicative protocol

> tenseal-BFV, **multiplication-supporting params** (depth 1). The server SQUARES
> an encrypted value (ciphertext × ciphertext) to derive the second moment, so it
> exercises exactly **one** BFV multiplicative level. Same published coordinate
> definition and same contributor payload as the flagship
> (`allele_frequency_count`) — which makes it the controlled "money comparison"
> row: hold the inputs fixed, add one multiplicative level, measure the premium.
> See `docs/protocol_catalog.md` §5. The additive **client-precompute benchmark
> variant** (client pre-squares, server only sums) is documented in
> `BENCHMARK.md`; it is not a separate registry protocol.

## What it computes

Each contributor holds an alt-allele **dosage vector** `g ∈ {0,1,2}^L` over a
fixed, published coordinate definition (ordered variants `(chrom,pos,ref,alt)`),
identical to the flagship; missing calls encoded as 0. The cohort aggregate
released is **two** per-coordinate integer vectors — the first and second moments:

```
sum_g[j]   = Σ_i g_i[j]              (integer, exact — additive path)
sum_g2[j]  = Σ_i g_i[j]²             (integer, exact — server squares under encryption)

mean[j]     = sum_g[j] / N                          (mean dosage; derived post-decrypt)
variance[j] = sum_g2[j] / N − (sum_g[j] / N)²       (population variance E[g²]−E[g]²)
frequency[j]= mean[j] / 2                            (2 alleles per diploid coordinate)
```

**The square is server-side.** The client sends only one ciphertext of `g`. The
server computes `Σ_i enc(g_ij)²` under encryption — squaring **each contributor
first, then summing**, because `(Σ g)² ≠ Σ g²`. That per-contributor square is
the ct × ct multiply; it needs relinearization keys in the public context. This
is the whole point versus the additive benchmark variant, where the client would
also encrypt `g²` and the server would only add (`BENCHMARK.md`, `docs/spec.md`).

**Exactness:** BFV is exact in `Z_t`. The largest value is `max sum_g2 = 4N`
(`g² ≤ 4`), and the plaintext modulus `t = 786433` exceeds it for `N` up to ~196k.
`tolerance: 0` — both encrypted integer vectors equal the cleartext moments
**bit-for-bit**. `mean`/`variance`/`frequency` are real-valued derivations of the
two exact integer aggregates.

**Append-1 sentinel:** encryption appends a trailing `1` slot to every
contribution, so **both** result vectors' last slot decrypts to **exactly N**
(sum path: `Σ 1 = N`; square path: `Σ 1² = N`). `50_decode.py` cross-checks that
the two sentinels agree. It is an integrity/corruption check, **not a MAC** — it
says nothing about whether contributors are distinct or genuine (see `SECURITY.md`).

## Crypto approach — why multiplication-supporting params

| parameter | value | why |
|-----------|-------|-----|
| `poly_modulus_degree` | **16384** (fixed, all levels) | multiplication-supporting ring; 16384 slots ≫ L+1. The depth-1 noise floor (~200 bits) can't fit under the 152/118 caps at n=8192, so 8192 is out for 192/256 — N stays 16384 across all three levels (vary the chain, fix N). The larger ring is the dominant cost vs the flagship's 8192. |
| `coeff_mod_bit_sizes` | **selected by `--security`** (see table below) | this is the ONLY knob security moves; depth-1 needs ≥2 interior 40/60-bit primes between the two 60-bit special primes. |
| `plain_modulus` | **786433** (fixed, all levels) | 20-bit NTT batching prime, `≡ 1 (mod 32768)` — **required** at n=16384 (the flagship's `1032193` is invalid here). Exact for `max sum_g2 = 4N`. A function of the value envelope + depth, not of security. |
| relinearization keys | **yes** | ct × ct raises ciphertext degree to 3; TenSEAL relinearizes back to 2 using relin keys, which `00_keygen.py` generates (a secret key exists at context creation) and **retains through `make_context_public()`**. |
| Galois keys | **no** | the square is element-wise per slot; there is no rotation, so no Galois keys are generated. |

### `--security {128,192,256}` — the coeff-modulus chain

`00_keygen.py --security L` (default **128**) selects `coeff_mod_bit_sizes` from
the authoritative per-level table; `poly_modulus_degree` and `plain_modulus` are
fixed. The benchmark's `security` column is the achieved level computed from
`(N, Σ coeff_mod_bit_sizes)` against the HomomorphicEncryption.org caps at
N=16384 (256 ≤ 237, 192 = 238–305, 128 = 306–438), and **achieved == requested**
for every row (verified bit-exact against the cleartext oracle, TenSEAL 0.3.16):

| `--security` | `coeff_mod_bit_sizes` | Σ bits | achieved | ciphertext cost |
|--------------|-----------------------|--------|----------|-----------------|
| `128` (default) | `[60, 60, 60, 60, 60, 60]` | 360 | **128** | largest |
| `192` | `[60, 60, 60, 60]` | 240 | **192** | middle |
| `256` | `[60, 40, 40, 60]` | 200 | **256** | smallest |

**Intentional inversion:** at fixed N, security level == the q-band and *smaller*
Σ ⇒ *more* secure, so the **128-bit** cell uses a **larger** coeff modulus (bigger,
slower ciphertexts) than the **256-bit** cell. This is correct RLWE behaviour, not
a bug — the depth-1 noise floor for this payload already sits in the 256 band, so
certifying 128/192 spends *surplus* modulus. (`[60,40,40,60]=200` technically meets
all three targets; we publish cap-tracking chains so the `security` column reads a
distinct, honest 128/192/256.) The chain flows unchanged into every downstream
stage — they all `ts.context_from(...)`, so `10`–`50` stay security-agnostic.

**§3 escape hatch (not in the default table):** a *quantized-trait* /
oversized-cohort deployment whose grown `t` breaches the 256 cap at N=16384 moves
to **N=32768** via the explicit overrides — e.g.
`--security 256 --poly-modulus-degree 32768 --plain-modulus 537133057
--coeff-mod-bit-sizes 60 50 50 50 60`. This is a per-deployment override, not the
default binary payload.

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
| `00_keygen.py` | local (researcher) | — → PRIVATE + PUBLIC context | `--out-dir DIR` → `secret_context.tenseal` (never upload), `public_context.tenseal` (uploadable; **relin keys retained**) |
| `10_encode.py` | local (data owner) | RAW → ENCODED | `--raw raw.json --length L --out encoded.json` (validate {0,1,2}, null→0, pad to L) — verbatim flagship |
| `20_encrypt.py` | local (data owner) | ENCODED → ENCRYPTED | `--context public_context.tenseal --encoded encoded.json --out cipher.bin` (appends sentinel, BFV-encrypts a SINGLE ciphertext) — verbatim flagship |
| `30_compute_encrypted.py` | **SERVER** | ENCRYPTED → ENCRYPTED × 2 | `--context public_context.tenseal --inputs c0.bin c1.bin … --out result.bin` (**squares under encryption**; packs `sum_g` + `sum_g2` into ONE deterministic container; **no secret key present**) |
| `40_decrypt.py` | local (researcher) | ENCRYPTED × 2 → PRIVATE | `--context secret_context.tenseal --result result.bin --out plain.json` (unpacks both moments, each length L+1) |
| `50_decode.py` | local (researcher) | PRIVATE → RELEASED | `--plain plain.json --length L --out result.json` (splits both sentinels→N, sum_g, sum_g2, mean, variance, frequency) |

**`--out` on the compute stage is a single FILE.** Although this protocol emits
two result ciphertexts (`sum_g`, `sum_g2`), `30_compute_encrypted.py` packs them
into ONE self-describing, deterministic binary container written at the `--out`
FILE path — magic `BMCT1\n` (Blind Machine multi-CipherText container v1), a
uint8 count then, in fixed `MOMENT_ORDER = (sum, sumsq)`, each moment as a
length-prefixed name + length-prefixed raw ciphertext (`pack_results` /
`unpack_results`). This is the SAME container format
`genotype_phenotype_covariance` uses (each bundle carries its own verbatim copy —
bundles are self-contained). The single-file output is what the hosted worker
content-addresses (one opaque `result.bin`, SHA-256'd), so the flag convention
(`--context` / `--inputs` / `--out`) matches the flagship's exactly. Fixed field
order + length prefixes + no timestamps/maps make the packed bytes deterministic,
giving verify-by-re-execution.

Inter-stage formats: contexts and ciphertexts are TenSEAL's raw serialized bytes
(binary); raw/encoded are JSON int lists; `plain.json` is
`{"sum": [L+1 ints], "sumsq": [L+1 ints]}`; the released result is JSON with
`n_contributors`, `sum_g`, `sum_g2`, `mean`, `variance`, `allele_frequency`.

`server.py`'s `compute` is written **once** against an abstract evaluator `E`
(`zero`/`add`/**`mul`**), so `docs/simulation_mode.md`'s cleartext correctness
oracle swaps a `PlaintextEvaluator` for the same `compute` and cannot drift from
this encrypted path. Determinism gives verify-by-re-execution: the same ordered
ciphertexts in → bit-identical result digests out (compute is deterministic;
encryption is not).

## Run the full loop by hand

```bash
cd protocols/allele_frequency_with_variance
D=/tmp/afv && mkdir -p "$D"
R() { (cd signed && uv --project env run python "$@"); }

R 00_keygen.py --out-dir "$D"          # add --security {128,192,256} (default 128)
for i in 00 01 02 03; do
  R 10_encode.py  --raw ../tests/vectors/contributor_$i.json --length 16 --out "$D/enc_$i.json"
  R 20_encrypt.py --context "$D/public_context.tenseal" --encoded "$D/enc_$i.json" --out "$D/c_$i.bin"
done
R 30_compute_encrypted.py --context "$D/public_context.tenseal" \
  --inputs "$D/c_00.bin" "$D/c_01.bin" "$D/c_02.bin" "$D/c_03.bin" --out "$D/result.bin"
R 40_decrypt.py --context "$D/secret_context.tenseal" \
  --result "$D/result.bin" --out "$D/plain.json"
R 50_decode.py  --plain "$D/plain.json" --length 16 --out "$D/result.json"
cat "$D/result.json"
```

## Test (local-loop equivalence)

```bash
uv --project signed/env run --group dev python -m pytest tests/
```

Proves keygen → encode → encrypt (≥3 synthetic contributors) → compute (**server
squares**) → decrypt → decode equals the cleartext first- and second-moment
oracle **exactly** (both `sum_g` and `sum_g2`), and that the sentinel decrypts to
**exactly N** in both paths (including that dropping one upload yields N−1). A
**parametrized case runs the full loop at each `--security` level (128, 192,
256)** and asserts bit-exact moments + sentinel==N at every level, plus that the
shipped chain lands in the requested q-band (achieved == requested). One test
guards the mandatory square-then-sum (`Σ g² ≠ (Σ g)²`); one runs the **additive
client-precompute benchmark variant** and asserts a bit-identical `sum_g2`. Skips
with a clear reason only if TenSEAL cannot be imported.

## Coordinate definition & synthetic data

For the synthetic v1 demo the `L=1000` coordinate list is generated
deterministically from `manifest.yml`'s `input.coordinates.seed` — the **same
seed as the flagship**, which is what makes protocol 5 the controlled
multiplicative comparison. The invariant that matters is not a separate
coordinate file — it is that every contributor encodes against the **same**
published definition and that definition is folded into the bundle SHA-256. All
data here is synthetic integer vectors; no real genomic data is used anywhere.
