# `allele_frequency_count` — Blind Machine flagship protocol

> tenseal-BFV, **minimal (additive-only) params**. The simplest possible circuit:
> a coordinate-wise homomorphic vector add. It carries the whole trust loop
> end-to-end (freeze cohort → encrypted sum → min-N release → certificate) and is
> the additive-suffices baseline every multiplicative-depth cost number is
> measured against. See `docs/protocol_catalog.md` §1.

## What it computes

Each contributor holds an alt-allele **dosage vector** `g ∈ {0,1,2}^L` over a
fixed, published coordinate definition (ordered variants `(chrom,pos,ref,alt)`);
coordinate `j` is the participant's alt-allele count at variant `j`, missing
calls encoded as 0. The cohort aggregate released is the per-coordinate sum:

```
sum_g[j] = Σ_i g_i[j]          (integer, exact)
frequency[j] = sum_g[j] / (2·N)   (derived post-decrypt; 2 alleles per diploid coordinate)
```

**Exactness:** BFV is exact in `Z_t` with plaintext modulus `t > max sum = 2N`.
`tolerance: 0` — the encrypted result equals the cleartext sum **bit-for-bit**.

**Append-1 sentinel:** encryption appends a trailing `1` slot to every
contribution, so the homomorphic sum's last slot decrypts to **exactly N**, the
contributor count. It is an integrity/corruption check, **not a MAC** — it says
nothing about whether contributors are distinct or genuine (see `SECURITY.md`).

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
| `10_encode.py` | local (data owner) | RAW → ENCODED | `--raw raw.json --length L --out encoded.json` (validate {0,1,2}, null→0, pad to L) |
| `20_encrypt.py` | local (data owner) | ENCODED → ENCRYPTED | `--context public_context.tenseal --encoded encoded.json --out cipher.bin` (appends sentinel, BFV-encrypts) |
| `30_compute_encrypted.py` | **SERVER** | ENCRYPTED → ENCRYPTED | `--context public_context.tenseal --inputs c0.bin c1.bin … --out result.bin` (homomorphic sum; **no secret key present**) |
| `40_decrypt.py` | local (researcher) | ENCRYPTED → PRIVATE | `--context secret_context.tenseal --result result.bin --out plain.json` (length L+1) |
| `50_decode.py` | local (researcher) | PRIVATE → RELEASED | `--plain plain.json --length L --out result.json` (splits sentinel→N, counts, frequencies) |

Inter-stage formats: contexts and ciphertexts are TenSEAL's raw serialized bytes
(binary); raw/encoded/plain are JSON int lists; the released result is JSON with
`n_contributors`, `allele_counts`, `allele_frequencies`.

`server.py`'s `compute` is written **once** against an abstract evaluator `E`
(`zero`/`add`), so `docs/simulation_mode.md`'s cleartext correctness oracle swaps
a `PlaintextEvaluator` for the same `compute` and cannot drift from this encrypted
path. Determinism gives verify-by-re-execution: the same ordered ciphertexts in →
a bit-identical result digest out (compute is deterministic; encryption is not).

## HE security level (`--security`)

`00_keygen.py` accepts `--security {128,192,256}` (default `128`, matching the
prior behaviour). It is the **only** knob that varies with the security level and
selects the coeff-modulus chain (`coeff_mod_bit_sizes`); `poly_modulus_degree`
(N=8192) and `plain_modulus` (t=1032193) are FIXED — functions of the value
envelope and depth (0), not of security. Downstream stages `context_from(...)`
the serialized context, so they stay security-agnostic: the choice flows through
automatically.

| `--security` | `coeff_mod_bit_sizes` | Σ bits | achieved | N | t |
|---|---|---|---|---|---|
| `128` (default) | `[60, 60, 60]` | 180 | 128 | 8192 | 1032193 |
| `192` | `[50, 50, 50]` | 150 | 192 | 8192 | 1032193 |
| `256` | `[45, 45, 28]` | 118 | 256 | 8192 | 1032193 |

**Intentional inversion:** at FIXED N, the security level is the coeff-modulus
band — *smaller* Σ ⇒ *more* secure. So the 256 chain is the SMALLEST (and its
ciphertexts are the cheapest); the depth-0 noise floor for this payload already
sits in the 256 band, so certifying 128/192 spends *surplus* modulus. "256 is
cheaper than 128" is correct RLWE behaviour, not a bug. The chains are shared
byte-for-byte across all four additive protocols (PGS-safe 3-prime chains).

The benchmark's `security` column is computed by the harness as
`achieved(N, Σbits)` = the strictest level whose HomomorphicEncryption.org cap
Σ fits under — never read back from SEAL (SEAL only validates at tc128). Every
level is verified bit-exact vs the cleartext oracle (see the test below).

```bash
(cd signed && uv --project env run python 00_keygen.py --out-dir "$D" --security 256)
```

## Run the full loop by hand

```bash
cd protocols/allele_frequency_count
D=/tmp/afc && mkdir -p "$D"
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
→ decode equals the cleartext aggregate **exactly**, and the sentinel decrypts to
**exactly N** (including that dropping one upload yields N−1). A parametrized case
re-runs the whole loop at **each** `--security` level {128, 192, 256}, asserting
bit-exactness and that each chain's *achieved* security equals the *requested*
level. Skips with a clear reason only if TenSEAL cannot be imported.

## Coordinate definition & synthetic data

For the synthetic v1 demo the `L=1000` coordinate list is generated
deterministically from `manifest.yml`'s `input.coordinates.seed` rather than
enumerated inline. The invariant that matters is not a separate coordinate file —
it is that every contributor encodes against the **same** published definition and
that definition is folded into the bundle SHA-256. All data here is synthetic
integer vectors; no real genomic data is used anywhere.
