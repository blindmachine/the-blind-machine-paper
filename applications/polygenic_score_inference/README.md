# `polygenic_score_inference` — Blind Machine curated application

> tenseal-BFV. **Per-individual** polygenic risk scores over encrypted genotypes
> under a **PUBLIC** model — a bit-exact, memory-light reproduction of **HEPRS**
> (Knight et al., *Homomorphic encryption enables privacy preserving polygenic
> risk scores*, Cell Reports Methods 2026; `github.com/gersteinlab/HEPRS`).

## What it computes

Each contributor `i` holds an alt-allele **dosage vector** `g_i ∈ {0,1,2}^L`
(missing calls → 0). The application fixes a **public effect-weight vector**
`w ∈ ℝ^L` — a published PRS model (e.g. a PGS-Catalog / GWAS weight set) —
integer-scaled by a fixed-point factor `S` and folded into the bundle digest. The
server returns **each individual's encrypted polygenic risk score**:

```
PRS_i = Σ_j w_j · g_ij            (one encrypted scalar per contributor)
```

The project owner (researcher) decrypts the `N` scalars and gets each
participant's score plus the cohort distribution (mean, sd, quartiles). The
compute server sees only ciphertext; the researcher sees scores, never genotypes.

## Why this is the least-powerful scheme that does the job

HEPRS encrypts **both** the genotypes and the model, so its per-SNP product is a
**ciphertext × ciphertext** multiply (`MulRelinNew` → relinearization → the
multiplicative tier), and it holds the whole encrypted cohort *and* model in RAM
(≈ 65 GB for 1,146 samples × 110k SNPs). We target the common case where the
**model is public** — most published PRS are. Then:

| step | HEPRS | this application |
|------|-------|------------------|
| per-SNP product | ciphertext × ciphertext (`MulRelinNew`) | ciphertext × **plaintext** (public weight) |
| relinearization keys | required | **none** |
| model encryption | yes (doubles ciphertext footprint) | **none** (public plaintext) |
| intra-vector reduction | `InnerSumLog` rotations | rotate-sum (`.sum()`), same Galois keys |
| numeric result | CKKS approximate (MSE ~1e-8) | **BFV bit-exact** (tolerance 0) |
| memory | whole cohort + model resident | **one contributor at a time** (streamed) |

The only homomorphism beyond add + plaintext-multiply is the intra-vector
reduction `Σ_j` (a rotate-and-sum, needs Galois keys — the one difference from
the flagship's Galois-free additive tier). No ciphertext × ciphertext multiply
ever happens; ciphertext degree never rises; no relinearization keys exist.

## BFV parameters

| param | value | why |
|-------|-------|-----|
| `poly_modulus_degree` | 8192 | N/2 = 4096 rotate-summable slots per ciphertext; a model of L SNPs splits into ⌈L/4096⌉ chunk-ciphertexts. |
| `plain_modulus` | 1073692673 | 30-bit batching prime (≡ 1 mod 16384). Exact signed BFV in Z_t; the value-envelope guard keeps `|PRS_scaled| < t/2` so the sign is recoverable on decrypt. |
| `coeff_mod_bit_sizes` | see `--security` | selects the q-band that fixes the achieved HE security level. |
| Galois keys | **yes** | the rotate-sum needs them (enlarges the PUBLIC context to ~15–20 MB). |
| relin keys | **none** | ciphertext × plaintext only; no ciphertext × ciphertext. |

### `--security {128,192,256}` (default 128)

`--security` selects the `coeff_mod_bit_sizes` chain. At **fixed N=8192** the
security level is the q-band: smaller Σbits ⇒ more secure. Every chain decrypts
the rotate-summed, public-weighted score **bit-exact** (verified, TenSEAL 0.3.16).

| `--security` | `coeff_mod_bit_sizes` | Σ bits | achieved |
|---|---|---|---|
| 128 (default) | `[60, 60, 60]` | 180 | 128 |
| 192 | `[50, 50, 50]` | 150 | 192 |
| 256 | `[45, 45, 28]` | 118 | 256 |

The minimal 256-bit chain has the least noise budget and still survives the 12
rotations of the rotate-sum plus the plaintext-weight multiply.

## Public model (deterministic, content-addressed)

`manifest.yml` declares `weights: { scale: 1000, values: { kind:
synthetic_weights, seed: blind-v1-prs-inference-weights, range: [-2000, 2000] } }`.
`server.py`'s `scaled_weights(length)` regenerates the exact **signed** integer
weight vector from that seed (real GWAS betas are signed), so the server and the
cleartext oracle score every contributor against the identical vector, and any
change to the seed/scale/generator changes the bundle digest.

**A real deployment ships the published model** as a signed
`model_weights.json` (`{"scaled_weights": [...]}`) beside `server.py` — also
folded into the digest. `scaled_weights` prefers that file when present. This is
the seam through which a researcher points the application at their own PRS
(e.g. the 110,258-SNP HEPRS schizophrenia model): swap the weights, re-sign, and
the score is computed blind on every contributor's ciphertext.

## Stage lifecycle & I/O contract

The author's logic lives in three pure-function files, grouped by role:
`server.py` (`compute`, the only server-side function), `local_project_owner.py`
(`keygen`/`decrypt`/`decode`), `local_data_owner.py` (`encode`/`encrypt`), plus a
trivial shared `_packing.py` (length-prefixed byte framing). The six numbered
files are materialized at run time and are **kit-owned shims** (do not edit).

| stage | runs | trust in → out | I/O |
|-------|------|----------------|-----|
| `00_keygen.py` | local (researcher) | — → PRIVATE + PUBLIC context | `--out-dir DIR [--security {128,192,256}]` → `secret_context.tenseal` (never upload), `public_context.tenseal` (uploadable; carries Galois keys) |
| `10_encode.py` | local (data owner) | RAW → ENCODED | `--raw raw.json --length L --out encoded.json` ({0,1,2}, null→0, pad to L) |
| `20_encrypt.py` | local (data owner) | ENCODED → ENCRYPTED | `--context public_context.tenseal --encoded encoded.json --out cipher.bin` (⌈L/4096⌉ chunk-ciphertexts, framed with the length header) |
| `30_compute_encrypted.py` | **SERVER** | ENCRYPTED → ENCRYPTED | `--context public_context.tenseal --inputs c0.bin c1.bin … --out result.bin` (per contributor: ciphertext × public plaintext + rotate-sum → one scalar; **no secret key present**) |
| `40_decrypt.py` | local (researcher) | ENCRYPTED → PRIVATE | `--context secret_context.tenseal --result result.bin --out plain.json` (N signed scaled scores) |
| `50_decode.py` | local (researcher) | PRIVATE → RELEASED | `--plain plain.json --length L [--scale S] --out result.json` (per-individual PRS + cohort distribution) |

## Test (local-loop equivalence)

```bash
uv --project signed/env run --group dev python -m pytest tests/
```

Proves keygen → encode → encrypt (≥3 contributors) → compute → decrypt → decode
equals the cleartext oracle (same public weights) **bit-exact on every
per-individual score**, that **signed** scores round-trip exactly, that scores
are independent per contributor, that a model longer than one ciphertext (the
110k-SNP path) is exact, and that the loop is bit-exact at `--security` 128 / 192
/ 256. Skips with a clear reason only if TenSEAL cannot be imported.

## Reproducing HEPRS

The `docs/paper/experiments/` harness (experiment **E9**) reproduces the HEPRS
public 10k-SNP × 50-individual example and a synthetic scaling sweep (SNPs
10k→130k, samples 50→2000, plus the 110k × 1,146 schizophrenia scale) on this
application, and reports the head-to-head time / memory / exactness comparison.
See `BENCHMARK.md` for the measured numbers. All data used here is synthetic
(HAPGEN2-style) or the HEPRS public example; the real PsychENCODE genotypes are
controlled-access and are not redistributed.
