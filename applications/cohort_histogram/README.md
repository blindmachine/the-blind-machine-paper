# `cohort_histogram` — Blind Machine curated protocol

> tenseal-BFV, **minimal (additive-only) params** — the exact same additive
> circuit as the flagship, pointed at a **non-genomic** aggregate. Each
> contributor is one-hot over a fixed, published bucket definition; the cohort
> result is the per-bucket count vector. It exists to prove the additive
> primitive is **generic**: genomics is the demo domain, not the only one.
> See `docs/protocol_catalog.md` §3.

## What it computes

Each contributor falls into **exactly one** bucket of a fixed, published,
ordered bucket definition (the v1 demo uses demographic age bands
`["0-9", "10-19", …, "90+"]`, `B = 10`). They map their raw value to a bucket
index per that definition and encode it as a one-hot vector `h ∈ {0,1}^B` with
`sum(h) = 1`. The cohort aggregate released is the per-bucket sum:

```
counts[b] = Σ_i h_i[b]          (integer, exact)   — the histogram
sum(counts) == N                (one-hot invariant; cross-checks the sentinel)
```

**Exactness:** BFV is exact in `Z_t` with plaintext modulus `t > max bucket
count`. Since each contribution is one-hot, the largest bucket count is `N`, so
`t = 1032193` is exact for `N` up to ~1M. `tolerance: 0` — the encrypted
histogram equals the cleartext histogram **bit-for-bit** at every security level.

## HE security level (`--security {128,192,256}`)

`00_keygen.py` accepts `--security {128,192,256}` (default **128**, matching the
prior behaviour). It is the ONLY security-dependent knob: it selects the
`coeff_mod_bit_sizes` chain (the RLWE ciphertext modulus). `poly_modulus_degree`
(N=8192) and `plain_modulus` (t=1032193) are **fixed** — they are functions of the
value envelope and the depth-0 additive circuit, not of security. The choice flows
downstream automatically because stages 20/40 `context_from(...)` the serialized
context; no other stage changes.

| `--security` | `coeff_mod_bit_sizes` | Σ bits | achieved (N=8192 band) |
|---|---|---|---|
| `128` (default) | `[60, 60, 60]` | 180 | **128** — band [153, 218] |
| `192` | `[50, 50, 50]` | 150 | **192** — band [119, 152] |
| `256` | `[45, 45, 28]` | 118 | **256** — band [≤118] |

At **fixed N the security level is the q-band**: a *smaller* Σ is *more* secure.
So — the intentional inversion — the **128-bit** chain uses a *larger* coeff
modulus (Σ=180, bigger/slower ciphertexts) than the **256-bit** chain (Σ=118).
The depth-0 additive noise floor for a bounded-int histogram sits deep in the 256
band, so certifying 128/192 spends *surplus* modulus. This is correct RLWE
behaviour, not a bug; all three decrypt bit-exact. The benchmark's `security`
column is computed by the harness as `achieved(N, Σ) = strictest level whose cap
covers Σ`, never read back from SEAL (SEAL always validates at tc128).

These 3-prime chains are byte-identical across all four additive protocols
(afc / carrier / cohort / pgs) so the `SECURITY` table stays one shared contract.
The `tests/` local-loop proves bit-exactness (and `achieved == requested`) at all
three levels.

**Append-1 sentinel:** encryption appends a trailing `1` slot to every
contribution, so the homomorphic sum's last slot decrypts to **exactly N**, the
contributor count. For a one-hot protocol this is doubly strong: the first `B`
slots must *also* total `N`, so decode asserts `sum(counts) == sentinel` — a free
integrity cross-check the flagship's dosage vectors don't have. It is an
integrity/corruption check, **not a MAC** — it says nothing about whether
contributors are distinct or genuine (see `SECURITY.md`).

## Reuse relationship to the flagship

`cohort_histogram` is a near-free clone of `allele_frequency_count`: `00_keygen`,
`20_encrypt`, `30_compute_encrypted`, and `40_decrypt` are the flagship's
additive stages verbatim (same BFV params, same append-1 sentinel, same abstract
`zero`/`add` evaluator fold, same `is_private()` server guard). Only two stages
change:

- `10_encode.py` — index → one-hot (a contributor holds a single bucket index in
  `[0, B)`; encode builds `[0]*B` with one `1`, and rejects an out-of-range or
  missing bucket — a one-hot histogram has no "missing → 0" escape hatch).
- `50_decode.py` — emits `{counts, n_contributors}`, drops the frequency/×2
  denominator, and adds the `sum(counts) == N` integrity assertion.

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
| `10_encode.py` | local (data owner) | RAW → ENCODED | `--raw raw.json --length B --out encoded.json` (raw is a single bucket index in `[0,B)`; emits one-hot) |
| `20_encrypt.py` | local (data owner) | ENCODED → ENCRYPTED | `--context public_context.tenseal --encoded encoded.json --out cipher.bin` (appends sentinel, BFV-encrypts) |
| `30_compute_encrypted.py` | **SERVER** | ENCRYPTED → ENCRYPTED | `--context public_context.tenseal --inputs c0.bin c1.bin … --out result.bin` (homomorphic sum; **no secret key present**) |
| `40_decrypt.py` | local (researcher) | ENCRYPTED → PRIVATE | `--context secret_context.tenseal --result result.bin --out plain.json` (length B+1) |
| `50_decode.py` | local (researcher) | PRIVATE → RELEASED | `--plain plain.json --length B --out result.json` (splits sentinel→N, counts; asserts `sum(counts)==N`) |

Inter-stage formats: contexts and ciphertexts are TenSEAL's raw serialized bytes
(binary); `raw.json` is a single JSON integer (bucket index); `encoded`/`plain`
are JSON int lists; the released result is JSON with `n_contributors`,
`buckets_length`, `counts`. **Bucket labels are not re-emitted** — the ordered
bucket definition lives in the digest-folded `manifest.yml`; the consumer maps
count position `b` to its published label.

`server.py`'s `compute` is written **once** against an abstract evaluator `E`
(`zero`/`add`), so `docs/simulation_mode.md`'s cleartext correctness oracle swaps
a `PlaintextEvaluator` for the same `compute` and cannot drift from this encrypted
path. Determinism gives verify-by-re-execution: the same ordered ciphertexts in →
a bit-identical result digest out (compute is deterministic; encryption is not).

## Run the full loop by hand

```bash
cd protocols/cohort_histogram
D=/tmp/ch && mkdir -p "$D"
R() { (cd signed && uv --project env run python "$@"); }

R 00_keygen.py --out-dir "$D"              # add --security 192 or 256 to certify a stronger level
for i in 00 01 02 03 04; do
  R 10_encode.py  --raw ../tests/vectors/contributor_$i.json --length 10 --out "$D/enc_$i.json"
  R 20_encrypt.py --context "$D/public_context.tenseal" --encoded "$D/enc_$i.json" --out "$D/c_$i.bin"
done
R 30_compute_encrypted.py --context "$D/public_context.tenseal" \
  --inputs "$D"/c_*.bin --out "$D/result.bin"
R 40_decrypt.py --context "$D/secret_context.tenseal" --result "$D/result.bin" --out "$D/plain.json"
R 50_decode.py  --plain "$D/plain.json" --length 10 --out "$D/result.json"
cat "$D/result.json"
```

## Test (local-loop equivalence)

```bash
uv --project signed/env run --group dev python -m pytest tests/
```

Proves keygen → encode → encrypt (≥3 synthetic contributors) → compute → decrypt
→ decode equals the cleartext histogram **exactly**, that the sentinel decrypts to
**exactly N** (including that dropping one upload yields N−1 and decrements that
contributor's bucket), and that the one-hot integrity check (`sum(counts) == N`)
rejects a tampered aggregate. Skips with a clear reason only if TenSEAL cannot be
imported.

## Bucket definition & synthetic data

For the synthetic v1 demo the `B = 10` bucket definition (ordered age bands) is
enumerated in `manifest.yml`'s `input.buckets.labels`. The invariant that matters
is that every contributor encodes their membership against the **same** published,
ordered definition and that definition is folded into the bundle SHA-256. All
data here is synthetic bucket indices; no real personal data is used anywhere.
