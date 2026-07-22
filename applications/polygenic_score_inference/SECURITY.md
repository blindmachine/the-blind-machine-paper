# Security notes — `polygenic_score_inference`

Scoped to this bundle. The platform-wide threat model lives in `docs/manifesto.md`,
`docs/requirements.md`, and `docs/simulation_mode.md` §5. Kerckhoffs applied to a
product: **no guarantee rests on the secrecy — or the honesty — of the server.**

## Trust classes (what may cross the wire)

| class | example artifact | may leave the owner's machine? |
|-------|------------------|-------------------------------|
| RAW | `raw.json` genotypes | **no** |
| ENCODED | `encoded.json` dosage vector | **no** |
| PRIVATE | `secret_context.tenseal` (secret key), `plain.json` (per-individual scores) | **no, ever** |
| ENCRYPTED | `cipher.bin`, `result.bin` | yes |
| PUBLIC | `public_context.tenseal` (incl. Galois keys), the effect weights (`manifest.yml` / `model_weights.json`) | yes |

Only ENCRYPTED and PUBLIC are ever uploaded. `00_keygen.py` writes the secret key
to `secret_context.tenseal`, used **only** by `40_decrypt.py` on the researcher's
machine. There is no `/api/v1` endpoint that accepts a secret key. The effect
weights are **already public** (a published model, folded into the digest).

## Who learns what (the honest trust model)

Three distinct parties, and what each can see:

- **The compute server (evaluator).** Sees ciphertext genotypes + the public
  context + the public plaintext weights, and returns ciphertext scores. It holds
  **no secret key** — `compute` refuses a context where `is_private()` is true — so
  it cannot read a single genotype or a single score. This is the guarantee the
  paper rests on.
- **The data owners (contributing sites / participants).** Each encrypts only
  their own genotype under the project's public key. Raw genotypes never leave a
  contributor's machine in the clear, and no contributor sees another's data.
- **The project owner (researcher, key holder).** Decrypts and receives the `N`
  per-individual **scores** — never the genotypes. This is the intended output (a
  cohort PRS study computed without any party aggregating raw genomes in the
  clear), and the reason the release is **not** `aggregate_only`: per-individual
  scores are what reproduce HEPRS's per-individual R²/AUROC validation.

**Difference from HEPRS.** In HEPRS the *model itself* is also hidden from the
evaluator (the modeler encrypts it). Here the model is **public** by construction
— that is the trade we make for the efficiency win (ciphertext × plaintext, no
relin, no model ciphertext). For a private-model PRS you would need a
ciphertext × ciphertext application (the multiplicative tier), which is out of
scope for this bundle. This bundle targets the common case: a **published** PRS
model applied to **private** genotypes by an **untrusted** compute provider.

## Public weights → additive tier + rotate-sum, no ciphertext × ciphertext

The score is a weighted sum `Σ_j w_j·g_ij`, but the weights are **public**, so
each product is **ciphertext × plaintext**:

- A plaintext multiply does not raise ciphertext degree ⇒ **no relinearization
  keys** are generated or shipped.
- The one homomorphism beyond add is the intra-vector reduction `Σ_j`, done as a
  rotate-and-sum (`.sum()`) under encryption ⇒ **Galois keys are generated** (the
  one addition over the flagship's Galois-free tier). No cross-contributor
  rotation, no ciphertext × ciphertext, ever.

Computing `Σ_j` under encryption (rather than post-decrypt) is deliberate: it is
what lets the server return a per-individual **scalar** score. A post-decrypt
reduction would hand the key holder each contributor's per-coordinate weighted
dosage — which, because the weights are public and invertible, would reveal the
raw genotype. Reducing under encryption releases only the scalar.

## What FHE here does and does not hide

- **Hides:** individual genotype vectors from the compute server AND from the
  researcher (inputs are ciphertext; only scalar scores are released).
- **Does not hide:** the released per-individual scores (from the key holder), the
  effect weights (public by construction), and metadata (participant count,
  timing, ciphertext sizes, application choice).
- **Differencing / re-identification of a score.** A per-individual score is a
  single scalar; it is not a genotype, but a released score is still individual
  data. `min_contributors ≥ 20` + cohort freeze + `allowed_runs_per_project: 1`
  (min-N + freeze + run cap) mitigate cross-run differencing; they are not a
  complete defense. Cross-cohort / Sybil differencing and DP query budgets are v2.
  Documented, not hand-waved — see `docs/simulation_mode.md` §5.
- **Integrity, not authenticity.** Nothing here proves a contributor's genotype is
  genuine, distinct, or non-Sybil; this bundle drops the flagship's append-1
  sentinel (it does not compose with the per-individual rotate-sum). The
  contributor count `N` is `len(inputs)`, taken from the frozen cohort.

## Exactness / parameter safety

BFV is exact in `Z_t`. Weights are **signed**, represented in Z_t; the score's
sign is recovered on decrypt (`residue > t/2` ⇒ negative). Exactness needs
`|PRS_scaled| < t/2`. `server._check_value_envelope` fails **closed** if a model's
worst-case magnitude (`2·Σ_j|w_scaled[j]|`) would reach `t/2` — a model outside
the published envelope (`S = 1000`, `|w_scaled| ≤ 2000`) must widen `t` rather
than silently wrap. Within the envelope, each per-individual score equals the
cleartext weighted sum **bit-for-bit** (`tolerance: 0`); the released real values
carry the fixed-point resolution `1/S` (per-weight rounding error ≤ `1/S`) — a
**stronger** guarantee than HEPRS's CKKS, which introduces a small (~1e-8) MSE.
