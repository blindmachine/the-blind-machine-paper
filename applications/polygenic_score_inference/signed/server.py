#!/usr/bin/env python3
"""server.py — the BLIND computation for `polygenic_score_inference`.

This is the ONLY code that runs server-side. The kit shim
`30_compute_encrypted.py` is its sole caller: it maps the argparse CLI
(`--context/--inputs/--out`) onto the reserved ``compute`` function below. The
author writes only this pure, bytes-in/bytes-out function; all the argv/file
plumbing lives in the (kit-owned) shim.

Trust boundary, made structural by the signature:

    compute(inputs: list[bytes], public_context: bytes) -> bytes

There is NO secret-context parameter — this function is incapable of receiving a
secret key. It runs in the network-isolated sandbox (`--network none`, read-only
fs, non-root, resource-limited) with the PUBLIC context and ciphertexts only, so
the server never sees a single plaintext genotype.

What it computes: per-individual polygenic risk scores under a PUBLIC model
--------------------------------------------------------------------------
Each contributor `i` uploads their alt-allele **dosage vector** ``g_i in {0,1,2}^L``
encrypted (see local_data_owner). The application also fixes a PUBLIC effect-weight
vector ``w in R^L`` (a published PGS-Catalog / GWAS model), integer-scaled by a
fixed-point factor `S` and folded into the bundle digest. This stage returns each
individual's encrypted polygenic risk score

    PRS_i = Sum_j  w_j * g_ij            (one encrypted scalar per contributor)

Why this is the LEAST-POWERFUL scheme that does the job (vs HEPRS / Knight et al.)
--------------------------------------------------------------------------------
Knight et al. (Cell Reports Methods 2026; github.com/gersteinlab/HEPRS) encrypt
BOTH the genotypes AND the model, so their per-SNP product is a **ciphertext x
ciphertext** multiply (`MulRelinNew`), needing relinearization keys and the whole
multiplicative tier. Here the model is PUBLIC, so each product is a **ciphertext x
plaintext** multiply — it does NOT raise ciphertext degree, so:

  * NO relinearization keys are generated or shipped, and
  * NO ciphertext x ciphertext multiply ever happens (depth stays 0 for the
    product; the reduction below is pure additions of rotations).

The only homomorphism beyond add is the intra-vector reduction ``Sum_j`` (a
rotate-and-sum, TenSEAL `.sum()`), which needs Galois keys but no relin. So the
scheme is "additive tier + one rotate-sum" — strictly lighter than HEPRS's
`ct x ct` path, and BFV makes each score **bit-exact** (not CKKS-approximate).

Compute design (per contributor, then pack) — ONE rotate-sum per contributor
----------------------------------------------------------------------------
    for each contributor blob:                # inputs[i]
        chunks = the K ciphertexts of g_i      # K = ceil(L / CHUNK_SLOTS)
        acc_vec = Sum_k  ct_k * w_scaled[chunk k]      # K ct x plaintext + adds; NO reduce yet
        emit acc_vec.sum()                     # ONE rotate-and-sum => scalar PRS_i (scaled)
    return frame([PRS_0, PRS_1, ...])          # N scalars, one per contributor

The chunks cover disjoint SNP blocks, so adding the K weighted chunk-vectors
element-wise lands, in slot j, the sum of the j-th SNP of every block; the single
rotate-sum over those slots is then the whole-model dot product. That folds the K
per-chunk rotate-sums (12 rotations each) into ONE — the dominant saving at the
110k-SNP scale (27 chunks => 1 reduce, not 27). BFV ciphertexts are full-poly
regardless of how many slots are filled, so zero-padding the last partial chunk
to CHUNK_SLOTS costs no extra bytes.

Genotypes never leave a contributor's machine in the clear, and the server never
holds a secret key, so it cannot read any `g_ij` or any `PRS_i` — it only shuffles
ciphertext. Memory is O(one contributor) because contributors are processed and
freed one at a time (the 65 GB HEPRS footprint came from holding the whole
encrypted cohort AND model in RAM; here nothing but public plaintext weights and
one contributor's ciphertext is resident).

Determinism: BFV add, plaintext-multiply, and rotate-sum are all deterministic, so
the same ordered inputs yield the same result ciphertext bytes (encryption is
randomized; the *compute* is not).
"""
from __future__ import annotations

import json
import pathlib
import random

from _packing import frame, unframe

# ---------------------------------------------------------------------------
# BFV batching: at poly_modulus_degree = 8192 a single ciphertext packs N/2 =
# 4096 usable slots for a clean rotate-and-sum (BFV's 2 x (N/2) batching layout —
# a full-N `.sum()` would cross rows and overflow the rotation step count). So a
# dosage vector of length L is split into ceil(L / CHUNK_SLOTS) ciphertexts, and
# the per-chunk scalar sums are added. MUST match local_data_owner.CHUNK_SLOTS.
# ---------------------------------------------------------------------------
CHUNK_SLOTS = 4096

# Published fixed-point factor S and the plaintext modulus t of the declared
# params (see local_project_owner). Signed integer weights are represented in
# Z_t; the value envelope guard below keeps |PRS_scaled| < t/2 so the project
# owner can recover the sign on decrypt.
WEIGHT_SCALE = 1000
PLAIN_MODULUS = 1073692673  # 30-bit batching prime; MUST match local_project_owner

# Deterministic synthetic PUBLIC model, used ONLY when no `model_weights.json`
# ships beside this file (the self-contained demo). A real deployment ships the
# published model weights as `model_weights.json` (integer-scaled, part of the
# digest); see README "Public model".
WEIGHT_SEED = "blind-v1-prs-inference-weights"
MAX_SCALED_WEIGHT = 2000  # |w_scaled| in [1, 2000] => real effect size in [-2.0, 2.0]

_MODEL_WEIGHTS_FILE = "model_weights.json"


def scaled_weights(length: int) -> list[int]:
    """Return the PUBLIC integer-scaled effect weights ``w_scaled in Z^length``.

    If a signed sibling ``model_weights.json`` is present (a real published
    model), load and length-check it. Otherwise regenerate the synthetic demo
    weights deterministically from ``WEIGHT_SEED`` (stable `random.Random`), so a
    reviewer reproduces the exact vector and any change to seed/scale/generator
    changes the bundle digest.
    """
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")

    path = pathlib.Path(__file__).with_name(_MODEL_WEIGHTS_FILE)
    if path.exists():
        payload = json.loads(path.read_text())
        weights = [int(w) for w in payload["scaled_weights"]]
        if len(weights) != length:
            raise ValueError(
                f"model_weights.json has {len(weights)} weights, expected {length}"
            )
        return weights

    rng = random.Random(WEIGHT_SEED)
    # Signed weights (real GWAS betas are signed): sign * magnitude, never 0.
    return [
        rng.choice((-1, 1)) * rng.randint(1, MAX_SCALED_WEIGHT) for _ in range(length)
    ]


def _check_value_envelope(weights: list[int]) -> None:
    """Fail closed if the model could overflow signed BFV recovery.

    The worst-case magnitude of a score is ``|PRS_scaled| <= 2 * sum_j |w_j|``
    (every dosage = 2, all same sign). Signed recovery on decrypt needs
    ``|PRS_scaled| < t/2``. Raising here (rather than silently wrapping mod t) is
    the fail-closed contract: a model outside the envelope must widen `t`.
    """
    worst = 2 * sum(abs(w) for w in weights)
    if worst >= PLAIN_MODULUS // 2:
        raise ValueError(
            f"model exceeds the exact BFV value envelope: worst-case |PRS_scaled| "
            f"~{worst} >= t/2 ({PLAIN_MODULUS // 2}). Widen the plaintext modulus."
        )


def _padded_weight_slice(weights: list[int], k: int) -> list[int]:
    """The k-th CHUNK_SLOTS-wide weight block, zero-padded so it lines up with the
    zero-padded last chunk (padding weights are 0 ⇒ contribute nothing)."""
    weight_slice = weights[k * CHUNK_SLOTS : (k + 1) * CHUNK_SLOTS]
    if len(weight_slice) < CHUNK_SLOTS:
        weight_slice = weight_slice + [0] * (CHUNK_SLOTS - len(weight_slice))
    return weight_slice


def score_individual(chunk_ciphertexts: list, weights: list[int], evaluator) -> object:
    """Encrypted PRS of one contributor: ``Sum_j w_j * g_ij`` as one scalar ciphertext.

    Accumulates the K weighted chunk-vectors element-wise (ciphertext x plaintext
    + add), then does a SINGLE rotate-and-sum. ``evaluator`` provides
    `mul_plain`, `add`, and `reduce_sum` — a small interface the cleartext oracle
    (tests / simulation mode) can implement to score with the identical logic.
    """
    accumulator = None
    for k, ciphertext in enumerate(chunk_ciphertexts):
        weighted = evaluator.mul_plain(ciphertext, _padded_weight_slice(weights, k))
        accumulator = weighted if accumulator is None else evaluator.add(accumulator, weighted)
    if accumulator is None:
        raise ValueError("contributor blob carried no ciphertext chunks")
    return evaluator.reduce_sum(accumulator)


class BFVEvaluator:
    """The real (encrypted) evaluator: ops on TenSEAL BFV ciphertexts."""

    def __init__(self, context) -> None:
        self.context = context

    def load(self, blob: bytes):
        import tenseal as ts

        return ts.bfv_vector_from(self.context, blob)

    def mul_plain(self, ciphertext, weight_slice: list[int]):
        # ciphertext x PLAINTEXT (element-wise; no relin, no ct x ct).
        return ciphertext * weight_slice

    def add(self, a, b):
        return a + b

    def reduce_sum(self, ciphertext):
        # encrypted rotate-and-sum across the slots (Galois keys). ONE per contributor.
        return ciphertext.sum()


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    """RESERVED blind entrypoint — score each contributor under the PUBLIC model.

    Deserialize the PUBLIC context (defensively refuse one carrying a secret key),
    then, for each contributor blob, recover the declared coordinate length L,
    load the K chunk-ciphertexts, and reduce them to that contributor's single
    encrypted PRS scalar. Return the N scalars framed one per contributor.
    """
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        # The server must never receive a secret key.
        raise ValueError("compute stage received a context holding a secret key")
    if not inputs:
        raise ValueError("compute stage received no contributor ciphertexts")

    evaluator = BFVEvaluator(context)

    length = None
    scores: list[bytes] = []
    for blob in inputs:
        parts = unframe(blob)
        if len(parts) < 2:
            raise ValueError("contributor blob missing its length header or chunks")
        declared = int.from_bytes(parts[0], "big")
        if length is None:
            length = declared
            weights = scaled_weights(length)
            _check_value_envelope(weights)
        elif declared != length:
            raise ValueError(
                f"contributors disagree on coordinate length ({declared} != {length})"
            )

        chunk_ciphertexts = [evaluator.load(chunk) for chunk in parts[1:]]
        prs = score_individual(chunk_ciphertexts, weights, evaluator)
        scores.append(prs.serialize())

    return frame(scores)
