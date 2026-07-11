#!/usr/bin/env python3
"""server.py — the BLIND computation for `polygenic_score_aggregate`.

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

Homomorphically sum every contributor ciphertext, then apply the PUBLIC effect
weights as a **plaintext-scalar multiply** — producing the cohort's weighted
per-coordinate aggregate as one ciphertext.

Why this stays in the ADDITIVE tier (no relin, no Galois)
--------------------------------------------------------
The weights are PUBLIC (they live in `manifest.yml` and are regenerated here from
the published seed), so weighting is a ciphertext x **plaintext** multiply, not
ciphertext x ciphertext. A plaintext multiply does not raise ciphertext degree,
so no relinearization keys are needed; there is no cross-slot rotation, so no
Galois keys are needed. The cohort sum ``Sigma_j`` (a cross-coordinate reduction)
is done POST-decrypt (local_project_owner.decode), never under encryption.

Compute design (multiply once, at the end)
------------------------------------------
    acc     = Sigma_i  cipher_g_i                 # additive fold (flagship path)
    result  = acc * w_plain                       # single plaintext-scalar multiply
So ``result[j] = w_scaled[j] * Sigma_i g_ij``. Written ONCE against an abstract
evaluator ``E`` (the cleartext oracle in docs/simulation_mode.md swaps a plaintext
evaluator into the same ``aggregate`` so it cannot drift from this encrypted path):

    aggregate(inputs, E, weights):   # E provides zero / add / scalar_mul
        acc = <fold inputs under E.add>
        return E.scalar_mul(acc, weights)

Sentinel invariant (the one subtlety this protocol adds)
--------------------------------------------------------
The append-1 sentinel occupies slot L of every contribution, so ``acc``'s slot L
is exactly N. The weight applied to that slot is **1** (``w_plain[L] == 1``), so
the multiply leaves the sentinel untouched: ``result``'s slot L still decrypts to
exactly N. Only the L coordinate slots are scaled by the effect weights.

Public weights are DETERMINISTIC + content-addressed
----------------------------------------------------
``scaled_weights(length)`` regenerates the published integer-scaled weight vector
from the fixed seed ``blind-v1-pgs-weights`` and scale ``S = 1000`` — the same
values `manifest.yml` declares. Because server.py is covered by the bundle
SHA-256, changing the seed, scale, or generator changes the protocol identity.

Determinism / verify-by-re-execution: BFV add and plaintext-multiply are both
deterministic, so the same ordered inputs always yield the same result ciphertext
bytes (encryption is randomized, the *compute* is not).
"""
from __future__ import annotations

import random
from typing import Iterable, Protocol

# ---------------------------------------------------------------------------
# Published public effect weights (part of the protocol identity via the digest).
# Declared in manifest.yml as { scale: 1000, values: { kind: synthetic_weights,
# seed: blind-v1-pgs-weights } }; regenerated here so the server (and the oracle)
# apply the exact same integer-scaled vector every contributor was scored against.
# ---------------------------------------------------------------------------
WEIGHT_SEED = "blind-v1-pgs-weights"
WEIGHT_SCALE = 1000            # published fixed-point factor S; real error <= 1/S
MAX_SCALED_WEIGHT = 2000       # w_scaled in [1, 2000] => real effect weight in (0, 2.0]
SENTINEL_WEIGHT = 1            # slot L weight; keeps the sentinel == N after multiply


def scaled_weights(
    length: int, scale: int = WEIGHT_SCALE, seed: str = WEIGHT_SEED
) -> list[int]:
    """Return the published integer-scaled effect weights ``w_scaled in Z^length``.

    Deterministic from ``seed`` (``random.Random`` seeds a str via SHA-512, stable
    across CPython 3.x), so a reviewer regenerates the exact weight vector from the
    published ``(seed, scale, length)``. ``scale`` is carried for provenance; the
    integer weights are already scaled by it.
    """
    rng = random.Random(seed)
    return [rng.randint(1, MAX_SCALED_WEIGHT) for _ in range(length)]


def weight_plaintext(length: int) -> list[int]:
    """Length-``length + 1`` plaintext multiplier: effect weights + sentinel weight.

    The trailing ``SENTINEL_WEIGHT`` (== 1) multiplies the append-1 sentinel slot,
    so slot L stays exactly N after the plaintext-scalar multiply.
    """
    return scaled_weights(length) + [SENTINEL_WEIGHT]


class Evaluator(Protocol):
    """The abstract op interface both engines implement (see simulation_mode)."""

    def zero(self, length: int): ...
    def add(self, a, b): ...
    def scalar_mul(self, a, plain_vector): ...


class BFVEvaluator:
    """The real (encrypted) evaluator: ops on TenSEAL BFV ciphertexts."""

    def __init__(self, context) -> None:
        self.context = context

    def zero(self, length: int):
        import tenseal as ts

        return ts.bfv_vector(self.context, [0] * length)

    def add(self, a, b):
        return a + b

    def scalar_mul(self, a, plain_vector):
        # ciphertext x PLAINTEXT vector, element-wise. Does not raise ciphertext
        # degree -> no relinearization; no rotation -> no Galois keys.
        return a * plain_vector

    def load(self, blob: bytes):
        import tenseal as ts

        return ts.bfv_vector_from(self.context, blob)


def aggregate(
    inputs: Iterable,
    evaluator: Evaluator,
    weights: list[int],
    length: int | None = None,
):
    """Fold ``inputs`` under ``evaluator.add``, then apply the public ``weights``.

    Folds from the first input (no length needed). If ``inputs`` is empty a zero
    vector of ``length`` is used (requires ``length``). The final step is a single
    ``evaluator.scalar_mul`` by the public plaintext weight vector.
    """
    iterator = iter(inputs)
    try:
        accumulator = next(iterator)
    except StopIteration:
        if length is None:
            raise ValueError("aggregate() needs a length when there are no inputs")
        accumulator = evaluator.zero(length)
    else:
        for item in iterator:
            accumulator = evaluator.add(accumulator, item)
    return evaluator.scalar_mul(accumulator, weights)


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    """RESERVED blind entrypoint — sum, then public-plaintext-weight the cohort.

    Deserialize the PUBLIC context and each ciphertext, fold them, apply the
    published integer weight vector as a plaintext-scalar multiply, and return the
    serialized result. No secret key is present; defensively refuse a context that
    carries one.
    """
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        # The server must never receive a secret key.
        raise ValueError("compute stage received a context holding a secret key")
    if not inputs:
        raise ValueError("compute stage received no ciphertexts")

    evaluator = BFVEvaluator(context)
    vectors = [evaluator.load(blob) for blob in inputs]

    # The ciphertexts are L coordinates + 1 sentinel slot; recover L to build the
    # matching public weight vector (no extra CLI arg — weights come from the seed).
    length = vectors[0].size() - 1
    weights = weight_plaintext(length)

    result = aggregate(vectors, evaluator, weights, length=length + 1)
    return result.serialize()
