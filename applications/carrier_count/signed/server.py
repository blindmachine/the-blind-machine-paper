#!/usr/bin/env python3
"""server.py — the BLIND computation for `carrier_count`.

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
the server never sees a single plaintext carrier indicator.

`carrier_count` is a pure additive fold of carrier indicators — BYTE-FOR-BYTE the
flagship's abstract-evaluator ``add`` circuit (catalog §2: additive count of
indicators). The fold is written ONCE against an abstract evaluator ``E`` (the
cleartext oracle in docs/simulation_mode.md swaps a plaintext evaluator into the
same shape so it cannot drift from this encrypted path):

    aggregate(inputs, E):          # E provides zero / add
        acc = <first input>
        for ct in rest(inputs):    # carrier_count: pure coordinate-wise add
            acc = E.add(acc, ct)
        return acc

Additive-only: the append-1 sentinel rides along, so ``sum_i (c_i || 1)`` yields
the per-coordinate carrier-count vector in the first L slots and the exact
contributor count N in the trailing sentinel slot.

Determinism / verify-by-re-execution: BFV addition is deterministic, so the same
ordered set of input ciphertexts always yields the same result ciphertext bytes
(encryption is randomized, the *compute* is not). Re-running this stage on the
same inputs reproduces a bit-identical result digest.
"""
from __future__ import annotations

from typing import Iterable, Protocol


class Evaluator(Protocol):
    """The abstract op interface both engines implement (see simulation_mode)."""

    def zero(self, length: int): ...
    def add(self, a, b): ...


class BFVEvaluator:
    """The real (encrypted) evaluator: ops on TenSEAL BFV ciphertexts."""

    def __init__(self, context) -> None:
        self.context = context

    def zero(self, length: int):
        import tenseal as ts

        return ts.bfv_vector(self.context, [0] * length)

    def add(self, a, b):
        return a + b

    def load(self, blob: bytes):
        import tenseal as ts

        return ts.bfv_vector_from(self.context, blob)


def aggregate(inputs: Iterable, evaluator: Evaluator, length: int | None = None):
    """Fold ``inputs`` under ``evaluator.add`` into a single aggregate.

    Folds from the first input (no length needed). If ``inputs`` is empty a
    zero vector of ``length`` is returned (requires ``length``).
    """
    iterator = iter(inputs)
    try:
        accumulator = next(iterator)
    except StopIteration:
        if length is None:
            raise ValueError("aggregate() needs a length when there are no inputs")
        return evaluator.zero(length)
    for item in iterator:
        accumulator = evaluator.add(accumulator, item)
    return accumulator


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    """RESERVED blind entrypoint — homomorphically sum the contributor ciphertexts.

    Deserialize the PUBLIC context and each ciphertext, fold them into one
    aggregate ciphertext, and return the serialized result. No secret key is
    present; defensively refuse a context that carries one.
    """
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        # The server must never receive a secret key.
        raise ValueError("compute stage received a context holding a secret key")
    evaluator = BFVEvaluator(context)
    vectors = [evaluator.load(blob) for blob in inputs]
    return aggregate(vectors, evaluator).serialize()
