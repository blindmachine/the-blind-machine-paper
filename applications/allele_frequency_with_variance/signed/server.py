#!/usr/bin/env python3
"""server.py — the BLIND computation for `allele_frequency_with_variance`.

This is the ONLY code that runs server-side. The kit shim
`30_compute_encrypted.py` is its sole caller: it maps the argparse CLI
(`--context/--inputs/--out`) onto the reserved ``compute`` function below. The
author writes only this pure, bytes-in/bytes-out function; all the argv/file
plumbing lives in the (kit-owned) shim.

Trust boundary, made structural by the signature:

    compute(inputs: list[bytes], public_context: bytes) -> bytes

There is NO secret-context parameter — this function is incapable of receiving a
secret key. It runs in the network-isolated sandbox (`--network none`, read-only
fs, non-root, resource-limited) with the PUBLIC context (relin keys, NO secret
key) and ciphertexts only, so the server never sees a single plaintext genotype.

Fold every contributor ciphertext into TWO aggregate ciphertexts — the first and
second moments:

    sum_g[j]   = sum_i  g_ij           (additive path; reuses .add)
    sum_g2[j]  = sum_i  g_ij^2         (element-wise SQUARE per contributor,
                                        depth 1, THEN sum)

Squaring each contributor BEFORE summing is mandatory: ``(sum g)^2 != sum g^2``.
This is the ONE ct x ct multiplicative level that separates this protocol from
the additive flagship — the server SQUARES an encrypted value, which is why the
public context must carry relinearization keys (keygen). There is NO rotation, so
NO Galois keys are needed; the square is element-wise per slot.

Written ONCE against an abstract evaluator ``E`` (the cleartext oracle in
docs/simulation_mode.md swaps a plaintext evaluator into the same ``aggregate`` so
it cannot drift from this encrypted path):

    aggregate(inputs, E):          # E provides zero / add / mul
        acc_sum = <first>
        acc_sq  = E.mul(<first>, <first>)
        for ct in rest(inputs):    # square-then-sum, depth 1
            acc_sum = E.add(acc_sum, ct)
            acc_sq  = E.add(acc_sq, E.mul(ct, ct))
        return acc_sum, acc_sq

Additive sentinel rides along both paths: sum path slot L sums to N; square path
slot L sums to ``sum_i 1^2 = N``.

Output convention: a SINGLE ``--out`` FILE artifact. Because this protocol emits
TWO result ciphertexts (sum_g, sum_g2) and the hosted worker content-addresses
exactly one opaque ``result.bin`` FILE, both moments are packed into that one
artifact as a deterministic, self-describing binary container (magic ``BMCT1\n``,
see ``pack_results`` / ``unpack_results``). This is the shared Blind Machine
multi-ciphertext container format (byte-identical to the one
genotype_phenotype_covariance uses).

Determinism / verify-by-re-execution: BFV add and multiply are deterministic, so
the same ordered set of input ciphertexts always yields the same result
ciphertext bytes (encryption is randomized, the *compute* is not). Re-running
this stage on the same inputs reproduces bit-identical result digests.
"""
from __future__ import annotations

import struct
from typing import Iterable, Protocol

# Canonical moment order — shared, fixed protocol definition. Decrypt unpacks
# against the same names, so the container is deterministic and self-describing.
# Names match the plain.json keys decode already consumes ({"sum","sumsq"}).
MOMENT_ORDER = ("sum", "sumsq")

# Container framing for the moment ciphertexts inside one --out artifact. This is
# the shared Blind Machine multi-CipherText container v1 (also used verbatim by
# genotype_phenotype_covariance); a fixed MOMENT_ORDER + length-prefixed framing
# makes the packed bytes deterministic.
_CONTAINER_MAGIC = b"BMCT1\n"  # Blind Machine multi-CipherText container v1


class Evaluator(Protocol):
    """The abstract op interface both engines implement (see simulation_mode).

    Extends the flagship's zero/add with ``mul`` (the ct x ct square). A
    ``PlaintextEvaluator`` mirror must implement the identical ops so the cleartext
    oracle cannot drift from this encrypted path.
    """

    def zero(self, length: int): ...
    def add(self, a, b): ...
    def mul(self, a, b): ...


class BFVEvaluator:
    """The real (encrypted) evaluator: ops on TenSEAL BFV ciphertexts."""

    def __init__(self, context) -> None:
        self.context = context

    def zero(self, length: int):
        import tenseal as ts

        return ts.bfv_vector(self.context, [0] * length)

    def add(self, a, b):
        return a + b

    def mul(self, a, b):
        # ct x ct element-wise product (depth 1). TenSEAL relinearizes the degree-2
        # product back down using the relin keys retained in the PUBLIC context
        # (keygen). No rotation, so no Galois keys are touched.
        return a * b

    def load(self, blob: bytes):
        import tenseal as ts

        return ts.bfv_vector_from(self.context, blob)


def aggregate(inputs: Iterable, evaluator: Evaluator, length: int | None = None):
    """Fold ``inputs`` into ``(acc_sum, acc_sumsq)`` under the evaluator.

    ``acc_sum``   = sum_i x_i                (additive)
    ``acc_sumsq`` = sum_i (x_i * x_i)        (square each input, THEN sum; depth 1)

    Folds from the first input (no length needed). If ``inputs`` is empty a pair
    of zero vectors of ``length`` is returned (requires ``length``).
    """
    iterator = iter(inputs)
    try:
        first = next(iterator)
    except StopIteration:
        if length is None:
            raise ValueError("aggregate() needs a length when there are no inputs")
        return evaluator.zero(length), evaluator.zero(length)

    acc_sum = first
    acc_sumsq = evaluator.mul(first, first)
    for item in iterator:
        acc_sum = evaluator.add(acc_sum, item)
        acc_sumsq = evaluator.add(acc_sumsq, evaluator.mul(item, item))
    return acc_sum, acc_sumsq


def pack_results(named_blobs: dict[str, bytes]) -> bytes:
    """Pack the moment ciphertexts into one deterministic container.

    Layout: MAGIC, then for each moment in ``MOMENT_ORDER`` a length-prefixed
    name and a length-prefixed blob. Fixed order => byte-deterministic.
    """
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(MOMENT_ORDER))
    for name in MOMENT_ORDER:
        blob = named_blobs[name]
        name_bytes = name.encode("utf-8")
        out += struct.pack(">B", len(name_bytes)) + name_bytes
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def unpack_results(blob: bytes) -> dict[str, bytes]:
    """Inverse of ``pack_results``: recover ``{name: ciphertext_bytes}``."""
    if blob[: len(_CONTAINER_MAGIC)] != _CONTAINER_MAGIC:
        raise ValueError("result artifact is not a Blind Machine multi-ciphertext "
                         "container (bad magic)")
    offset = len(_CONTAINER_MAGIC)
    (count,) = struct.unpack_from(">B", blob, offset)
    offset += 1
    named: dict[str, bytes] = {}
    for _ in range(count):
        (name_len,) = struct.unpack_from(">B", blob, offset)
        offset += 1
        name = blob[offset : offset + name_len].decode("utf-8")
        offset += name_len
        (blob_len,) = struct.unpack_from(">Q", blob, offset)
        offset += 8
        named[name] = bytes(blob[offset : offset + blob_len])
        offset += blob_len
    return named


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    """RESERVED blind entrypoint — fold into the two moments, pack the aggregate.

    Deserialize the PUBLIC context and each ciphertext, fold them into the
    ``(sum_g, sum_g2)`` moment pair, and return the deterministic ``BMCT1``
    container holding ``{"sum": <sum_g>, "sumsq": <sum_g2>}`` (raw serialized
    ciphertexts). No secret key is present; defensively refuse a context that
    carries one.
    """
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        # The server must never receive a secret key.
        raise ValueError("compute stage received a context holding a secret key")
    evaluator = BFVEvaluator(context)
    vectors = [evaluator.load(blob) for blob in inputs]
    acc_sum, acc_sumsq = aggregate(vectors, evaluator)
    named = {"sum": acc_sum.serialize(), "sumsq": acc_sumsq.serialize()}
    return pack_results(named)
