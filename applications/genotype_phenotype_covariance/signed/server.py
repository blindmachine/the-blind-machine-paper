#!/usr/bin/env python3
"""server.py — the BLIND computation for `genotype_phenotype_covariance`.

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
key) and ciphertexts only — the server never sees a plaintext genotype or
phenotype.

This is the v1 encrypted×encrypted anchor: the server forms a genuine ciphertext×
ciphertext product (depth 1, relinearized), which is exactly the operation the
additive tier cannot do. Four accumulators over the contributor fold:

    sum_g  = Σ_i cipher_g_i                    (additive; slot L = N)
    sum_gy = Σ_i (cipher_g_i * cipher_y_i)     (ct×ct, relin; slot j = Σ_i g_ij·y_i)
    sum_y  = Σ_i cipher_y_i                    (additive; broadcast, every slot = Σ_i y_i)
    sum_y2 = Σ_i (cipher_y_i * cipher_y_i)     (ct×ct, relin; broadcast, any slot = Σ_i y_i²)

Written ONCE against an abstract evaluator ``E`` (the cleartext oracle in
docs/simulation_mode.md swaps a ``PlaintextEvaluator`` exposing the same
``add`` / ``mul`` into the same ``aggregate`` so the cleartext oracle cannot drift
from this encrypted path):

    aggregate(pairs, E):           # E provides add / mul
        for g, y in pairs:
            sum_g  += g ;  sum_y  += y
            sum_gy += E.mul(g, y) ;  sum_y2 += E.mul(y, y)
        return {sum_g, sum_gy, sum_y, sum_y2}

Input convention: each ``--input`` is ONE packed ``(g, y)`` contributor blob (a
BMCT1 container written by the data owner's encrypt). The compute stage unpacks
each blob back to its ``(cipher_g, cipher_y)`` pair, so pairing is preserved
regardless of the order the inputs arrive in — correct under the hosted worker's
Stager, which digest-sorts inputs before staging (with one blob per contributor
the sort only permutes contributors, and the moment folds are order-independent).

Output convention: a single ``--out`` artifact holding all four moment
ciphertexts in a deterministic, self-describing BMCT1 container (see
``pack_results`` / ``unpack_results``). The moments cannot be packed into one
ciphertext without cross-slot masking (rotation / Galois), which this protocol
deliberately avoids — so one artifact carries four labelled ciphertexts instead.

Determinism / verify-by-re-execution: BFV add and (relinearized) multiply are
deterministic, so the same ordered inputs always yield the same result bytes
(encryption is randomized; the *compute* is not). Re-running reproduces a
bit-identical result digest.
"""
from __future__ import annotations

import struct
from typing import Iterable, Protocol

# Canonical moment order — shared, fixed protocol definition. Decrypt unpacks
# against the same names, so the container is deterministic and self-describing.
MOMENT_ORDER = ("sum_g", "sum_gy", "sum_y", "sum_y2")

# Container framing for the four moment ciphertexts inside one --out artifact.
# This is the shared Blind Machine multi-CipherText container v1 — byte-identical
# to the format allele_frequency_with_variance uses. Each bundle carries its own
# verbatim copy of the pack/unpack helper (bundles are self-contained).
_CONTAINER_MAGIC = b"BMCT1\n"  # Blind Machine multi-CipherText container v1


class Evaluator(Protocol):
    """The abstract op interface both engines implement (see simulation_mode).

    Covariance needs a real product, so this interface adds ``mul`` (ct×ct) on top
    of the flagship's ``zero`` / ``add``.
    """

    def zero(self, length: int): ...
    def add(self, a, b): ...
    def mul(self, a, b): ...


class BFVEvaluator:
    """The real (encrypted) evaluator: ops on TenSEAL BFV ciphertexts.

    ``mul`` is a ciphertext×ciphertext product; TenSEAL relinearizes it using the
    relin keys carried in the public context (depth 1). No rotation is performed,
    so no Galois keys are needed.
    """

    def __init__(self, context) -> None:
        self.context = context

    def zero(self, length: int):
        import tenseal as ts

        return ts.bfv_vector(self.context, [0] * length)

    def add(self, a, b):
        return a + b

    def mul(self, a, b):
        return a * b

    def load(self, blob: bytes):
        import tenseal as ts

        return ts.bfv_vector_from(self.context, blob)


def aggregate(pairs: Iterable, evaluator: Evaluator) -> dict:
    """Fold paired ``(g_i, y_i)`` inputs into the four covariance moments.

    Returns ``{"sum_g", "sum_gy", "sum_y", "sum_y2"}``. Uses only
    ``evaluator.add`` and ``evaluator.mul`` so the cleartext oracle can run the
    identical function over a ``PlaintextEvaluator``.
    """
    sum_g = sum_gy = sum_y = sum_y2 = None
    saw_any = False
    for g, y in pairs:
        saw_any = True
        gy = evaluator.mul(g, y)
        yy = evaluator.mul(y, y)
        sum_g = g if sum_g is None else evaluator.add(sum_g, g)
        sum_y = y if sum_y is None else evaluator.add(sum_y, y)
        sum_gy = gy if sum_gy is None else evaluator.add(sum_gy, gy)
        sum_y2 = yy if sum_y2 is None else evaluator.add(sum_y2, yy)
    if not saw_any:
        raise ValueError("aggregate() needs at least one (genotype, phenotype) pair")
    return {"sum_g": sum_g, "sum_gy": sum_gy, "sum_y": sum_y, "sum_y2": sum_y2}


def pack_results(named_blobs: dict[str, bytes]) -> bytes:
    """Pack the four moment ciphertexts into one deterministic container.

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


def unpack_pair(blob: bytes) -> tuple[bytes, bytes]:
    """Recover ``(cipher_g_bytes, cipher_y_bytes)`` from one packed contributor blob.

    Reuses the generic BMCT1 reader (``unpack_results``). Input containers carry
    the names ``{g, y}`` (count 2); the OUTPUT container carries the four moment
    names (count 4), so a result.bin fed here as an input raises cleanly — there is
    no magic collision, only a name mismatch.
    """
    named = unpack_results(blob)
    if "g" not in named or "y" not in named:
        raise ValueError(
            "contributor blob is not a packed (g, y) container "
            f"(found names: {sorted(named)})"
        )
    return named["g"], named["y"]


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    """RESERVED blind entrypoint — unpack each (g, y) blob, fold, pack the moments.

    ORDER-INDEPENDENT: each input blob co-packs its own (g, y) pair, so the pairing
    survives any permutation of the input list (the hosted Stager digest-sorts).
    The moment folds are order-independent across contributors, so the packed
    result is identical regardless of input order. No secret key is present;
    defensively refuse a context that carries one.
    """
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        # The server must never receive a secret key.
        raise ValueError("compute stage received a context holding a secret key")
    if len(inputs) == 0:
        raise ValueError("expected at least one packed (g, y) contributor blob")

    evaluator = BFVEvaluator(context)
    pairs = []
    for blob in inputs:
        g_bytes, y_bytes = unpack_pair(blob)
        pairs.append((evaluator.load(g_bytes), evaluator.load(y_bytes)))
    results = aggregate(pairs, evaluator)
    named = {name: results[name].serialize() for name in MOMENT_ORDER}
    return pack_results(named)
