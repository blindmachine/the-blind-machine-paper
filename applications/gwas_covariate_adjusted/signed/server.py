#!/usr/bin/env python3
"""server.py — the BLIND computation for `gwas_covariate_adjusted`.

This is the ONLY code that runs server-side (the kit shim `30_compute_encrypted.py`
is its sole caller). It has NO secret-context parameter and runs in the
network-isolated sandbox with the PUBLIC context and ciphertexts only.

**Additive-only.** Each data owner has already formed — locally, in the clear —
every product a covariate-adjusted (semi-parallel) GWAS needs: the covariate Gram
upper triangle x·xᵀ, x·y, y², and per SNP the cross terms x_c·g, g·y, g². What
reaches the server is only sums-to-be-taken, so its whole circuit is a
coordinate-wise ADDITION over the contributor fold — no ciphertext×ciphertext
multiply, no relinearization keys, no Galois keys. The per-SNP score test (the k×k
covariate inverse and the p-values) is computed by the project owner after
decryption (local_project_owner.decode).

Per contributor, the data owner uploads ONE BMCT1 container carrying, for a
length-L SNP set chunked at ``SLOT_COUNT`` slots and k covariates:

    scalars       -> the k(k+1)/2 upper-triangle of Σ_i x_i·x_iᵀ, Σ_i x_i·y_i,
                     Σ_i y_i², and N (append-1 sentinel)
    xg{c}_{ch}    -> Σ_i x_ic·g_ij   (per covariate c: the covariate/genotype cross term)
    gy_{ch}       -> Σ_i g_ij·y_i
    gg_{ch}       -> Σ_i g_ij²

The server folds each NAMED ciphertext across every contributor and returns the
same-named aggregate container.

The fold is written ONCE against an abstract evaluator ``E`` (the cleartext oracle
swaps a plaintext evaluator into the same shape), streamed so peak memory is O(1)
in the cohort size. BFV addition is deterministic ⇒ verify-by-re-execution holds.
"""
from __future__ import annotations

import struct
from typing import Protocol

_CONTAINER_MAGIC = b"BMCT1\n"  # shared Blind Machine multi-CipherText container v1


class Evaluator(Protocol):
    def add(self, a, b): ...


class BFVEvaluator:
    """The real (encrypted) evaluator: additive ops on TenSEAL BFV ciphertexts."""

    def __init__(self, context) -> None:
        self.context = context

    def add(self, a, b):
        return a + b

    def load(self, blob: bytes):
        import tenseal as ts

        return ts.bfv_vector_from(self.context, blob)


def pack_results(named_blobs: "dict[str, bytes]", order: list[str]) -> bytes:
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(order))
    for name in order:
        blob = named_blobs[name]
        nb = name.encode("utf-8")
        out += struct.pack(">B", len(nb)) + nb
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def unpack_container(blob: bytes) -> "dict[str, bytes]":
    if blob[: len(_CONTAINER_MAGIC)] != _CONTAINER_MAGIC:
        raise ValueError("contribution is not a Blind Machine multi-ciphertext container (bad magic)")
    offset = len(_CONTAINER_MAGIC)
    named: dict[str, bytes] = {}
    try:
        (count,) = struct.unpack_from(">B", blob, offset)
        offset += 1
        for _ in range(count):
            (name_len,) = struct.unpack_from(">B", blob, offset)
            offset += 1
            name = blob[offset : offset + name_len].decode("utf-8")
            offset += name_len
            (blob_len,) = struct.unpack_from(">Q", blob, offset)
            offset += 8
            if offset + blob_len > len(blob):
                raise ValueError("truncated BMCT1 container (declared blob length exceeds buffer)")
            named[name] = bytes(blob[offset : offset + blob_len])
            offset += blob_len
    except struct.error as exc:
        raise ValueError("truncated or malformed BMCT1 container") from exc
    return named


def aggregate(contributions, evaluator: Evaluator) -> dict:
    """Streaming coordinate-wise additive fold of each named ciphertext (O(1) memory
    in the number of contributors)."""
    acc: dict | None = None
    names: list[str] | None = None
    for i, contribution in enumerate(contributions):
        if names is None:
            names = list(contribution.keys())
            acc = dict(contribution)
            continue
        if list(contribution.keys()) != names:
            raise ValueError(
                f"contributor {i} has container names {list(contribution.keys())}, "
                f"expected {names}; every contributor must encode the identical SNP "
                f"set and covariate count"
            )
        for name in names:
            acc[name] = evaluator.add(acc[name], contribution[name])
    if acc is None:
        raise ValueError("expected at least one contributor blob")
    return acc


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    """RESERVED blind entrypoint — additively fold the covariate-adjusted GWAS
    sufficient statistics in a single STREAMING pass. Order-independent. No secret
    key is present; defensively refuse a context that carries one.
    """
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        raise ValueError("compute stage received a context holding a secret key")
    if len(inputs) == 0:
        raise ValueError("expected at least one contributor blob")

    evaluator = BFVEvaluator(context)

    def loaded():
        for blob in inputs:
            named = unpack_container(blob)
            yield {name: evaluator.load(named[name]) for name in named}

    result = aggregate(loaded(), evaluator)
    order = list(result.keys())
    return pack_results({name: result[name].serialize() for name in order}, order)
