#!/usr/bin/env python3
"""server.py — the BLIND computation for `gwas_chi_square`.

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
the server never sees a single plaintext genotype or phenotype.

**Additive-only.** Unlike `genotype_phenotype_covariance` (which forms the cross
term g·y with a server-side ciphertext×ciphertext multiply), this bundle receives
the product g·y ALREADY FORMED by each data owner (who holds both g and y in the
clear). The entire server-side computation is therefore a coordinate-wise sum —
the same circuit as the flagship `allele_frequency_count`, the least powerful HE
operation there is. No relinearization keys, no Galois keys, no ct×ct multiply.

Per contributor, the data owner uploads ONE BMCT1 container carrying, for a
length-L SNP set chunked at ``SLOT_COUNT`` slots:

    g0..g{C-1}    -> Σ_i g_ij          (minor-allele count per SNP, "c1")
    gy0..gy{C-1}  -> Σ_i g_ij·y_i      (minor-allele count in cases per SNP, "n11")
    meta = [y,1]  -> [Σ_i y_i, N]      (#cases, contributor count)

The server folds each NAMED ciphertext across every contributor and returns the
same-named aggregate container. The chi-square statistic, odds ratio and p-value
per SNP are derived from these sufficient statistics on the project owner's
machine, in the clear (local_project_owner.decode) — nothing non-linear happens
under encryption.

The fold is written ONCE against an abstract evaluator ``E`` (the cleartext oracle
in docs/simulation_mode.md swaps a plaintext evaluator exposing the same ``add``
into the same shape, so it cannot drift from this encrypted path):

    aggregate(contributions, E):       # E provides add
        acc[name] = <first contribution's name>
        for c in rest:                 # coordinate-wise add, per name
            acc[name] = E.add(acc[name], c[name])
        return acc

Determinism / verify-by-re-execution: BFV addition is deterministic, so the same
ordered set of input ciphertexts always yields the same result ciphertext bytes
(encryption is randomized, the *compute* is not). Re-running this stage on the
same inputs reproduces a bit-identical result digest.
"""
from __future__ import annotations

import struct
from typing import Protocol

# Container framing — the shared Blind Machine multi-CipherText container v1,
# byte-identical to local_data_owner.pack_container and the covariance bundle.
# Each bundle carries its own verbatim copy (bundles are self-contained).
_CONTAINER_MAGIC = b"BMCT1\n"  # Blind Machine multi-CipherText container v1


class Evaluator(Protocol):
    """The abstract op interface both engines implement (see simulation_mode).

    Additive-only, so the interface is just ``add`` (no ``mul`` — the cross term
    g·y was already formed by the data owner in the clear)."""

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
    """Pack aggregate ciphertexts into one deterministic BMCT1 container.

    Layout: MAGIC, a uint8 count, then for each name in ``order`` a length-prefixed
    name and a length-prefixed blob. Fixed order => byte-deterministic.
    """
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(order))
    for name in order:
        blob = named_blobs[name]
        name_bytes = name.encode("utf-8")
        out += struct.pack(">B", len(name_bytes)) + name_bytes
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def unpack_container(blob: bytes) -> "dict[str, bytes]":
    """Recover ``{name: ciphertext_bytes}`` from one BMCT1 container blob.

    Preserves insertion order (Python dicts are ordered) so the aggregate is
    re-packed in the same canonical name order the contributors used.
    """
    if blob[: len(_CONTAINER_MAGIC)] != _CONTAINER_MAGIC:
        raise ValueError(
            "contribution is not a Blind Machine multi-ciphertext container (bad magic)"
        )
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
    """Coordinate-wise additive fold of each named ciphertext across contributors.

    ``contributions`` is any iterable of ``{name: loaded_ciphertext}`` dicts, all
    sharing the same name set (the canonical container shape). Folded in ONE pass —
    only the running accumulator (one set of named ciphertexts) and the current
    contribution are ever live, so peak memory is O(1) in the number of
    contributors N, not O(N). Returns ``{name: aggregate_ciphertext}``. Uses only
    ``evaluator.add`` so the cleartext oracle can run the identical function over a
    plaintext evaluator.
    """
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
                f"expected {names}; every contributor must encode the identical "
                f"SNP set (same length)"
            )
        for name in names:
            acc[name] = evaluator.add(acc[name], contribution[name])
    if acc is None:
        raise ValueError("expected at least one contributor blob")
    return acc


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    """RESERVED blind entrypoint — additively fold the per-SNP sufficient stats.

    Unpack each contributor's BMCT1 container, load its ciphertexts under the
    PUBLIC context, and sum every named ciphertext across contributors in a single
    STREAMING pass (load-add-discard), so peak memory does not grow with the cohort
    size. Returns the same-named aggregate container. ORDER-INDEPENDENT: additive
    folds do not depend on contributor order (correct under the hosted worker's
    digest-sorting Stager). No secret key is present; defensively refuse a context
    that carries one.
    """
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        # The server must never receive a secret key.
        raise ValueError("compute stage received a context holding a secret key")
    if len(inputs) == 0:
        raise ValueError("expected at least one contributor blob")

    evaluator = BFVEvaluator(context)

    def loaded_contributions():
        for blob in inputs:
            named = unpack_container(blob)
            yield {name: evaluator.load(named[name]) for name in named}

    result = aggregate(loaded_contributions(), evaluator)
    order = list(result.keys())
    return pack_results({name: result[name].serialize() for name in order}, order)
