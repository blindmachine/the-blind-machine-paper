#!/usr/bin/env python3
"""local_data_owner.py — LOCAL stages each DATA OWNER (contributor) runs.

A data owner turns their own raw genotype data into one uploadable blob, on their
own machine, using the project's PUBLIC context only. Nothing but that blob (and
the already-public context) ever leaves the machine; the secret key is never
touched here.

  * encode()  — raw dosage vector -> validated, zero-padded, length-L vector.
  * encrypt() — encoded vector -> ONE framed blob of K chunk-ciphertexts, where
    K = ceil(L / CHUNK_SLOTS). A BFV ciphertext at poly=8192 packs at most
    N/2 = 4096 dosages with a clean rotate-sum, so a large model (e.g. the 110k-SNP
    schizophrenia model) is split across K ciphertexts. The blob is framed as
    ``[8-byte length L][chunk_0][chunk_1]...`` so the server can recover L and slice
    the PUBLIC weights to match.

The project owner's stages (keygen, decrypt, decode) live in
local_project_owner.py; the blind server stage (compute) lives in server.py.

The client only ever ships a raw dosage vector `g in {0,1,2}^L` — identical in
shape to the flagship. The PUBLIC effect weights are NOT applied here; they are a
published model applied SERVER-side as a plaintext-scalar multiply. Because the
weights are public, the score `Sum_j w_j g_ij` is computed by the (untrusted)
evaluator on ciphertext, so a coordinating researcher who holds the key learns
each participant's *score* but never their genotype, and the compute server
learns neither.
"""
from __future__ import annotations

from _packing import frame

VALUE_DOMAIN = (0, 1, 2)
MISSING_ENCODED_AS = 0

# MUST match server.CHUNK_SLOTS: the number of dosages per BFV ciphertext (N/2 at
# poly_modulus_degree = 8192) that still admits a clean intra-vector rotate-sum.
CHUNK_SLOTS = 4096


def encode(raw: list[int | None], length: int) -> list[int]:
    """Return a validated, zero-padded, length-``length`` dosage vector.

    Missing calls (``None``) encode as 0; every present call is validated in
    {0,1,2}; the vector is zero-padded to length L (rejected if longer).

    Raises ValueError on an out-of-domain call or an over-length input.
    """
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    if len(raw) > length:
        raise ValueError(
            f"raw vector length {len(raw)} exceeds coordinate length {length}"
        )

    encoded: list[int] = []
    for index, call in enumerate(raw):
        if call is None:
            encoded.append(MISSING_ENCODED_AS)
            continue
        if call not in VALUE_DOMAIN:
            raise ValueError(f"coordinate {index}: dosage {call!r} not in {VALUE_DOMAIN}")
        encoded.append(int(call))

    # Zero-pad any trailing coordinates the raw vector did not cover.
    encoded.extend([MISSING_ENCODED_AS] * (length - len(encoded)))
    return encoded


def _chunks(vector: list[int], size: int):
    for start in range(0, len(vector), size):
        yield vector[start : start + size]


def encrypt(public_context_bytes: bytes, encoded: list[int]) -> bytes:
    """BFV-encrypt ``encoded`` as K chunk-ciphertexts -> ONE framed upload blob.

    Uses the PUBLIC context only. Each chunk of up to CHUNK_SLOTS dosages becomes
    one BFV ciphertext; the blob is ``[len L][chunk_0]...[chunk_{K-1}]`` so the
    server knows L (to slice the PUBLIC weights) without a secret key. The secret
    key is not touched here.
    """
    import tenseal as ts

    if not encoded:
        raise ValueError("encrypt received an empty encoded vector")

    context = ts.context_from(public_context_bytes)
    length = len(encoded)
    parts: list[bytes] = [length.to_bytes(8, "big")]
    for chunk in _chunks(encoded, CHUNK_SLOTS):
        # Zero-pad the last partial chunk to CHUNK_SLOTS so the server can add the
        # weighted chunk-vectors element-wise before a SINGLE rotate-sum. A BFV
        # ciphertext is full-poly regardless of fill, so this costs no extra bytes.
        if len(chunk) < CHUNK_SLOTS:
            chunk = chunk + [0] * (CHUNK_SLOTS - len(chunk))
        parts.append(ts.bfv_vector(context, chunk).serialize())
    return frame(parts)
