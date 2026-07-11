#!/usr/bin/env python3
"""local_data_owner.py — LOCAL stages each DATA OWNER (contributor) runs.

A data owner turns their own raw bucket membership into one ciphertext, on their
own machine, using the project's PUBLIC context only. Nothing but the ciphertext
(and the already-public context) ever leaves the machine; the secret key is never
touched here.

  * encode()  — a single raw bucket index ``b in [0, B)`` -> one-hot vector
    ``h in {0,1}^B`` (sum(h) = 1).
  * encrypt() — encoded vector (+ append-1 sentinel) -> serialized ciphertext.

The project owner's stages (keygen, decrypt, decode) live in
local_project_owner.py; the blind server stage (compute) lives in server.py.

`cohort_histogram` is deliberately non-genomic (it proves the additive primitive
is generic beyond genotypes). Each contributor falls into EXACTLY ONE bucket of
the fixed, published bucket definition (ordered categories / edges in
`manifest.yml`, folded into the bundle SHA-256), and holds a single bucket index
``b``. A non-integer, out-of-range, or missing index is REJECTED — unlike the
flagship there is no "missing -> 0" escape hatch, because a contributor with no
bucket cannot lawfully appear in a one-hot histogram.
"""
from __future__ import annotations

VALUE_DOMAIN = (0, 1)
SENTINEL_VALUE = 1


def encode(raw: int, length: int) -> list[int]:
    """Return a length-``length`` one-hot vector with a 1 at bucket ``raw``.

    ``length`` is the number of buckets ``B``. Raises ValueError on a non-integer
    index, an out-of-range index, or ``B <= 0`` — a contributor must land in
    exactly one published bucket.
    """
    if length <= 0:
        raise ValueError(f"length (bucket count B) must be positive, got {length}")
    # Reject bool explicitly: `True`/`False` are ints in Python and would silently
    # encode as bucket 1 / bucket 0.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError(
            f"raw bucket index must be an integer in [0, {length}), got {raw!r}"
        )
    if not 0 <= raw < length:
        raise ValueError(
            f"bucket index {raw} out of range [0, {length}) (B={length} buckets)"
        )

    one_hot = [0] * length
    one_hot[raw] = 1
    return one_hot


def append_sentinel(encoded: list[int], sentinel: int = SENTINEL_VALUE) -> list[int]:
    """Return ``encoded`` with the append-1 sentinel as the final slot.

    When the server homomorphically sums N contributions, that trailing slot sums
    to exactly N. Because every contribution is one-hot, the first B slots also
    sum to N — a free integrity cross-check (verified at decode). NOT a MAC.
    """
    return list(encoded) + [sentinel]


def encrypt(public_context_bytes: bytes, encoded: list[int]) -> bytes:
    """BFV-encrypt ``encoded`` (with sentinel appended) -> serialized ciphertext.

    Uses the PUBLIC context only. The extended plaintext vector (length B + 1) is
    encrypted; the ciphertext, alongside the public context, is the only thing
    ever uploaded. The secret key is not touched here.
    """
    import tenseal as ts

    context = ts.context_from(public_context_bytes)
    plaintext = append_sentinel(encoded)
    vector = ts.bfv_vector(context, plaintext)
    return vector.serialize()
