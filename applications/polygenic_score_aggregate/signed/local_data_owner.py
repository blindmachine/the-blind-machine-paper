#!/usr/bin/env python3
"""local_data_owner.py — LOCAL stages each DATA OWNER (contributor) runs.

A data owner turns their own raw genotype data into one ciphertext, on their own
machine, using the project's PUBLIC context only. Nothing but the ciphertext (and
the already-public context) ever leaves the machine; the secret key is never
touched here.

  * encode()  — raw dosage vector -> validated, zero-padded, length-L vector.
  * encrypt() — encoded vector (+ append-1 sentinel) -> serialized ciphertext.

The project owner's stages (keygen, decrypt, decode) live in
local_project_owner.py; the blind server stage (compute) lives in server.py.

For `polygenic_score_aggregate` the client encoding is IDENTICAL to the flagship's
alt-allele dosage encoding: the raw input is a dosage vector ``g in {0,1,2}^L``.
The public effect weights are NOT applied here — they live in `manifest.yml` and
are applied SERVER-side as a plaintext-scalar multiply on the already-summed
cohort ciphertext. This is the "looks multiplicative, remains additive" protocol:
the client only ever ships a raw dosage vector — bit-identical in shape to the
flagship.
"""
from __future__ import annotations

VALUE_DOMAIN = (0, 1, 2)
MISSING_ENCODED_AS = 0
SENTINEL_VALUE = 1


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
            raise ValueError(
                f"coordinate {index}: dosage {call!r} not in {VALUE_DOMAIN}"
            )
        encoded.append(int(call))

    # Zero-pad any trailing coordinates the raw vector did not cover.
    encoded.extend([MISSING_ENCODED_AS] * (length - len(encoded)))
    return encoded


def append_sentinel(encoded: list[int], sentinel: int = SENTINEL_VALUE) -> list[int]:
    """Return ``encoded`` with the append-1 sentinel as the final slot.

    When the server homomorphically sums N contributions, that trailing slot sums
    to exactly N. The server weights it by 1, so it still decrypts to exactly N —
    an integrity/corruption check, NOT a MAC.
    """
    return list(encoded) + [sentinel]


def encrypt(public_context_bytes: bytes, encoded: list[int]) -> bytes:
    """BFV-encrypt ``encoded`` (with sentinel appended) -> serialized ciphertext.

    Uses the PUBLIC context only. The extended plaintext vector (length L + 1) is
    encrypted; the ciphertext, alongside the public context, is the only thing
    ever uploaded. The secret key is not touched here.
    """
    import tenseal as ts

    context = ts.context_from(public_context_bytes)
    plaintext = append_sentinel(encoded)
    vector = ts.bfv_vector(context, plaintext)
    return vector.serialize()
