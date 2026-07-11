#!/usr/bin/env python3
"""local_data_owner.py — LOCAL stages each DATA OWNER (contributor) runs.

A data owner turns their own raw genotype data into one ciphertext, on their own
machine, using the project's PUBLIC context only. Nothing but the ciphertext (and
the already-public context) ever leaves the machine; the secret key is never
touched here.

  * encode()  — raw dosage vector -> validated, zero-padded, length-L carrier
    indicator vector (dosage {0,1,2}/null thresholded LOCALLY to {0,1}).
  * encrypt() — encoded vector (+ append-1 sentinel) -> serialized ciphertext.

The project owner's stages (keygen, decrypt, decode) live in
local_project_owner.py; the blind server stage (compute) lives in server.py.

`carrier_count` shares the flagship's coordinate definition but uses a DIFFERENT
client-side encoding (catalog §2): the raw input is still an alt-allele dosage
vector ``g in {0,1,2}^L``, but encoding thresholds each coordinate to a carrier
indicator ``c in {0,1}^L`` (dosage >= 1 -> 1, else 0; missing -> 0). Summing
these indicators homomorphically yields the per-coordinate carrier count, NOT the
allele dosage sum the flagship produces. One coordinate definition, one additive
primitive, a different released statistic.
"""
from __future__ import annotations

# The raw dosage domain accepted on input; the encoding EMITS {0,1} indicators.
VALUE_DOMAIN = (0, 1, 2)
MISSING_ENCODED_AS = 0
# A coordinate is a "carrier" coordinate when the alt-allele dosage is >= this.
CARRIER_THRESHOLD = 1
SENTINEL_VALUE = 1


def encode(raw: list[int | None], length: int) -> list[int]:
    """Return a validated, zero-padded, length-``length`` carrier-indicator vector.

    Each entry is ``1`` iff the raw alt-allele dosage is >= ``CARRIER_THRESHOLD``
    (i.e. the participant carries at least one alt allele at that coordinate),
    else ``0``. Missing calls encode as 0 (non-carrier).

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
        # Threshold dosage -> carrier indicator (the one line that differs from
        # the flagship's per-coordinate dosage passthrough).
        encoded.append(1 if int(call) >= CARRIER_THRESHOLD else 0)

    # Zero-pad any trailing coordinates the raw vector did not cover.
    encoded.extend([MISSING_ENCODED_AS] * (length - len(encoded)))
    return encoded


def append_sentinel(encoded: list[int], sentinel: int = SENTINEL_VALUE) -> list[int]:
    """Return ``encoded`` with the append-1 sentinel as the final slot.

    When the server homomorphically sums N contributions, that trailing slot sums
    to exactly N. Decrypting it recovers the exact contributor count — an
    integrity/corruption check, NOT a MAC.
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
