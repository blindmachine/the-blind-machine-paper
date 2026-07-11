#!/usr/bin/env python3
"""local_data_owner.py — LOCAL stages each DATA OWNER (contributor) runs.

A data owner turns their own raw (genotype, phenotype) record into ONE packed
uploadable ciphertext, on their own machine, using the project's PUBLIC context
only. Nothing but that blob (and the already-public context) ever leaves the
machine; the secret key is never touched here.

  * encode()  — a ``{"genotype": [...], "phenotype": y}`` record -> ``{"g", "y"}``,
    where ``g`` is the length-L dosage vector and ``y`` is the phenotype scalar
    broadcast to all L slots (broadcasting is what lets the server compute
    ``g_j * y`` element-wise with NO rotation / Galois keys).
  * encrypt() — encoded ``{"g", "y"}`` (+ append-1 sentinel on BOTH) -> ONE packed
    BMCT1 blob co-packing ``(cipher_g, cipher_y)``.

The project owner's stages (keygen, decrypt, decode) live in
local_project_owner.py; the blind server stage (compute) lives in server.py.

Why one packed blob per contributor (not two separate ciphertexts): the hosted
worker's Stager digest-sorts every ciphertext before staging, so two unrelated
``(g, y)`` blobs would be reordered into an arbitrary permutation and the server's
positional pairing would break silently. Co-packing the pair at encrypt time makes
a transport/staging-level "lost or mismatched (g,y) pair" **structurally
impossible**. See SECURITY.md § "Pairing integrity".
"""
from __future__ import annotations

import struct

GENOTYPE_VALUE_DOMAIN = (0, 1, 2)
MISSING_ENCODED_AS = 0
# Default phenotype coding: binary case/control (0 = control, 1 = case). A
# quantized trait passes an explicit phenotype_domain (e.g. 0..Q).
DEFAULT_PHENOTYPE_DOMAIN = (0, 1)

SENTINEL_VALUE = 1

# Container framing for the packed (g, y) pair inside one uploadable blob. This is
# the shared Blind Machine multi-CipherText container v1 — byte-identical to the
# format the server uses for the four moment ciphertexts. Each bundle carries its
# own verbatim copy (bundles are self-contained).
_CONTAINER_MAGIC = b"BMCT1\n"  # Blind Machine multi-CipherText container v1
# Fixed per-contributor pack order => the blob is deterministic and self-describing.
INPUT_ORDER = ("g", "y")


def encode_genotype(raw: list[int | None], length: int) -> list[int]:
    """Return a validated, zero-padded, length-``length`` dosage vector (VERBATIM
    flagship genotype encoding).

    Raises ValueError on an out-of-domain call or an over-length input.
    """
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    if len(raw) > length:
        raise ValueError(
            f"raw genotype length {len(raw)} exceeds coordinate length {length}"
        )

    encoded: list[int] = []
    for index, call in enumerate(raw):
        if call is None:
            encoded.append(MISSING_ENCODED_AS)
            continue
        if call not in GENOTYPE_VALUE_DOMAIN:
            raise ValueError(
                f"coordinate {index}: dosage {call!r} not in {GENOTYPE_VALUE_DOMAIN}"
            )
        encoded.append(int(call))

    encoded.extend([MISSING_ENCODED_AS] * (length - len(encoded)))
    return encoded


def encode_phenotype(
    y: int, length: int, value_domain: tuple[int, ...] = DEFAULT_PHENOTYPE_DOMAIN
) -> list[int]:
    """Return the phenotype scalar ``y`` broadcast to all ``length`` slots.

    Broadcasting (every slot = y) is what makes ``g_j * y`` an element-wise product
    with no rotation. Raises ValueError if ``y`` is missing or out of the published
    phenotype value domain.
    """
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    if y is None:
        raise ValueError("phenotype is missing (null); a covariance contributor "
                         "must supply a phenotype value")
    if y not in value_domain:
        raise ValueError(f"phenotype {y!r} not in published domain {value_domain}")
    return [int(y)] * length


def encode(
    raw: dict,
    length: int,
    phenotype_domain: tuple[int, ...] = DEFAULT_PHENOTYPE_DOMAIN,
) -> dict:
    """Encode a ``{"genotype": [...], "phenotype": y}`` record into ``{"g", "y"}``.

    ``g`` = length-L dosage vector; ``y`` = phenotype broadcast to length L.
    """
    if not isinstance(raw, dict):
        raise ValueError("raw covariance input must be a JSON object with "
                         "'genotype' and 'phenotype' keys")
    if "genotype" not in raw or "phenotype" not in raw:
        raise ValueError("raw input needs both 'genotype' and 'phenotype' keys")

    genotype = raw["genotype"]
    if not isinstance(genotype, list):
        raise ValueError("raw 'genotype' must be a JSON list")

    g = encode_genotype(genotype, length)
    y = encode_phenotype(raw["phenotype"], length, phenotype_domain)
    return {"g": g, "y": y}


def append_sentinel(encoded: list[int], sentinel: int = SENTINEL_VALUE) -> list[int]:
    """Return ``encoded`` with the append-1 sentinel as the final slot.

    Appended to BOTH the genotype and broadcast-phenotype vectors, so all four
    server moments recover the exact contributor count N in their trailing slot —
    a contributor-count integrity check, NOT a MAC.
    """
    return list(encoded) + [sentinel]


def _encrypt_vector(context, plaintext: list[int]) -> bytes:
    """BFV-encrypt one already-sentinel-appended plaintext vector."""
    import tenseal as ts

    return ts.bfv_vector(context, plaintext).serialize()


def pack_pair(named_blobs: dict[str, bytes]) -> bytes:
    """Pack the ``(g, y)`` ciphertext pair into one deterministic container.

    Layout: MAGIC, a uint8 count, then for each name in ``INPUT_ORDER`` a
    length-prefixed name and a length-prefixed blob. Fixed order => byte-
    deterministic. Same framing as ``server.pack_results``.
    """
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(INPUT_ORDER))
    for name in INPUT_ORDER:
        blob = named_blobs[name]
        name_bytes = name.encode("utf-8")
        out += struct.pack(">B", len(name_bytes)) + name_bytes
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def encrypt(public_context_bytes: bytes, encoded: dict) -> bytes:
    """Return ONE packed ``(cipher_g, cipher_y)`` blob for one contributor.

    ``encoded`` is ``{"g": [L ints], "y": [L ints]}``. The append-1 sentinel is
    appended to BOTH vectors before encryption, then the two ciphertexts are
    packed into a single BMCT1 container blob (uploadable). Uses the PUBLIC context
    only; the secret key is not touched here.
    """
    import tenseal as ts

    if not isinstance(encoded, dict) or "g" not in encoded or "y" not in encoded:
        raise ValueError("encoded input must be a JSON object with 'g' and 'y'")

    context = ts.context_from(public_context_bytes)
    cipher_g = _encrypt_vector(context, append_sentinel(encoded["g"]))
    cipher_y = _encrypt_vector(context, append_sentinel(encoded["y"]))
    return pack_pair({"g": cipher_g, "y": cipher_y})
