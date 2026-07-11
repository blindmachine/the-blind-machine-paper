#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These functions run only
on the owner's machine — the secret context never leaves it:

  * keygen()  — create the multiplication-supporting BFV crypto context (relin
    keys retained in the public half for the server's ct×ct product). The kit
    shim 00_keygen.py writes the two halves to disk; only the public half is ever
    published.
  * decrypt() — the ONLY use of the secret key: unpack the BMCT1 result container
    and decrypt all four moment ciphertexts -> labelled int vectors.
  * decode()  — the four moment vectors -> released per-variant covariance.

The data owner's stages (encode, encrypt) live in local_data_owner.py; the blind
server stage (compute) lives in server.py.

BFV parameters
--------------
poly_modulus_degree = 16384 -> multiplication-supporting ring; 16384 packing
                              slots (>> length+1). FIXED across all three security
                              levels (the depth-1 noise floor cannot fit under the
                              152/118 caps at n=8192, so we vary the chain and pin
                              N — mirroring the additive design).
coeff_mod_bit_sizes -> selected by ``security`` from the SECURITY table. All three
                              land under the 438-bit cap at n=16384 and, because
                              security == q-band at fixed N, a SMALLER chain is
                              MORE secure (the "256 is cheaper than 128" inversion,
                              correct RLWE behaviour — see SECURITY.md).
                                128 -> [60,60,60,60,60,60] (Σ=360, achieved 128)
                                192 -> [60,60,60,60]       (Σ=240, achieved 192)
                                256 -> [60,40,40,60]       (Σ=200, achieved 256)
                              Every chain keeps ≥2 interior "level" primes between
                              the two 60-bit key-switching special primes, so the
                              one multiplicative level (ct×ct + relin) has budget.
plain_modulus       = 786433 (a 20-bit batching prime, 24*32768 + 1, ≡ 1 mod
                              2*16384 as BFV NTT batching requires at this ring
                              size). FIXED per protocol. For a BINARY phenotype the
                              max moment is ~2N (sum_gy with g<=2, y<=1), so
                              t = 786433 stays exact for N up to ~196k.
"""
from __future__ import annotations

import struct

# Multiplication-supporting ring: depth-1 ct*ct needs a coeff-mod chain and a
# larger poly degree than the additive flagship (8192). FIXED across all levels.
DEFAULT_POLY_MODULUS_DEGREE = 16384
# 20-bit NTT batching prime valid at poly=16384 (786433 = 24*32768 + 1, so it is
# ≡ 1 mod 2*16384). Exact BFV in Z_t for a binary phenotype (max moment ~2N).
DEFAULT_PLAIN_MODULUS = 786433

# --security selects the coefficient-modulus chain (the ONLY security knob). N and
# t are fixed per protocol; only the chain moves the achieved level. At fixed N,
# security level == q-band, so a SMALLER Σ is MORE secure — the depth-1 noise floor
# sits in the 256 band, so 128/192 widen the chain into their (higher-cap, lower-
# security) bands. All three keep ≥2 interior primes for the one multiplicative
# level and were verified bit-exact against the cleartext oracle (TenSEAL 0.3.16).
SECURITY = {
    128: [60, 60, 60, 60, 60, 60],  # Σ=360 -> achieved 128 (band 306..438 @ n=16384)
    192: [60, 60, 60, 60],          # Σ=240 -> achieved 192 (band 238..305)
    256: [60, 40, 40, 60],          # Σ=200 -> achieved 256 (band  ≤237)
}
DEFAULT_SECURITY = 128
# Retained for backward compatibility with callers that pass a chain positionally:
# the historical default was the 200-bit chain (which certifies 256).
DEFAULT_COEFF_MOD_BIT_SIZES = tuple(SECURITY[DEFAULT_SECURITY])

# Kept in lockstep with server.py (same canonical order + framing).
MOMENT_ORDER = ("sum_g", "sum_gy", "sum_y", "sum_y2")
_CONTAINER_MAGIC = b"BMCT1\n"  # shared Blind Machine multi-CipherText container v1


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
    coeff_mod_bit_sizes: tuple[int, ...] | None = None,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    ``security`` (128/192/256) selects the coefficient-modulus chain from the
    ``SECURITY`` table. Pass ``coeff_mod_bit_sizes`` explicitly to override the
    table (the §3 quantized-trait / oversized-cohort escape hatch); when omitted
    the chain is derived from ``security``.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``) but the
    **relinearization keys retained** (depth-1 ct×ct protocol). We generate no
    Galois keys — every op is element-wise, so there is no rotation.
    """
    import tenseal as ts

    if coeff_mod_bit_sizes is None:
        if security not in SECURITY:
            raise ValueError(
                f"security must be one of {sorted(SECURITY)}, got {security!r}"
            )
        coeff_mod_bit_sizes = SECURITY[security]

    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=poly_modulus_degree,
        plain_modulus=plain_modulus,
        coeff_mod_bit_sizes=list(coeff_mod_bit_sizes),
    )
    # Explicit relin keys for the encrypted product (the server relinearizes each
    # ct×ct back to a degree-2 ciphertext). TenSEAL also auto-generates these when
    # a secret key is present; calling it makes the intent legible. No Galois keys.
    context.generate_relin_keys()

    # Serialize the private half (with secret key) first.
    secret_bytes = context.serialize(save_secret_key=True)

    # Derive the public half from an independent copy so we never mutate the
    # secret context in place. make_context_public() strips ONLY the secret key;
    # the relin keys ride along so the server can relinearize.
    public_context = ts.context_from(secret_bytes)
    public_context.make_context_public()
    public_bytes = public_context.serialize()

    return secret_bytes, public_bytes


def unpack_results(blob: bytes) -> dict[str, bytes]:
    """Recover ``{name: ciphertext_bytes}`` from the server's BMCT1 container."""
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


def decrypt_blob(context, result_bytes: bytes) -> list[int]:
    """Decrypt one aggregate ciphertext -> plaintext integer vector (length L+1)."""
    import tenseal as ts

    return [int(v) for v in ts.bfv_vector_from(context, result_bytes).decrypt()]


def decrypt(secret_context_bytes: bytes, result_bytes: bytes) -> dict:
    """Decrypt every moment ciphertext in the container -> labelled int vectors.

    This is the ONLY point the secret key is used, and it runs on the owner's
    machine — never on the server.
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")

    named = unpack_results(result_bytes)
    return {name: decrypt_blob(context, named[name]) for name in MOMENT_ORDER}


def _split_sentinel(vector: list[int], length: int, name: str) -> tuple[list[int], int]:
    expected = length + 1
    if len(vector) != expected:
        raise ValueError(
            f"{name}: expected {expected} slots (L={length} + 1 sentinel), "
            f"got {len(vector)}"
        )
    return [int(v) for v in vector[:length]], int(vector[length])


def _broadcast_scalar(slots: list[int], name: str) -> int:
    """Return the single value a broadcast moment holds in every leading slot.

    Asserts every leading slot is identical (integrity: the phenotype was
    broadcast, so any divergence means corruption).
    """
    if not slots:
        raise ValueError(f"{name}: no leading slots to read a broadcast scalar from")
    lo, hi = min(slots), max(slots)
    if lo != hi:
        raise ValueError(
            f"{name}: broadcast moment is not uniform across slots "
            f"(min={lo}, max={hi}); result is corrupt"
        )
    return int(slots[0])


def decode(plain: dict, length: int) -> dict:
    """Split sentinels, cross-check N, and compute per-variant covariance."""
    for name in MOMENT_ORDER:
        if name not in plain:
            raise ValueError(f"decrypted moments missing '{name}'")

    sum_g, n_g = _split_sentinel(plain["sum_g"], length, "sum_g")
    sum_gy, n_gy = _split_sentinel(plain["sum_gy"], length, "sum_gy")
    sum_y_slots, n_y = _split_sentinel(plain["sum_y"], length, "sum_y")
    sum_y2_slots, n_y2 = _split_sentinel(plain["sum_y2"], length, "sum_y2")

    # All four append-1 sentinels must recover the SAME contributor count.
    if not (n_g == n_gy == n_y == n_y2):
        raise ValueError(
            f"sentinel disagreement across moments: sum_g={n_g}, sum_gy={n_gy}, "
            f"sum_y={n_y}, sum_y2={n_y2} (result is corrupt)"
        )
    n_contributors = n_g
    if n_contributors <= 0:
        raise ValueError(f"sentinel decoded to N={n_contributors}; expected N > 0")

    sum_y = _broadcast_scalar(sum_y_slots, "sum_y")
    sum_y2 = _broadcast_scalar(sum_y2_slots, "sum_y2")

    n = n_contributors
    mean_g = [g / n for g in sum_g]
    mean_y = sum_y / n
    var_y = sum_y2 / n - mean_y * mean_y
    covariance = [
        sum_gy[j] / n - (sum_g[j] / n) * mean_y for j in range(length)
    ]

    return {
        "protocol": "genotype_phenotype_covariance",
        "coordinates_length": length,
        "n_contributors": n_contributors,
        "sum_g": sum_g,
        "sum_gy": sum_gy,
        "sum_y": sum_y,
        "sum_y2": sum_y2,
        "mean_g": mean_g,
        "mean_y": mean_y,
        "var_y": var_y,
        "covariance": covariance,
    }
