#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These functions run only
on the owner's machine — the secret context never leaves it:

  * keygen()  — create the BFV crypto context (multiplication-supporting: relin
    keys retained in the public half for the server's ct x ct square). The kit
    shim 00_keygen.py writes the two halves to disk; only the public half is ever
    published.
  * decrypt() — the ONLY use of the secret key: unpack the BMCT1 result container
    and decrypt both moment ciphertexts -> ``{"sum": [..], "sumsq": [..]}``.
  * decode()  — moment vectors -> released result (mean / variance / frequency).

The data owner's stages (encode, encrypt) live in local_data_owner.py; the blind
server stage (compute) lives in server.py.

BFV parameters (minimal-but-sufficient for ONE multiplicative level)
--------------------------------------------------------------------
poly_modulus_degree = 16384  -> 16384 packing slots (>> length+1). N is FIXED at
                                16384 at ALL THREE security levels (the depth-1
                                noise floor cannot fit under the 152/118 caps at
                                n=8192). The larger ring is what a multiplicative
                                level costs vs the flagship's 8192.
plain_modulus       = 786433 (a 20-bit batching prime, == 1 mod 2*16384) -> exact
                                integer arithmetic in Z_t. The largest value is
                                max sum_g2 = 4*N (g^2 <= 4), so t = 786433 stays
                                exact for N up to ~196k. FIXED per protocol.
coeff_mod_bit_sizes = selected by ``security`` from the SECURITY table. Depth-1
                                needs >=2 interior "level" primes between the two
                                60-bit special primes; the 256 cell uses the
                                minimal [60,40,40,60]=200, and 192/128 WIDEN the
                                chain into their (higher-cap, lower-security)
                                q-bands (the intentional "256 is cheaper" RLWE
                                inversion — correct behaviour, not a bug).

    security 128 -> [60, 60, 60, 60, 60, 60]  (Sigma=360, achieved 128)
    security 192 -> [60, 60, 60, 60]           (Sigma=240, achieved 192)
    security 256 -> [60, 40, 40, 60]           (Sigma=200, achieved 256)
"""
from __future__ import annotations

import struct

# Multiplication-supporting BFV: a larger ring + an explicit coeff modulus chain
# with >=2 RNS primes so ONE ct x ct multiply (the square) has budget.
DEFAULT_POLY_MODULUS_DEGREE = 16384
# 20-bit NTT batching prime, == 1 (mod 2*16384); REQUIRED at n=16384. Exact BFV in
# Z_t with t > max coordinate value (max sum_g2 = 4*N).
DEFAULT_PLAIN_MODULUS = 786433

# Default security level. 128 matches the survey contract; `security` selects the
# coeff modulus chain (the ONLY knob security moves) from the SECURITY table.
DEFAULT_SECURITY = 128

# AUTHORITATIVE per-security coeff_mod_bit_sizes (N=16384, t=786433, depth 1).
# Each chain lands in the requested level's q-band so the harness computes
# achieved == requested. At FIXED N smaller Sigma == MORE secure, hence the
# intentional inversion: 128 uses a LARGER modulus than 256 (see module docstring).
#   128: [60,60,60,60,60,60] Sigma=360 (band 306-438)  -> achieved 128
#   192: [60,60,60,60]       Sigma=240 (band 238-305)  -> achieved 192
#   256: [60,40,40,60]       Sigma=200 (band <=237)    -> achieved 256
SECURITY = {
    128: [60, 60, 60, 60, 60, 60],
    192: [60, 60, 60, 60],
    256: [60, 40, 40, 60],
}

# Default chain == SECURITY[128] = [60,60,60,60,60,60] (Sigma=360, achieved 128).
# Retained as a named constant for the explicit-override CLI path.
DEFAULT_COEFF_MOD_BIT_SIZES = tuple(SECURITY[DEFAULT_SECURITY])

# Sentinel distinguishing "caller did not pass a chain -> derive from `security`"
# from an explicit ``None`` (which means "TenSEAL default coeff modulus").
_USE_SECURITY_TABLE = object()

# Kept in lockstep with server.py (same canonical order + framing).
MOMENT_ORDER = ("sum", "sumsq")
_CONTAINER_MAGIC = b"BMCT1\n"


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    coeff_mod_bit_sizes=_USE_SECURITY_TABLE,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``) but the
    **relinearization keys retained** so the server can square under encryption.
    Depth-1 protocol => TenSEAL auto-generates relin keys (a secret key exists at
    context creation) and keeps them through ``make_context_public()``; we do NOT
    generate Galois keys (no rotation is ever performed).

    ``security`` selects the coeff modulus chain from ``SECURITY`` (128/192/256);
    it is the ONLY knob that moves security — ``poly_modulus_degree`` and
    ``plain_modulus`` are fixed functions of the value envelope + depth, not of
    security.

    ``coeff_mod_bit_sizes`` overrides ``security`` when passed explicitly:
      * left unset  -> use ``SECURITY[security]`` (the normal path);
      * ``None``    -> TenSEAL's default coeff modulus (additive/minimal regime,
        used by the benchmark's additive client-precompute variant);
      * a list      -> that exact chain (e.g. the §3 quantized-trait escape hatch).
    """
    import tenseal as ts

    if coeff_mod_bit_sizes is _USE_SECURITY_TABLE:
        if security not in SECURITY:
            raise ValueError(
                f"security must be one of {sorted(SECURITY)}; got {security!r}"
            )
        coeff_mod_bit_sizes = list(SECURITY[security])

    context_kwargs = dict(
        poly_modulus_degree=poly_modulus_degree,
        plain_modulus=plain_modulus,
    )
    if coeff_mod_bit_sizes is not None:
        context_kwargs["coeff_mod_bit_sizes"] = list(coeff_mod_bit_sizes)

    context = ts.context(ts.SCHEME_TYPE.BFV, **context_kwargs)
    # Serialize the private half (with secret key) first. TenSEAL has already
    # generated relin keys alongside the secret key.
    secret_bytes = context.serialize(save_secret_key=True)

    # Derive the public half from an independent copy so we never mutate the
    # secret context in place. make_context_public() strips ONLY the secret key;
    # the relin keys survive, which is exactly what the ct x ct square needs.
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

    return [int(value) for value in ts.bfv_vector_from(context, result_bytes).decrypt()]


def decrypt(secret_context_bytes: bytes, result_bytes: bytes) -> dict:
    """Decrypt every moment ciphertext in the container -> labelled int vectors.

    Returns ``{"sum": [L+1 ints], "sumsq": [L+1 ints]}``. This is the ONLY point
    the secret key is used, and it runs on the owner's machine — never the server.
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")

    named = unpack_results(result_bytes)
    return {name: decrypt_blob(context, named[name]) for name in MOMENT_ORDER}


def _split_sentinel(vector: list[int], length: int, name: str) -> tuple[list[int], int]:
    """Return ``(first_L_slots, sentinel)`` or raise if the length is wrong."""
    expected = length + 1
    if len(vector) != expected:
        raise ValueError(
            f"{name}: expected {expected} slots (L={length} + 1 sentinel), "
            f"got {len(vector)}"
        )
    return [int(v) for v in vector[:length]], int(vector[length])


def decode(plain: dict, length: int) -> dict:
    """Split sentinels from both moment vectors and derive mean/variance.

    ``plain`` is ``{"sum": [L+1 ints], "sumsq": [L+1 ints]}``. Raises ValueError if
    either vector is not exactly ``length + 1`` slots, if the two sentinels
    disagree, or if the recovered N is not positive.
    """
    if not isinstance(plain, dict) or "sum" not in plain or "sumsq" not in plain:
        raise ValueError('plain must be a dict with "sum" and "sumsq" keys')

    sum_g, n_from_sum = _split_sentinel(plain["sum"], length, "sum_g")
    sum_g2, n_from_sumsq = _split_sentinel(plain["sumsq"], length, "sum_g2")

    if n_from_sum != n_from_sumsq:
        raise ValueError(
            f"sentinel mismatch: sum path N={n_from_sum}, square path "
            f"N={n_from_sumsq} (the two aggregates saw different cohorts)"
        )
    n_contributors = n_from_sum
    if n_contributors <= 0:
        raise ValueError(f"sentinel decoded to N={n_contributors}; expected N > 0")

    mean = [s / n_contributors for s in sum_g]
    variance = [
        sq / n_contributors - (s / n_contributors) ** 2
        for s, sq in zip(sum_g, sum_g2)
    ]
    allele_frequency = [m / 2 for m in mean]

    return {
        "protocol": "allele_frequency_with_variance",
        "coordinates_length": length,
        "n_contributors": n_contributors,
        "sum_g": sum_g,
        "sum_g2": sum_g2,
        "mean": mean,
        "variance": variance,
        "allele_frequency": allele_frequency,
    }
