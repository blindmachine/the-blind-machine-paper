#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These three functions
run only on the owner's machine — the secret context never leaves it:

  * keygen()  — create the BFV crypto context; return (secret, public). The kit
    shim 00_keygen.py writes the two halves to disk; only the public half is ever
    published.
  * decrypt() — the ONLY use of the secret key: aggregate result ciphertext ->
    plaintext integer vector.
  * decode()  — plaintext vector -> released result (carrier counts + rates + N).

The data owner's stages (encode, encrypt) live in local_data_owner.py; the blind
server stage (compute) lives in server.py.

BFV parameters (BYTE-FOR-BYTE the flagship — additive minimal params)
---------------------------------------------------------------------
poly_modulus_degree = 8192  -> 8192 packing slots (>> length+1). FIXED across all
                               three security levels: this additive, depth-0
                               protocol's batching prime is ``≡1 (mod 16384)``
                               (valid ONLY at N=8192), and its depth-0 headroom
                               never needs a bigger ring. Security is selected by
                               the coeff modulus chain, NOT by N.
plain_modulus       = 1032193 (a 20-bit batching prime) -> exact integer
                               arithmetic in Z_t. t must exceed the largest
                               coordinate sum, which for this protocol is N
                               (carrier indicator <= 1, N contributors), so
                               t = 1032193 stays exact for N up to ~1M. FIXED
                               across security levels (a function of the value
                               envelope, not of security).

Security levels (`--security {128,192,256}`)
--------------------------------------------
`--security` is the ONLY new knob; it selects the coeff-modulus chain
(`coeff_mod_bit_sizes`) and nothing else. At FIXED N=8192 the security level is
the q-band: SMALLER Σbits ⇒ MORE secure. The depth-0 carrier-count noise floor
sits in the 256 band, so certifying 128/192 spends *surplus* modulus — the 128
chain is intentionally LARGER (and its ciphertexts bigger/slower) than the 256
chain. That inversion is correct RLWE behaviour, not a bug. All four additive
protocols standardize on the same PGS-safe 3-prime chains so the SECURITY table
is byte-identical across bundles.

  * 128 -> [60,60,60] (Σ=180, lands in the 8192 128-band 153–218)
  * 192 -> [50,50,50] (Σ=150, lands in the 8192 192-band 119–152)
  * 256 -> [45,45,28] (Σ=118, lands in the 8192 256-band ≤118)
"""
from __future__ import annotations

DEFAULT_POLY_MODULUS_DEGREE = 8192
# 20-bit NTT-friendly prime; exact BFV in Z_t, t > max coordinate sum (N).
DEFAULT_PLAIN_MODULUS = 1032193
DEFAULT_SECURITY = 128

# coeff_mod_bit_sizes chains keyed by requested HE security level (bits). Each
# chain's bit-sum lands in that level's q-band at N=8192 so the harness-computed
# achieved security equals the requested level. Standardized on the PGS-safe
# 3-prime layout so this table is byte-identical across all four additive
# protocols. See module docstring for the band arithmetic.
SECURITY: dict[int, list[int]] = {
    128: [60, 60, 60],  # Σ=180  -> achieved 128
    192: [50, 50, 50],  # Σ=150  -> achieved 192
    256: [45, 45, 28],  # Σ=118  -> achieved 256
}


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    ``security`` selects the ``coeff_mod_bit_sizes`` chain from ``SECURITY``
    (one of 128/192/256); ``poly_modulus_degree`` and ``plain_modulus`` are fixed.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``). Additive-only
    protocol => we generate no relin/Galois keys.
    """
    import tenseal as ts

    if security not in SECURITY:
        raise ValueError(
            f"security must be one of {sorted(SECURITY)}, got {security!r}"
        )

    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=poly_modulus_degree,
        plain_modulus=plain_modulus,
        coeff_mod_bit_sizes=SECURITY[security],
    )
    # Serialize the private half (with secret key) first.
    secret_bytes = context.serialize(save_secret_key=True)

    # Derive the public half from an independent copy so we never mutate the
    # secret context in place.
    public_context = ts.context_from(secret_bytes)
    public_context.make_context_public()
    public_bytes = public_context.serialize()

    return secret_bytes, public_bytes


def decrypt(secret_context_bytes: bytes, result_bytes: bytes) -> list[int]:
    """Decrypt the aggregate ciphertext -> plaintext integer vector (length L+1).

    This is the ONLY point the secret key is used, and it runs on the owner's
    machine — never on the server. The decrypted tensor has length ``L + 1``: the
    first L slots are the per-coordinate carrier counts, the trailing slot is the
    append-1 sentinel (== N).
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")
    return [int(value) for value in ts.bfv_vector_from(context, result_bytes).decrypt()]


def decode(plain: list[int], length: int) -> dict:
    """Split sentinel from counts and compute per-coordinate carrier rates.

    Raises ValueError if the tensor is not exactly ``length + 1`` slots, which
    would mean the sentinel is missing or the coordinate length disagrees.
    """
    expected = length + 1
    if len(plain) != expected:
        raise ValueError(
            f"expected {expected} slots (L={length} + 1 sentinel), got {len(plain)}"
        )

    carrier_counts = [int(value) for value in plain[:length]]
    n_contributors = int(plain[length])

    if n_contributors <= 0:
        raise ValueError(f"sentinel decoded to N={n_contributors}; expected N > 0")

    # A carrier count cannot exceed the number of contributors (each contributes
    # a single 0/1 indicator per coordinate). A violation means corruption or an
    # out-of-domain contribution slipped past encoding.
    if any(count < 0 or count > n_contributors for count in carrier_counts):
        raise ValueError(
            "carrier count outside [0, N]; corrupted aggregate or bad contribution"
        )

    # People, not alleles: denominator is N (no ×2 diploid factor).
    carrier_rates = [count / n_contributors for count in carrier_counts]

    return {
        "protocol": "carrier_count",
        "coordinates_length": length,
        "n_contributors": n_contributors,
        "carrier_counts": carrier_counts,
        "carrier_rates": carrier_rates,
    }
