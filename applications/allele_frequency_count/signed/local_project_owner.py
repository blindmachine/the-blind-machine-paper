#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These three functions
run only on the owner's machine — the secret context never leaves it:

  * keygen()  — create the BFV crypto context; return (secret, public). The kit
    shim 00_keygen.py writes the two halves to disk; only the public half is ever
    published.
  * decrypt() — the ONLY use of the secret key: aggregate result ciphertext ->
    plaintext integer vector.
  * decode()  — plaintext vector -> released result (allele frequencies + N).

The data owner's stages (encode, encrypt) live in local_data_owner.py; the blind
server stage (compute) lives in server.py.

BFV parameters
--------------
poly_modulus_degree = 8192  -> 8192 packing slots (>> length+1). FIXED across all
                               security levels: this protocol's batching prime is
                               `≡1 (mod 16384)` only (invalid at any larger N), and
                               depth-0 headroom makes a bump unnecessary. N is a
                               function of the value envelope + multiplicative
                               depth, NOT of security.
plain_modulus       = 1032193 (a 20-bit batching prime) -> exact integer
                               arithmetic in Z_t. The plaintext modulus t must
                               exceed the largest coordinate sum, which for this
                               protocol is 2*N (dosage <= 2, N contributors), so
                               t = 1032193 stays exact for N up to ~500k. Also
                               FIXED — a function of the value envelope, not
                               security.

Security levels (`--security {128,192,256}`)
--------------------------------------------
`--security` is the ONLY new knob; it selects the coeff-modulus chain
(`coeff_mod_bit_sizes`) and nothing else. At FIXED N=8192 the security level is
the q-band: SMALLER Σbits ⇒ MORE secure. So certifying a HIGHER security level
uses a SMALLER coeff modulus. This is correct RLWE behaviour — the depth-0 noise
floor for this payload sits in the 256 band, so 128/192 spend *surplus* modulus
(bigger/slower ciphertexts) than 256. Not a bug: the "256 is cheaper than 128"
inversion is intrinsic. All four additive protocols standardize on the same
PGS-safe 3-prime chains so the SECURITY table is byte-identical across bundles.

  * 128 -> [60,60,60] (Σ=180, lands in the 8192 128-band 153–218)
  * 192 -> [50,50,50] (Σ=150, lands in the 8192 192-band 119–152)
  * 256 -> [45,45,28] (Σ=118, lands in the 8192 256-band ≤118)
"""
from __future__ import annotations

DEFAULT_POLY_MODULUS_DEGREE = 8192
# 20-bit NTT-friendly prime; exact BFV in Z_t, t > max coordinate sum (2*N).
DEFAULT_PLAIN_MODULUS = 1032193
DEFAULT_SECURITY = 128

# coeff_mod_bit_sizes chain per requested HE security level, at FIXED N=8192.
# Verified by real TenSEAL 0.3.16 measurement: each chain decrypts bit-exact and
# its achieved level (Σbits vs the HomomorphicEncryption.org caps) == requested.
# Shared verbatim across all four additive protocols (PGS-safe 3-prime chains).
SECURITY: dict[int, list[int]] = {
    128: [60, 60, 60],  # Σ=180 -> achieved 128
    192: [50, 50, 50],  # Σ=150 -> achieved 192
    256: [45, 45, 28],  # Σ=118 -> achieved 256
}


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``). Additive-only
    protocol => we generate no relin/Galois keys.

    ``security`` selects the ``coeff_mod_bit_sizes`` chain from ``SECURITY`` — the
    only parameter that varies with the requested HE security level.
    """
    import tenseal as ts

    if security not in SECURITY:
        raise ValueError(
            f"unsupported security level {security!r}; choose one of {sorted(SECURITY)}"
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
    first L slots are the per-coordinate allele counts, the trailing slot is the
    append-1 sentinel (== N).
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")
    return [int(value) for value in ts.bfv_vector_from(context, result_bytes).decrypt()]


def decode(plain: list[int], length: int) -> dict:
    """Split sentinel from counts and compute per-coordinate frequencies.

    Splits the length-``L + 1`` decrypted vector into ``allele_counts`` (the first
    L slots) and ``n_contributors`` (the trailing append-1 sentinel == exact N),
    then derives per-variant allele frequency ``= sum_g / (2N)`` (each contributor
    carries up to 2 alt alleles per diploid coordinate, so the denominator is 2N).

    Raises ValueError if the tensor is not exactly ``length + 1`` slots, which
    would mean the sentinel is missing or the coordinate length disagrees.
    """
    expected = length + 1
    if len(plain) != expected:
        raise ValueError(
            f"expected {expected} slots (L={length} + 1 sentinel), got {len(plain)}"
        )

    allele_counts = [int(value) for value in plain[:length]]
    n_contributors = int(plain[length])

    if n_contributors <= 0:
        raise ValueError(f"sentinel decoded to N={n_contributors}; expected N > 0")

    denominator = 2 * n_contributors
    allele_frequencies = [count / denominator for count in allele_counts]

    return {
        "protocol": "allele_frequency_count",
        "coordinates_length": length,
        "n_contributors": n_contributors,
        "allele_counts": allele_counts,
        "allele_frequencies": allele_frequencies,
    }
