#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These three functions
run only on the owner's machine — the secret context never leaves it:

  * keygen()  — create the BFV crypto context; return (secret, public). The kit
    shim 00_keygen.py writes the two halves to disk; only the public half is ever
    published.
  * decrypt() — the ONLY use of the secret key: aggregate result ciphertext ->
    plaintext integer vector.
  * decode()  — plaintext vector -> released result (per-bucket counts + N),
    with the free one-hot integrity cross-check.

The data owner's stages (encode, encrypt) live in local_data_owner.py; the blind
server stage (compute) lives in server.py.

BFV parameters (IDENTICAL to the flagship — additive minimal params)
--------------------------------------------------------------------
poly_modulus_degree = 8192  -> 8192 packing slots (>> B+1 buckets). FIXED at all
                               security levels: this protocol's batching prime
                               1032193 is ≡1 (mod 16384) only (invalid at any
                               larger ring), and depth-0 headroom makes a bump
                               unnecessary.
plain_modulus       = 1032193 (a 20-bit batching prime) -> exact integer
                               arithmetic in Z_t. Because every contribution is a
                               one-hot vector, the largest per-bucket coordinate
                               sum is N, so t = 1032193 stays exact for N up to
                               ~1M. FIXED per protocol, independent of security.

HE security level (`--security {128,192,256}`)
----------------------------------------------
The one new knob. It selects `coeff_mod_bit_sizes` — the RLWE ciphertext modulus
chain — and NOTHING else (N and t are fixed above). At fixed N the security level
IS the q-band: a *smaller* Σ coeff_mod_bit_sizes is MORE secure. Each chain below
is sized to land squarely in its target band so the harness-computed achieved
level equals the requested one. All four additive protocols standardize on the
same PGS-safe 3-prime chains so the SECURITY table is byte-identical across
bundles.

  * 128 -> [60,60,60] (Σ=180, 128-band [153,218] at N=8192)
  * 192 -> [50,50,50] (Σ=150, 192-band [119,152])
  * 256 -> [45,45,28] (Σ=118, 256-band [≤118])
"""
from __future__ import annotations

DEFAULT_POLY_MODULUS_DEGREE = 8192
# 20-bit NTT-friendly prime; exact BFV in Z_t, t > max coordinate sum (N for a
# one-hot histogram — a single bucket can hold at most every contributor).
DEFAULT_PLAIN_MODULUS = 1032193

# HE security level -> coeff_mod_bit_sizes (the ONLY security-dependent parameter).
# N=8192, depth-0 additive circuit. Each chain lands in its target q-band so the
# harness-computed achieved level == the requested level, and each decrypts
# bit-exact (verified with real TenSEAL 0.3.16). Byte-identical across the four
# additive protocols. See the module docstring for the band semantics.
SECURITY = {
    128: [60, 60, 60],  # Σ=180 -> 128-bit band [153,218] at N=8192
    192: [50, 50, 50],  # Σ=150 -> 192-bit band [119,152]
    256: [45, 45, 28],  # Σ=118 -> 256-bit band [≤118]
}
DEFAULT_SECURITY = 128


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``). Additive-only
    protocol => we generate no relin/Galois keys.

    ``security`` selects the coeff-modulus chain (one of ``SECURITY``'s keys:
    128, 192, or 256). N and t stay fixed — only the ciphertext modulus band
    (hence the certified RLWE security level) changes.
    """
    import tenseal as ts

    if security not in SECURITY:
        raise ValueError(
            f"unsupported security level {security!r}; "
            f"choose one of {sorted(SECURITY)}"
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
    """Decrypt the aggregate ciphertext -> plaintext integer vector (length B+1).

    This is the ONLY point the secret key is used, and it runs on the owner's
    machine — never on the server. The decrypted tensor has length ``B + 1``: the
    first B slots are the per-bucket counts, the trailing slot is the append-1
    sentinel (== N).
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")
    return [int(value) for value in ts.bfv_vector_from(context, result_bytes).decrypt()]


def decode(plain: list[int], length: int) -> dict:
    """Split sentinel from per-bucket counts and run the one-hot integrity check.

    ``length`` is the number of buckets ``B``. Raises ValueError if the tensor is
    not exactly ``B + 1`` slots (sentinel missing / bucket count disagrees), if
    the sentinel is non-positive, or if ``sum(counts) != N`` (a corrupted or
    non-one-hot aggregate).
    """
    expected = length + 1
    if len(plain) != expected:
        raise ValueError(
            f"expected {expected} slots (B={length} + 1 sentinel), got {len(plain)}"
        )

    counts = [int(value) for value in plain[:length]]
    n_contributors = int(plain[length])

    if n_contributors <= 0:
        raise ValueError(f"sentinel decoded to N={n_contributors}; expected N > 0")

    total = sum(counts)
    if total != n_contributors:
        raise ValueError(
            "histogram integrity failure: bucket counts sum to "
            f"{total} but the append-1 sentinel says N={n_contributors} "
            "(one-hot contributions must total N exactly)"
        )

    return {
        "protocol": "cohort_histogram",
        "buckets_length": length,
        "n_contributors": n_contributors,
        "counts": counts,
    }
