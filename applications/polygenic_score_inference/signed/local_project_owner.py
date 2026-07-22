#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These three functions
run only on the owner's machine — the secret context never leaves it:

  * keygen()  — create the BFV crypto context (WITH Galois keys, so the server can
    do the intra-vector rotate-sum); return (secret, public). The kit shim
    00_keygen.py writes the two halves to disk; only the public half is published.
  * decrypt() — the ONLY use of the secret key: unframe the N per-individual result
    ciphertexts, decrypt each, and recover the signed fixed-point PRS scalar.
  * decode()  — plaintext scalars -> released result (per-individual PRS + cohort
    distribution). Real-valued division by the fixed-point scale is done HERE,
    post-decrypt.

The data owner's stages (encode, encrypt) live in local_data_owner.py; the blind
server stage (compute) lives in server.py.

BFV parameters
--------------
poly_modulus_degree = 8192  -> N/2 = 4096 rotate-summable slots per ciphertext.
                               FIXED across all security levels.
plain_modulus       = 1073692673 (a 30-bit batching prime, == 1 mod 16384) ->
                               EXACT integer arithmetic in Z_t. Signed weights are
                               represented in Z_t and the score's sign is recovered
                               on decrypt (residue > t/2 => negative). The value
                               envelope (server._check_value_envelope) keeps
                               |PRS_scaled| < t/2. FIXED — a function of the value
                               envelope, not security.
Galois keys                 GENERATED (the server's `.sum()` rotate-and-sum needs
                               them). Relinearization keys are NOT generated: the
                               only multiply is ciphertext x PUBLIC plaintext, which
                               never raises ciphertext degree. This is the one
                               difference from the flagship's Galois-free additive
                               tier, and the whole reason a per-individual score is
                               possible without a ciphertext x ciphertext multiply.

Security levels (`--security {128,192,256}`)
--------------------------------------------
`--security` selects the coeff-modulus chain and nothing else. At FIXED N=8192 the
security level is the q-band: SMALLER Sum(bits) => MORE secure. Every chain below
decrypts the rotate-summed, public-weighted score BIT-EXACT (verified, TenSEAL
0.3.16); the 256-bit chain has the least noise budget and still survives the 12
rotations of the rotate-sum plus the plaintext-weight multiply.

  * 128 -> [60,60,60] (Sum=180, lands in the 8192 128-band 153-218)
  * 192 -> [50,50,50] (Sum=150, lands in the 8192 192-band 119-152)
  * 256 -> [45,45,28] (Sum=118, lands in the 8192 256-band <=118)
"""
from __future__ import annotations

from _packing import unframe

DEFAULT_POLY_MODULUS_DEGREE = 8192
# 30-bit NTT batching prime (== 1 mod 16384); exact BFV in Z_t. MUST match
# server.PLAIN_MODULUS. Signed PRS scalars are recovered around t/2 on decrypt.
DEFAULT_PLAIN_MODULUS = 1073692673
DEFAULT_SECURITY = 128

# Published fixed-point factor S (must match server.WEIGHT_SCALE).
WEIGHT_SCALE = 1000

# coeff_mod_bit_sizes chain per requested HE security level, at FIXED N=8192.
# Verified by real TenSEAL 0.3.16 measurement: each chain decrypts the
# public-weighted, rotate-summed per-individual score bit-exact and its achieved
# level (Sum bits vs the HomomorphicEncryption.org caps) == requested.
SECURITY: dict[int, list[int]] = {
    128: [60, 60, 60],  # Sum=180 -> achieved 128
    192: [50, 50, 50],  # Sum=150 -> achieved 192
    256: [45, 45, 28],  # Sum=118 -> achieved 256
}


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``) but WITH Galois
    keys (the server's rotate-sum needs them). No relinearization keys are
    generated — the server never does a ciphertext x ciphertext multiply.

    ``security`` selects the ``coeff_mod_bit_sizes`` chain from ``SECURITY``.
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
    # The server's per-individual `Sum_j` is a rotate-and-sum; it needs Galois keys.
    context.generate_galois_keys()

    # Serialize the private half (with secret key + Galois keys) first.
    secret_bytes = context.serialize(save_secret_key=True)

    # Derive the public half from an independent copy so we never mutate the
    # secret context in place. make_context_public() drops the secret key but
    # keeps the (public) Galois keys the server needs.
    public_context = ts.context_from(secret_bytes)
    public_context.make_context_public()
    public_bytes = public_context.serialize()

    return secret_bytes, public_bytes


def decrypt(secret_context_bytes: bytes, result_bytes: bytes) -> list[int]:
    """Decrypt the N per-individual result ciphertexts -> signed scaled PRS ints.

    This is the ONLY point the secret key is used, and it runs on the owner's
    machine — never on the server. The result blob frames one scalar ciphertext
    per contributor; each decrypts to a residue in ``[0, t)`` which is mapped back
    to a signed integer (``> t/2`` => negative), the fixed-point ``PRS_i * S``.
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")

    plain_modulus = DEFAULT_PLAIN_MODULUS
    half = plain_modulus // 2

    scores: list[int] = []
    for blob in unframe(result_bytes):
        residue = int(ts.bfv_vector_from(context, blob).decrypt()[0])
        scores.append(residue - plain_modulus if residue > half else residue)
    return scores


def _quantile(sorted_values: list[float], q: float) -> float:
    """Linear-interpolated quantile of a pre-sorted list (q in [0,1])."""
    if not sorted_values:
        raise ValueError("no values")
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = q * (len(sorted_values) - 1)
    low = int(position)
    high = min(low + 1, len(sorted_values) - 1)
    frac = position - low
    return sorted_values[low] * (1 - frac) + sorted_values[high] * frac


def decode(plain: list[int], length: int, scale: int = WEIGHT_SCALE) -> dict:
    """Turn the signed scaled PRS scalars into per-individual scores + cohort stats.

        prs_i        = plain[i] / S                        # real per-individual PRS
        mean / sd    = cohort moments of {prs_i}
        min/median/max, q25/q75                            # cohort distribution

    ``length`` is the model's coordinate count L (provenance); ``scale`` is S.
    """
    if scale <= 0:
        raise ValueError(f"scale must be positive, got {scale}")
    if not plain:
        raise ValueError("decode received no per-individual scores")

    n = len(plain)
    scores = [value / scale for value in plain]
    mean = sum(scores) / n
    variance = sum((s - mean) ** 2 for s in scores) / n  # population variance
    ordered = sorted(scores)

    return {
        "application": "polygenic_score_inference",
        "coordinates_length": length,
        "weight_scale": scale,
        "n_contributors": n,
        "scaled_scores": [int(value) for value in plain],
        "per_individual_prs": scores,
        "mean_prs": mean,
        "sd_prs": variance ** 0.5,
        "min_prs": ordered[0],
        "q25_prs": _quantile(ordered, 0.25),
        "median_prs": _quantile(ordered, 0.5),
        "q75_prs": _quantile(ordered, 0.75),
        "max_prs": ordered[-1],
    }
