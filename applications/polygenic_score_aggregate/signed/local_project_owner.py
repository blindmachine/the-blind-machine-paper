#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These three functions
run only on the owner's machine — the secret context never leaves it:

  * keygen()  — create the BFV crypto context; return (secret, public). The kit
    shim 00_keygen.py writes the two halves to disk; only the public half is ever
    published.
  * decrypt() — the ONLY use of the secret key: aggregate result ciphertext ->
    plaintext integer vector.
  * decode()  — plaintext vector -> released result (weighted counts + cohort PGS).
    The cross-coordinate reduction (Sigma_j) is done HERE, post-decrypt, never
    under encryption — which is what keeps the protocol on minimal additive-tier
    params.

The data owner's stages (encode, encrypt) live in local_data_owner.py; the blind
server stage (compute, incl. the public-weight multiply) lives in server.py.

BFV parameters
--------------
poly_modulus_degree = 8192  -> 8192 packing slots (>> length+1). FIXED across all
                               security levels.
plain_modulus       = 1073692673 (a 30-bit batching prime, == 1 mod 16384) ->
                               exact integer arithmetic in Z_t. The flagship's
                               20-bit t = 1032193 is UNDER-SIZED here: the public
                               plaintext-weight multiply inflates each coordinate
                               to w_scaled[j] * (sum_i g_ij), whose maximum is
                               max_j(w_scaled[j]) * 2N. With S = 1000 and effect
                               weights <= ~2.0 (w_scaled <= ~2000), t = 1073692673
                               stays exact for N up to ~250k. FIXED — a function of
                               the value envelope, not security.

Security levels (`--security {128,192,256}`)
--------------------------------------------
`--security` selects the coeff-modulus chain (`coeff_mod_bit_sizes`) and nothing
else. At FIXED N=8192 the security level is the q-band: SMALLER Σbits ⇒ MORE
secure. This protocol's one extra op — a single ciphertext × PLAINTEXT weight
multiply (degree-preserving) — combined with the 30-bit t needs an EFFECTIVE q
≳ 80 bits; TenSEAL reserves the LAST coeff prime as a key-switching special prime,
so every level ships a 3-prime chain (a 2-prime chain leaves < 80 effective bits
and FAILS to decrypt). All four additive protocols standardize on these same
PGS-safe 3-prime chains so the SECURITY table is byte-identical across bundles.

  * 128 -> [60,60,60] (Σ=180, eff 120, lands in the 8192 128-band 153–218)
  * 192 -> [50,50,50] (Σ=150, eff 100, lands in the 8192 192-band 119–152)
  * 256 -> [45,45,28] (Σ=118, eff  90, lands in the 8192 256-band ≤118)
"""
from __future__ import annotations

DEFAULT_POLY_MODULUS_DEGREE = 8192
# 30-bit NTT batching prime (== 1 mod 16384); exact BFV in Z_t, t > max slot value
# = max_j(w_scaled[j]) * 2N after the public-weight multiply. See module docstring.
DEFAULT_PLAIN_MODULUS = 1073692673
DEFAULT_SECURITY = 128

# coeff_mod_bit_sizes chain per requested HE security level, at FIXED N=8192.
# Verified by real TenSEAL 0.3.16 measurement: each chain decrypts the public-
# weighted aggregate bit-exact and its achieved level (Σbits vs the
# HomomorphicEncryption.org caps) == requested. PGS-safe 3-prime chains (2-prime
# chains leave < 80 effective bits after the special prime and FAIL for this
# protocol's 30-bit t + weight multiply). Shared verbatim across all four
# additive protocols.
SECURITY: dict[int, list[int]] = {
    128: [60, 60, 60],  # Σ=180 -> achieved 128
    192: [50, 50, 50],  # Σ=150 -> achieved 192
    256: [45, 45, 28],  # Σ=118 -> achieved 256
}

# Published fixed-point factor S (must match server.WEIGHT_SCALE).
WEIGHT_SCALE = 1000


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``). Additive-tier
    protocol (add + plaintext-scalar multiply) => we generate no relin/Galois keys.

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
    first L slots are the per-coordinate weighted counts ``w_scaled[j] *
    (sum_i g_ij)`` (integer, fixed-point domain of scale S), the trailing slot is
    the append-1 sentinel — weighted by 1 in stage 30, so it still decrypts to
    exactly N.
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")
    return [int(value) for value in ts.bfv_vector_from(context, result_bytes).decrypt()]


def decode(plain: list[int], length: int, scale: int = WEIGHT_SCALE) -> dict:
    """Split sentinel from weighted counts and compute the cohort PGS.

    Raises ValueError if the tensor is not exactly ``length + 1`` slots, which
    would mean the sentinel is missing or the coordinate length disagrees.

        cohort_pgs_scaled = sum_j weighted_counts[j]        # integer, exact
        cohort_pgs_sum    = cohort_pgs_scaled / S           # sum_i PGS_i  (real)
        mean_pgs          = cohort_pgs_scaled / (S * N)     # mean per-contributor PGS
    """
    expected = length + 1
    if len(plain) != expected:
        raise ValueError(
            f"expected {expected} slots (L={length} + 1 sentinel), got {len(plain)}"
        )
    if scale <= 0:
        raise ValueError(f"scale must be positive, got {scale}")

    weighted_counts = [int(value) for value in plain[:length]]
    n_contributors = int(plain[length])

    if n_contributors <= 0:
        raise ValueError(f"sentinel decoded to N={n_contributors}; expected N > 0")

    cohort_pgs_scaled = sum(weighted_counts)
    cohort_pgs_sum = cohort_pgs_scaled / scale
    mean_pgs = cohort_pgs_scaled / (scale * n_contributors)

    return {
        "protocol": "polygenic_score_aggregate",
        "coordinates_length": length,
        "weight_scale": scale,
        "n_contributors": n_contributors,
        "weighted_counts": weighted_counts,
        "cohort_pgs_scaled": cohort_pgs_scaled,
        "cohort_pgs_sum": cohort_pgs_sum,
        "mean_pgs": mean_pgs,
    }
