#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

  * keygen()  — create the ADDITIVE BFV context (wide plaintext modulus for the
    fixed-point covariate moments); return (secret, public).
  * decrypt() — the ONLY use of the secret key: unpack the BMCT1 result container
    and decrypt every aggregate ciphertext -> labelled int vectors.
  * decode()  — the aggregate sufficient statistics -> the covariate-adjusted GWAS
    result: per-SNP effect size, score-test statistic, and p-value.

The covariate-adjusted association is the **semi-parallel GWAS** (Sikorska et al.;
the basis of Blatt et al.'s LRA, PNAS 2020): fit the covariate model ONCE (invert
the k×k covariate Gram `A = XᵀX`), then for each SNP compute a score/Wald statistic
in O(k) from the sufficient statistics. All of that runs HERE, in cleartext, on
exact-or-fixed-point integer aggregates the server produced by ADDITION alone.

Per SNP j, with `A = XᵀX` (k×k), `Ainv = A⁻¹`, `b = Xᵀy`, and the per-SNP terms
`XtG_j = Xᵀg_j` (k), `gy_j = gᵀy`, `gg_j = gᵀg`:

    g⊥ᵀg⊥ = gg_j − XtG_jᵀ·Ainv·XtG_j          # genotype variance orthogonal to covariates
    g⊥ᵀy  = gy_j − XtG_jᵀ·Ainv·b
    β_j    = g⊥ᵀy / g⊥ᵀg⊥
    RSS    = (yᵀy − bᵀ·Ainv·b) − (g⊥ᵀy)² / g⊥ᵀg⊥
    σ²     = RSS / (N − k − 1);   SE(β_j) = sqrt(σ² / g⊥ᵀg⊥)
    z_j    = β_j / SE(β_j);   p_j = erfc(|z_j| / √2)   (score ~ χ²₁)

BFV parameters
--------------
poly_modulus_degree = 8192  -> 8192 packing slots; per-SNP series chunked at 8192.
                              Additive-only (no relin/Galois keys).
plain_modulus       = 274877562881 (a 38-bit batching prime ≡ 1 mod 16384) -> exact
                              integer arithmetic in Z_t for the fixed-point moments.
                              The largest moment is the covariate Gram Σ x·xᵀ, scaled
                              by SCALE² (SCALE=1024), so max ~ SCALE²·N; t keeps it
                              exact for N up to ~260k.
security levels      -> `--security {128,192,256}` selects the coeff chain, byte-
                              identical to the additive flagship (128:[60,60,60],
                              192:[50,50,50], 256:[45,45,28]).

Fixed-point note: the continuous covariates (age, age²) are encoded in fixed point
(SCALE=1024), so this reproduction is highly CONCORDANT (-log10(p) R² ≈ 1.00 vs the
cleartext regression, matching the paper's own R²=1.00 vs exact logistic) rather
than bit-exact. Genotype/phenotype terms are exact integers.
"""
from __future__ import annotations

import math
import struct

DEFAULT_POLY_MODULUS_DEGREE = 8192
# 38-bit NTT batching prime (≡ 1 mod 16384); exact additive BFV in Z_t for the
# fixed-point covariate Gram (max ~ SCALE²·N).
DEFAULT_PLAIN_MODULUS = 274877562881
DEFAULT_SECURITY = 128
SCALE = 1024  # must match local_data_owner.SCALE
SLOT_COUNT = 8192

SECURITY: dict[int, list[int]] = {
    128: [60, 60, 60],
    192: [50, 50, 50],
    256: [45, 45, 28],
}

_CONTAINER_MAGIC = b"BMCT1\n"


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)`` — additive-only BFV
    with the wide plaintext modulus. No relin/Galois keys."""
    import tenseal as ts

    if security not in SECURITY:
        raise ValueError(f"unsupported security level {security!r}; choose {sorted(SECURITY)}")
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=poly_modulus_degree,
        plain_modulus=plain_modulus,
        coeff_mod_bit_sizes=SECURITY[security],
    )
    secret_bytes = context.serialize(save_secret_key=True)
    public_context = ts.context_from(secret_bytes)
    public_context.make_context_public()
    # TenSEAL auto-generates relin keys when a secret key is present; strip both
    # relin and Galois keys from the PUBLISHED public context so it genuinely cannot
    # multiply or rotate — the additive-only trust promise, made structural.
    return secret_bytes, public_context.serialize(save_relin_keys=False, save_galois_keys=False)


def _unpack_container(blob: bytes) -> "dict[str, bytes]":
    if blob[: len(_CONTAINER_MAGIC)] != _CONTAINER_MAGIC:
        raise ValueError("result artifact is not a Blind Machine multi-ciphertext container (bad magic)")
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


def decrypt(secret_context_bytes: bytes, result_bytes: bytes) -> dict:
    """Decrypt every aggregate ciphertext in the container -> ``{name: [ints]}``."""
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")
    named = _unpack_container(result_bytes)
    return {
        name: [int(v) for v in ts.bfv_vector_from(context, named[name]).decrypt()]
        for name in named
    }


def _covariate_count_from_scalars(n: int) -> int:
    """Invert len(scalars) = k(k+1)/2 + k + 2 for k (the covariate count)."""
    k = 1
    while k <= 64:
        if k * (k + 1) // 2 + k + 2 == n:
            return k
        k += 1
    raise ValueError(f"cannot recover covariate count k from scalars length {n}")


def _reassemble(plain: dict, prefix: str, n_chunks: int, length: int) -> list[int]:
    out: list[int] = []
    for c in range(n_chunks):
        name = f"{prefix}_{c}"
        if name not in plain:
            raise ValueError(f"decrypted result missing chunk '{name}'")
        out.extend(int(v) for v in plain[name])
    if len(out) < length:
        raise ValueError(f"reassembled '{prefix}' has {len(out)} slots, fewer than L={length}")
    return out[:length]


def decode(plain: dict, length: int, scale: int = SCALE) -> dict:
    """Covariate-adjusted GWAS: reconstruct the sufficient statistics and run the
    per-SNP semi-parallel score test in cleartext."""
    import numpy as np

    if "scalars" not in plain:
        raise ValueError("decrypted result missing 'scalars'")
    scalars = plain["scalars"]
    k = _covariate_count_from_scalars(len(scalars))

    # unpack scalars: k(k+1)/2 upper-triangle (scale S^2), k of x*y (scale S), y^2, N
    idx = 0
    A = np.zeros((k, k), dtype=float)
    for a in range(k):
        for b in range(a, k):
            v = scalars[idx] / (scale * scale)
            A[a, b] = v
            A[b, a] = v
            idx += 1
    bvec = np.array([scalars[idx + a] / scale for a in range(k)], dtype=float)
    idx += k
    yy = float(scalars[idx]); idx += 1
    n_contributors = int(scalars[idx])
    if n_contributors <= k + 1:
        raise ValueError(f"N={n_contributors} too small for k={k} covariates (need N > k+1)")
    # Exactness envelope: the covariate Gram's largest entry (the intercept diagonal,
    # SCALE²·N) must stay below the plaintext modulus, else the additive sums wrapped
    # mod t silently. Refuse rather than invert a corrupt Gram.
    if (scale * scale) * n_contributors >= DEFAULT_PLAIN_MODULUS:
        raise ValueError(
            f"cohort N={n_contributors} exceeds the exact envelope for SCALE={scale} "
            f"(SCALE^2*N must be < plaintext modulus {DEFAULT_PLAIN_MODULUS}); the "
            f"covariate Gram may have wrapped mod t — split the cohort or lower SCALE"
        )

    n_chunks = (length + SLOT_COUNT - 1) // SLOT_COUNT if length > 0 else 1
    XtG = np.array(
        [[v / scale for v in _reassemble(plain, f"xg{c}", n_chunks, length)] for c in range(k)],
        dtype=float,
    )  # k x M
    gy = np.array(_reassemble(plain, "gy", n_chunks, length), dtype=float)   # M
    gg = np.array(_reassemble(plain, "gg", n_chunks, length), dtype=float)   # M

    try:
        Ainv = np.linalg.inv(A)
    except np.linalg.LinAlgError as exc:
        raise ValueError(
            "covariate design matrix X^T X is singular — collinear or constant "
            "covariates (e.g. a single-sex cohort makes the sex column constant and "
            "collinear with the intercept). Drop a covariate or use a full-rank design."
        ) from exc
    Ainv_b = Ainv @ bvec
    rss_null = yy - float(bvec @ Ainv_b)
    dof = n_contributors - k - 1

    Ainv_XtG = Ainv @ XtG                                   # k x M
    gperp_gperp = gg - np.einsum("cm,cm->m", XtG, Ainv_XtG)  # M
    gperp_y = gy - XtG.T @ Ainv_b                            # M

    beta = np.full(length, np.nan)
    z = np.zeros(length)
    p_value = np.ones(length)
    ok = gperp_gperp > 1e-6
    beta_ok = gperp_y[ok] / gperp_gperp[ok]
    rss_full = rss_null - gperp_y[ok] ** 2 / gperp_gperp[ok]
    sigma2 = np.maximum(rss_full, 0.0) / dof
    se = np.sqrt(sigma2 / gperp_gperp[ok])
    z_ok = np.where(se > 0, beta_ok / np.where(se > 0, se, 1.0), 0.0)
    beta[ok] = beta_ok
    z[ok] = z_ok
    p_value[ok] = [math.erfc(abs(float(zi)) / math.sqrt(2.0)) for zi in z_ok]

    chi_square = (z * z).tolist()
    neg_log10_p = [float("inf") if p <= 0.0 else -math.log10(p) for p in p_value]

    return {
        "protocol": "gwas_covariate_adjusted",
        "coordinates_length": length,
        "n_contributors": n_contributors,
        "covariate_count": k,
        "cases": int(round(bvec[0])),  # intercept column of Xᵀy == Σ y == #cases
        "beta": [None if math.isnan(b) else float(b) for b in beta],
        "score_chi_square": chi_square,
        "z": z.tolist(),
        "p_value": p_value.tolist(),
        "neg_log10_p": neg_log10_p,
    }
