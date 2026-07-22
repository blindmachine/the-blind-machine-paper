#!/usr/bin/env python3
"""local_project_owner.py — LOCAL stages the PROJECT OWNER (researcher) runs.

The project owner holds the key and receives the result. These three functions run
only on the owner's machine — the secret context never leaves it:

  * keygen()  — create the ADDITIVE BFV crypto context; return (secret, public).
    The kit shim 00_keygen.py writes the two halves to disk; only the public half
    is ever published.
  * decrypt() — the ONLY use of the secret key: unpack the BMCT1 result container
    and decrypt each aggregate ciphertext -> labelled int vectors.
  * decode()  — the aggregate sufficient statistics -> the released GWAS result:
    per-SNP allelic chi-square statistic, p-value and odds ratio.

Everything non-linear in the association test — the chi-square ratio, the odds
ratio, the p-value (chi-square survival with 1 degree of freedom) — is computed
HERE, in cleartext, from integer sufficient statistics. Under encryption the
server only summed. This is the "push all the work you can to the local, keep the
encrypted circuit as weak as possible" design (see README.md and the paper's
GWAS-replication experiment).

Chi-square math (matches Duality's `demo-chi2`, PNAS 2020)
---------------------------------------------------------
For each SNP j the aggregate gives ``c1 = Σ_i g_ij`` (minor-allele count) and
``n11 = Σ_i g_ij·y_i`` (minor-allele count in cases); the meta ciphertext gives
``cases = Σ_i y_i`` and ``N``. With ``d = 2N`` total alleles and ``r1 = 2·cases``
alleles in cases, the one-degree-of-freedom allelic chi-square is

    chi2 = (n11·d − c1·r1)² · d / [ c1·(d − c1) · r1·(d − r1) ]

and the p-value is the chi-square-with-1-df survival ``erfc(sqrt(chi2/2))``.

BFV parameters
--------------
poly_modulus_degree = 8192  -> 8192 packing slots; each per-SNP series is chunked
                              into ceil(L/8192) ciphertexts (local_data_owner.SLOT_COUNT).
                              Additive-only, so the SMALLEST practical ring — the
                              least powerful scheme that does the job. FIXED across
                              security levels (as in the additive flagship).
plain_modulus       = 1032193 (a 20-bit batching prime ≡ 1 mod 16384) -> exact
                              integer arithmetic in Z_t. The sufficient statistics
                              are at most 2N (dosage ≤ 2, y ≤ 1), so t = 1032193
                              stays bit-exact for N up to ~500k. FIXED (a function
                              of the value envelope, not security). Byte-identical
                              to the additive flagship's t.

Security levels (`--security {128,192,256}`)
--------------------------------------------
`--security` selects the coeff-modulus chain and nothing else. At FIXED N=8192 the
security level is the q-band: SMALLER Σbits ⇒ MORE secure (correct RLWE behaviour —
the depth-0 noise floor sits in the 256 band, so 128/192 spend surplus modulus).
The chains are byte-identical to the four additive protocols (PGS-safe 3-prime).

  * 128 -> [60,60,60] (Σ=180, lands in the 8192 128-band 153–218)
  * 192 -> [50,50,50] (Σ=150, lands in the 8192 192-band 119–152)
  * 256 -> [45,45,28] (Σ=118, lands in the 8192 256-band ≤118)
"""
from __future__ import annotations

import math
import struct

DEFAULT_POLY_MODULUS_DEGREE = 8192
# 20-bit NTT-friendly batching prime (≡ 1 mod 16384); exact additive BFV in Z_t,
# t > max sufficient statistic (2N). Byte-identical to the additive flagship.
DEFAULT_PLAIN_MODULUS = 1032193
DEFAULT_SECURITY = 128

# BFV packing capacity — must match local_data_owner.SLOT_COUNT (= poly degree).
SLOT_COUNT = 8192

# coeff_mod_bit_sizes chain per requested HE security level, at FIXED N=8192.
# Shared verbatim with the additive flagship (PGS-safe 3-prime chains). Verified
# by real TenSEAL 0.3.16 measurement: each chain decrypts bit-exact and its
# achieved level (Σbits vs the HomomorphicEncryption.org caps) == requested.
SECURITY: dict[int, list[int]] = {
    128: [60, 60, 60],  # Σ=180 -> achieved 128
    192: [50, 50, 50],  # Σ=150 -> achieved 192
    256: [45, 45, 28],  # Σ=118 -> achieved 256
}

_CONTAINER_MAGIC = b"BMCT1\n"  # shared Blind Machine multi-CipherText container v1


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
) -> tuple[bytes, bytes]:
    """Return ``(secret_context_bytes, public_context_bytes)``.

    The secret context carries the secret key; the public context is the same
    context with the secret key removed (``make_context_public``). Additive-only
    protocol => we generate NO relin keys and NO Galois keys (the server never
    multiplies or rotates). ``security`` selects the ``coeff_mod_bit_sizes`` chain.
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
    # No generate_relin_keys()/generate_galois_keys(): additive-only.
    secret_bytes = context.serialize(save_secret_key=True)

    public_context = ts.context_from(secret_bytes)
    public_context.make_context_public()
    # TenSEAL auto-generates relinearization keys when a secret key is present, and
    # serialize() would ship them by default. Strip both relin and Galois keys from
    # the PUBLISHED public context so it genuinely cannot multiply or rotate
    # ciphertexts — the additive-only trust promise, made structural, not documented.
    public_bytes = public_context.serialize(save_relin_keys=False, save_galois_keys=False)

    return secret_bytes, public_bytes


def _unpack_container(blob: bytes) -> "dict[str, bytes]":
    """Recover ``{name: ciphertext_bytes}`` from the server's BMCT1 container."""
    if blob[: len(_CONTAINER_MAGIC)] != _CONTAINER_MAGIC:
        raise ValueError(
            "result artifact is not a Blind Machine multi-ciphertext container (bad magic)"
        )
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
    """Decrypt every aggregate ciphertext in the container -> labelled int vectors.

    This is the ONLY point the secret key is used, and it runs on the owner's
    machine — never on the server. Returns ``{name: [ints]}`` for every name in the
    BMCT1 container (g0.., gy0.., meta).
    """
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context (has no secret key)")

    named = _unpack_container(result_bytes)
    return {
        name: [int(v) for v in ts.bfv_vector_from(context, named[name]).decrypt()]
        for name in named
    }


def _reassemble(plain: dict, prefix: str, n_chunks: int, length: int) -> list[int]:
    """Concatenate ``{prefix}0.. {prefix}{n_chunks-1}`` and truncate to ``length``."""
    out: list[int] = []
    for c in range(n_chunks):
        name = f"{prefix}{c}"
        if name not in plain:
            raise ValueError(f"decrypted result missing chunk '{name}'")
        out.extend(int(v) for v in plain[name])
    if len(out) < length:
        raise ValueError(
            f"reassembled '{prefix}' has {len(out)} slots, fewer than L={length}"
        )
    return out[:length]


def _allelic_chi_square(n11: int, c1: int, cases: int, n: int) -> tuple[float, float, float]:
    """Return ``(chi2, p_value, odds_ratio)`` for one SNP's 2x2 allelic table.

    Reproduces Duality's `demo-chi2` exactly. ``d = 2N`` total alleles,
    ``r1 = 2·cases`` alleles in cases. Monomorphic / degenerate SNPs (no minor
    allele, or all-case / all-control) yield chi2 = 0, p = 1, and an undefined
    odds ratio (returned as NaN).
    """
    d = 2 * n
    r1 = 2 * cases

    # Degenerate table: a constant row/column -> the test is undefined; report the
    # null (chi2 0, p 1), as demo-chi2's guarded denominators do.
    if c1 <= 0 or c1 >= d or r1 <= 0 or r1 >= d:
        chi2 = 0.0
    else:
        num = (n11 * d - c1 * r1) ** 2
        den = c1 * (d - c1) * r1 * (d - r1)
        chi2 = (num * d) / den
        if chi2 < 0:
            chi2 = 0.0

    # Chi-square survival with 1 degree of freedom: P(χ²_1 > x) = erfc(sqrt(x/2)).
    p_value = math.erfc(math.sqrt(chi2 / 2.0))

    # Allelic odds ratio = (a·d)/(b·c) on the 2x2 table
    # a = minor in cases (n11), b = major in cases (r1 - n11),
    # c = minor in controls (c1 - n11), d_cell = major in controls (d - r1 - c1 + n11).
    a = n11
    b = r1 - n11
    c = c1 - n11
    d_cell = d - r1 - c1 + n11
    numer = a * d_cell
    denom = b * c
    # Zero-denominator (a zero cell in the 2x2 table): the conventional odds ratio is
    # +inf (e.g. all minor alleles in cases), and 0/0 is undefined (NaN).
    if denom == 0:
        odds_ratio = float("nan") if numer == 0 else float("inf")
    else:
        odds_ratio = numer / denom

    return chi2, p_value, odds_ratio


def decode(plain: dict, length: int) -> dict:
    """Reassemble the sufficient statistics and compute the per-SNP GWAS result.

    ``plain`` is the ``{name: [ints]}`` map from ``decrypt``. Reassembles the
    chunked per-SNP series (Σg, Σgy), reads ``[#cases, N]`` from the meta vector,
    and computes the allelic chi-square, p-value and odds ratio per SNP, all in
    cleartext.
    """
    if "meta" not in plain:
        raise ValueError("decrypted result missing 'meta' (case count + N)")
    meta = plain["meta"]
    if len(meta) < 2:
        raise ValueError(f"meta vector has {len(meta)} slots, expected >= 2 ([cases, N])")
    cases = int(meta[0])
    n_contributors = int(meta[1])
    if n_contributors <= 0:
        raise ValueError(f"meta sentinel decoded to N={n_contributors}; expected N > 0")
    if not (0 <= cases <= n_contributors):
        raise ValueError(
            f"case count {cases} outside [0, N={n_contributors}]; result is corrupt"
        )
    # Exactness envelope: every sufficient statistic is <= 2N, which must stay below
    # the plaintext modulus, else a coordinate wrapped mod t silently. Refuse rather
    # than return a corrupt statistic.
    if 2 * n_contributors >= DEFAULT_PLAIN_MODULUS:
        raise ValueError(
            f"cohort N={n_contributors} exceeds the exact envelope (2N must be < "
            f"plaintext modulus {DEFAULT_PLAIN_MODULUS}); a coordinate may have wrapped mod t"
        )

    n_chunks = (length + SLOT_COUNT - 1) // SLOT_COUNT if length > 0 else 1
    sum_g = _reassemble(plain, "g", n_chunks, length)
    sum_gy = _reassemble(plain, "gy", n_chunks, length)

    controls = n_contributors - cases

    chi_square: list[float] = []
    p_value: list[float] = []
    odds_ratio: list[float] = []
    neg_log10_p: list[float] = []
    for j in range(length):
        chi2, p, orat = _allelic_chi_square(sum_gy[j], sum_g[j], cases, n_contributors)
        chi_square.append(chi2)
        p_value.append(p)
        odds_ratio.append(orat)
        neg_log10_p.append(float("inf") if p <= 0.0 else -math.log10(p))

    return {
        "protocol": "gwas_chi_square",
        "coordinates_length": length,
        "n_contributors": n_contributors,
        "cases": cases,
        "controls": controls,
        "minor_allele_count": sum_g,          # c1 per SNP
        "minor_allele_count_in_cases": sum_gy,  # n11 per SNP
        "chi_square": chi_square,
        "p_value": p_value,
        "neg_log10_p": neg_log10_p,
        "odds_ratio": odds_ratio,
    }
