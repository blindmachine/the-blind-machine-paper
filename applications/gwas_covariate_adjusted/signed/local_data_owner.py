#!/usr/bin/env python3
"""local_data_owner.py — LOCAL stages each DATA OWNER (contributor) runs.

`gwas_covariate_adjusted` reproduces the **covariate-adjusted GWAS** of Blatt,
Gusev, Polyakov & Goldwasser, PNAS 2020 (doi:10.1073/pnas.1918257117) — their
Logistic Regression Approximation (LRA), a semi-parallel score test (after Sikorska
et al.) that adjusts each SNP's case/control association for covariates (sex, age,
age²) — but, like `gwas_chi_square`, with the **least powerful HE scheme that does
the job: additive-only BFV**.

The move that makes covariate adjustment additive-only: each data owner holds their
own genotype `g`, phenotype `y`, AND covariates `x = [1, sex, age, age²]`, so every
product a semi-parallel GWAS needs — the covariate Gram matrix `xxᵀ`, the covariate/
phenotype term `x·y`, and the per-SNP covariate/genotype cross term `x·g` — is formed
**locally, in the clear**, before encryption. The server only ADDS. The project
owner decrypts the (fixed-point) sufficient statistics, inverts the tiny k×k
covariate matrix in the clear, and runs the per-SNP score test — exactly the
semi-parallel decomposition (fit covariates once, then O(k) per SNP).

Because the covariates are continuous, they are encoded in **fixed point** (scaled
by `SCALE`), so the reproduction is highly concordant with the cleartext regression
(R² ≈ 1.00, matching the paper's own R² = 1.00 vs exact logistic) rather than
bit-exact. Genotype/phenotype terms stay exact integers.

  * encode()  — a ``{"genotype":[...],"phenotype":0|1,"covariates":[...]}`` record
    -> validated dosage vector, phenotype, and scaled integer covariate vector.
  * encrypt() — the encoded record -> ONE packed BMCT1 blob of the additive
    sufficient-statistic ciphertexts the server folds.

The project owner's stages (keygen, decrypt, decode) live in
local_project_owner.py; the blind server stage (compute) lives in server.py.
"""
from __future__ import annotations

import struct

GENOTYPE_VALUE_DOMAIN = (0, 1, 2)
MISSING_ENCODED_AS = 0
PHENOTYPE_VALUE_DOMAIN = (0, 1)
SENTINEL_VALUE = 1

# Fixed-point scale for the continuous covariates (matches local_project_owner).
# Covariate values must be NORMALIZED to [-1, 1] (intercept 1, sex 0/1, age & age²
# are the paper's normalized covariates); scaled to round(SCALE * x). SCALE=1024
# gives ~3-decimal covariate precision and -log10(p) concordance R² ≈ 0.99997 vs the
# cleartext regression on the demo data.
SCALE = 1024

# Covariates MUST be normalized to |x| <= this bound. This is what keeps the
# covariate Gram exact in Z_t: the intercept diagonal Σ SCALE² already reaches
# SCALE²·N, so any covariate scaled beyond SCALE would only push a Gram entry higher
# and, for a large cohort, wrap the plaintext modulus SILENTLY — corrupting every
# SNP's covariate-adjusted result. Enforcing the bound here turns that silent
# corruption into a clean, local, contributor-visible error (a common mistake is
# forgetting to normalize age: pass 0.65, not 65).
COVARIATE_ABS_LIMIT = 1.0

# BFV packing capacity (= poly_modulus_degree in local_project_owner.keygen).
SLOT_COUNT = 8192

_CONTAINER_MAGIC = b"BMCT1\n"  # shared Blind Machine multi-CipherText container v1


def encode_genotype(raw: list[int | None], length: int) -> list[int]:
    """Return a validated, zero-padded, length-``length`` dosage vector (VERBATIM
    flagship genotype encoding). Missing calls -> 0; each present call in {0,1,2}."""
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    if len(raw) > length:
        raise ValueError(f"raw genotype length {len(raw)} exceeds coordinate length {length}")
    encoded: list[int] = []
    for index, call in enumerate(raw):
        if call is None:
            encoded.append(MISSING_ENCODED_AS)
            continue
        if call not in GENOTYPE_VALUE_DOMAIN:
            raise ValueError(f"coordinate {index}: dosage {call!r} not in {GENOTYPE_VALUE_DOMAIN}")
        encoded.append(int(call))
    encoded.extend([MISSING_ENCODED_AS] * (length - len(encoded)))
    return encoded


def encode_covariates(covariates: list[float], covariate_count: int) -> list[int]:
    """Return the fixed-point integer design-row ``x = [1, *covariates]`` (length k).

    The leading intercept is always 1 (scaled to SCALE). Each covariate is scaled
    by SCALE and rounded. ``covariate_count`` = k = 1 + number of covariates.
    """
    n_cov = covariate_count - 1
    if len(covariates) != n_cov:
        raise ValueError(
            f"expected {n_cov} covariates (k={covariate_count} includes the "
            f"intercept), got {len(covariates)}"
        )
    x = [SCALE]  # intercept 1, scaled
    for index, c in enumerate(covariates):
        value = float(c)
        if not (-COVARIATE_ABS_LIMIT <= value <= COVARIATE_ABS_LIMIT):
            raise ValueError(
                f"covariate {index} = {value!r} is outside the normalized range "
                f"[-{COVARIATE_ABS_LIMIT}, {COVARIATE_ABS_LIMIT}]; normalize covariates "
                f"(e.g. age in [0,1], not years) before contributing — an out-of-range "
                f"covariate would silently overflow the plaintext modulus"
            )
        x.append(int(round(SCALE * value)))
    return x


def encode(raw: dict, length: int, covariate_count: int = 4) -> dict:
    """Encode a ``{"genotype","phenotype","covariates"}`` record.

    Returns ``{"g": [L dosages], "y": 0|1, "x": [k scaled-int covariates]}``.
    Defaults to k=4 (intercept + 3 covariates: sex, age, age²), matching the LRA.
    """
    if not isinstance(raw, dict):
        raise ValueError("raw input must be a JSON object with genotype/phenotype/covariates")
    for key in ("genotype", "phenotype", "covariates"):
        if key not in raw:
            raise ValueError(f"raw input needs a '{key}' key")
    if not isinstance(raw["genotype"], list) or not isinstance(raw["covariates"], list):
        raise ValueError("'genotype' and 'covariates' must be JSON lists")
    y = raw["phenotype"]
    if y not in PHENOTYPE_VALUE_DOMAIN:
        raise ValueError(f"phenotype {y!r} not in {PHENOTYPE_VALUE_DOMAIN}")
    g = encode_genotype(raw["genotype"], length)
    x = encode_covariates(raw["covariates"], covariate_count)
    return {"g": g, "y": int(y), "x": x}


def _chunk(vector: list[int], size: int = SLOT_COUNT) -> list[list[int]]:
    if not vector:
        return [[]]
    return [vector[i : i + size] for i in range(0, len(vector), size)]


def container_names(length: int, covariate_count: int) -> list[str]:
    """Canonical, deterministic container name list.

    ``scalars`` (the covariate Gram upper-triangle + x·y + y² + N sentinel), then
    ``xg{c}_{ch}`` (per covariate c, the x_c·g per-SNP series, chunked), then
    ``gy_{ch}`` and ``gg_{ch}`` (per-SNP Σ g·y and Σ g² series, chunked)."""
    n_chunks = (length + SLOT_COUNT - 1) // SLOT_COUNT if length > 0 else 1
    names = ["scalars"]
    for c in range(covariate_count):
        names += [f"xg{c}_{ch}" for ch in range(n_chunks)]
    names += [f"gy_{ch}" for ch in range(n_chunks)]
    names += [f"gg_{ch}" for ch in range(n_chunks)]
    return names


def _scalars_vector(x: list[int], y: int) -> list[int]:
    """Pack this contributor's constant-size sufficient statistics into one vector.

    Layout: the k(k+1)/2 upper-triangular entries of x·xᵀ (scaled SCALE²), then the
    k entries of x·y (scaled SCALE), then y² (integer), then the append-1 sentinel
    (folds to N). Mixed scales are undone per-slot in decode."""
    k = len(x)
    out: list[int] = []
    for a in range(k):
        for b in range(a, k):
            out.append(x[a] * x[b])       # xxᵀ upper triangle, scale SCALE²
    for a in range(k):
        out.append(x[a] * y)              # x·y, scale SCALE
    out.append(y * y)                     # y², integer
    out.append(SENTINEL_VALUE)            # -> N
    return out


def pack_container(named_blobs: "dict[str, bytes]", order: list[str]) -> bytes:
    if len(order) > 255:
        raise ValueError(
            f"BMCT1 container holds at most 255 named ciphertexts, got {len(order)} "
            f"(too many covariates × SNP chunks for one contribution; split the SNP set)"
        )
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(order))
    for name in order:
        blob = named_blobs[name]
        nb = name.encode("utf-8")
        out += struct.pack(">B", len(nb)) + nb
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def encrypt(public_context_bytes: bytes, encoded: dict) -> bytes:
    """Return ONE packed BMCT1 blob of additive sufficient-statistic ciphertexts.

    ``encoded`` = ``{"g":[L], "y":0|1, "x":[k scaled ints]}``. Every product is
    formed HERE, in the clear (this owner holds g, y and x): the covariate Gram
    upper triangle x·xᵀ, x·y, y², and per SNP x_c·g, g·y, g². The server only adds.
    Uses the PUBLIC context only; the secret key is not touched here.
    """
    import tenseal as ts

    g, y, x = list(encoded["g"]), int(encoded["y"]), list(encoded["x"])
    k = len(x)
    context = ts.context_from(public_context_bytes)

    def enc(vec):
        return ts.bfv_vector(context, vec).serialize()

    named: dict[str, bytes] = {"scalars": enc(_scalars_vector(x, y))}

    g_chunks = _chunk(g)
    gy_chunks = _chunk([gj * y for gj in g])
    gg_chunks = _chunk([gj * gj for gj in g])
    for c in range(k):
        xc = x[c]
        xg_c = [gj * xc for gj in g]          # x_c · g_j, scale SCALE
        for ch, chunk in enumerate(_chunk(xg_c)):
            named[f"xg{c}_{ch}"] = enc(chunk)
    for ch, chunk in enumerate(gy_chunks):
        named[f"gy_{ch}"] = enc(chunk)
    for ch, chunk in enumerate(gg_chunks):
        named[f"gg_{ch}"] = enc(chunk)

    return pack_container(named, container_names(len(g), k))
