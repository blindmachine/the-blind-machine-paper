#!/usr/bin/env python3
"""local_data_owner.py — LOCAL stages each DATA OWNER (contributor) runs.

`gwas_chi_square` reproduces the **Chi-Square GWAS** protocol of Blatt, Gusev,
Polyakov & Goldwasser, *"Secure large-scale genome-wide association studies using
homomorphic encryption"*, PNAS 2020 (doi:10.1073/pnas.1918257117) — the same
one-degree-of-freedom **allelic association test** their `demo-chi2` prototype
computes — but under The Blind Machine's multiparty trust model and with the
**least powerful HE scheme that still does the job: additive-only BFV**.

The efficiency idea, made concrete here:

    In the Duality prototype every individual's genotype AND phenotype are
    encrypted, and the *server* forms the cross term g·y with a ciphertext×
    ciphertext multiply. In our model each data owner OWNS both their genotype
    vector g and their phenotype y, so the product g·y is formed **locally, in
    cleartext**, before anything is encrypted. The server is then left with a
    single homomorphic operation — ADDITION — exactly the flagship
    `allele_frequency_count` circuit. No ct×ct multiply, no relinearization keys,
    no Galois keys: the whole per-SNP association test rides on additive BFV.

A data owner turns their own raw ``{"genotype": [...], "phenotype": y}`` record
into ONE packed uploadable ciphertext, on their own machine, using the project's
PUBLIC context only. Nothing but that blob (and the already-public context) ever
leaves the machine; the secret key is never touched here.

  * encode()  — a ``{"genotype": [...], "phenotype": y}`` record -> ``{"g", "y"}``,
    where ``g`` is the validated, zero-padded length-L alt-allele dosage vector and
    ``y in {0,1}`` is the case/control phenotype scalar.
  * encrypt() — encoded ``{"g", "y"}`` -> ONE packed BMCT1 blob co-packing the
    per-SNP sufficient-statistic ciphertexts the server will additively fold:
    ``g`` chunks (-> Σ_i g_ij, the minor-allele count per SNP) and ``g·y`` chunks
    (-> Σ_i g_ij·y_i, the minor-allele count in cases per SNP), plus a tiny
    ``meta`` = [y, 1] (-> [Σ_i y_i = #cases, N]).

Why the per-SNP series is CHUNKED: a BFV ciphertext packs at most
``POLY_MODULUS_DEGREE`` (= 8192) plaintext slots, so an L-SNP series is split into
``ceil(L / 8192)`` ciphertexts — mirroring the Duality prototype, which likewise
"batches 4,096 SNPs at a time" for the chi-square test (PNAS 2020). The server
folds each chunk position across contributors, so pairing is preserved regardless
of the order the ciphertexts arrive in.

The project owner's stages (keygen, decrypt, decode) live in
local_project_owner.py; the blind server stage (compute) lives in server.py.
"""
from __future__ import annotations

import struct

GENOTYPE_VALUE_DOMAIN = (0, 1, 2)
MISSING_ENCODED_AS = 0
# Case/control phenotype coding: 0 = control, 1 = case. Fixed — the allelic
# chi-square test is a case/control test; a quantized trait is out of scope for
# this bundle (that is the `genotype_phenotype_covariance` / regression path).
PHENOTYPE_VALUE_DOMAIN = (0, 1)

SENTINEL_VALUE = 1

# The BFV packing capacity (= poly_modulus_degree in local_project_owner.keygen).
# Each per-SNP series is chunked into ceil(L / SLOT_COUNT) ciphertexts of <= this
# many slots. MUST stay in lockstep with local_project_owner.DEFAULT_POLY_MODULUS_DEGREE.
SLOT_COUNT = 8192

# Container framing for the packed per-contributor ciphertexts inside one
# uploadable blob. This is the shared Blind Machine multi-CipherText container v1 —
# byte-identical to the format server.py and genotype_phenotype_covariance use.
# Each bundle carries its own verbatim copy (bundles are self-contained).
_CONTAINER_MAGIC = b"BMCT1\n"  # Blind Machine multi-CipherText container v1


def encode_genotype(raw: list[int | None], length: int) -> list[int]:
    """Return a validated, zero-padded, length-``length`` dosage vector.

    The raw input is an alt-allele dosage vector ``g in {0,1,2}^L`` over the
    published SNP coordinate definition. Missing calls (``None``) encode as 0;
    every present call is validated in {0,1,2}; the vector is zero-padded to length
    L (rejected if longer). VERBATIM flagship genotype encoding.

    Raises ValueError on an out-of-domain call or an over-length input.
    """
    if length <= 0:
        raise ValueError(f"length must be positive, got {length}")
    if len(raw) > length:
        raise ValueError(
            f"raw genotype length {len(raw)} exceeds coordinate length {length}"
        )

    encoded: list[int] = []
    for index, call in enumerate(raw):
        if call is None:
            encoded.append(MISSING_ENCODED_AS)
            continue
        if call not in GENOTYPE_VALUE_DOMAIN:
            raise ValueError(
                f"coordinate {index}: dosage {call!r} not in {GENOTYPE_VALUE_DOMAIN}"
            )
        encoded.append(int(call))

    encoded.extend([MISSING_ENCODED_AS] * (length - len(encoded)))
    return encoded


def encode_phenotype(y: int) -> int:
    """Validate and return the binary case/control phenotype scalar.

    Unlike the covariance protocol (which broadcasts y so the *server* can multiply
    g·y), here y stays a scalar: the data owner multiplies g·y LOCALLY, so the
    server only has to add. Raises ValueError if y is missing or not in {0,1}.
    """
    if y is None:
        raise ValueError(
            "phenotype is missing (null); a case/control contributor must supply "
            "a phenotype (0 = control, 1 = case)"
        )
    if y not in PHENOTYPE_VALUE_DOMAIN:
        raise ValueError(f"phenotype {y!r} not in published domain {PHENOTYPE_VALUE_DOMAIN}")
    return int(y)


def encode(raw: dict, length: int) -> dict:
    """Encode a ``{"genotype": [...], "phenotype": y}`` record into ``{"g", "y"}``.

    ``g`` = validated length-L dosage vector; ``y`` = the case/control scalar.
    """
    if not isinstance(raw, dict):
        raise ValueError(
            "raw gwas_chi_square input must be a JSON object with 'genotype' and "
            "'phenotype' keys"
        )
    if "genotype" not in raw or "phenotype" not in raw:
        raise ValueError("raw input needs both 'genotype' and 'phenotype' keys")

    genotype = raw["genotype"]
    if not isinstance(genotype, list):
        raise ValueError("raw 'genotype' must be a JSON list")

    g = encode_genotype(genotype, length)
    y = encode_phenotype(raw["phenotype"])
    return {"g": g, "y": y}


def _chunk(vector: list[int], size: int = SLOT_COUNT) -> list[list[int]]:
    """Split ``vector`` into consecutive chunks of at most ``size`` slots.

    An L-SNP series becomes ceil(L/size) ciphertext-sized chunks. All contributors
    share the same L, hence the same chunk boundaries, so the server can fold each
    chunk position across contributors.
    """
    if not vector:
        return [[]]
    return [vector[i : i + size] for i in range(0, len(vector), size)]


def _encrypt_vector(context, plaintext: list[int]) -> bytes:
    """BFV-encrypt one integer plaintext vector -> serialized ciphertext."""
    import tenseal as ts

    return ts.bfv_vector(context, plaintext).serialize()


def pack_container(named_blobs: "dict[str, bytes]", order: list[str]) -> bytes:
    """Pack named ciphertexts into one deterministic BMCT1 container blob.

    Layout: MAGIC, a uint8 count, then for each name in ``order`` a length-prefixed
    name and a length-prefixed blob. Fixed order => byte-deterministic and
    self-describing. Same framing as ``server.pack_results`` and the covariance
    bundle's ``pack_pair``.
    """
    if len(order) > 255:
        raise ValueError(
            f"BMCT1 container holds at most 255 named ciphertexts, got {len(order)} "
            f"(L too large for one contribution; split the SNP set into blocks)"
        )
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(order))
    for name in order:
        blob = named_blobs[name]
        name_bytes = name.encode("utf-8")
        out += struct.pack(">B", len(name_bytes)) + name_bytes
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def container_names(length: int) -> list[str]:
    """The canonical, deterministic name list for a length-L contribution.

    ``g0..g{C-1}`` then ``gy0..gy{C-1}`` (C = number of chunks) then ``meta``.
    Shared verbatim by encrypt / server.compute / decode so every side agrees on
    the container shape without embedding it in the ciphertext.
    """
    n_chunks = (length + SLOT_COUNT - 1) // SLOT_COUNT if length > 0 else 1
    return (
        [f"g{c}" for c in range(n_chunks)]
        + [f"gy{c}" for c in range(n_chunks)]
        + ["meta"]
    )


def encrypt(public_context_bytes: bytes, encoded: dict) -> bytes:
    """Return ONE packed BMCT1 blob of additive sufficient-statistic ciphertexts.

    ``encoded`` is ``{"g": [L ints in {0,1,2}], "y": 0|1}``. The cross term g·y is
    formed HERE, in cleartext (this owner holds both g and y), so the server never
    multiplies. Each per-SNP series (g and g·y) is chunked into <= SLOT_COUNT-slot
    ciphertexts; a tiny ``meta`` = [y, 1] rides along so the fold recovers the
    exact case count and contributor count N. Uses the PUBLIC context only; the
    secret key is not touched here.
    """
    import tenseal as ts

    if not isinstance(encoded, dict) or "g" not in encoded or "y" not in encoded:
        raise ValueError("encoded input must be a JSON object with 'g' and 'y'")

    g = list(encoded["g"])
    y = int(encoded["y"])
    if y not in PHENOTYPE_VALUE_DOMAIN:
        raise ValueError(f"phenotype {y!r} not in published domain {PHENOTYPE_VALUE_DOMAIN}")

    # THE local multiply: g·y in cleartext (y in {0,1}, so gy is g on cases, 0 on
    # controls). This is what lets the server stay additive-only.
    gy = [gj * y for gj in g]

    context = ts.context_from(public_context_bytes)

    g_chunks = _chunk(g)
    gy_chunks = _chunk(gy)

    named: dict[str, bytes] = {}
    for c, chunk in enumerate(g_chunks):
        named[f"g{c}"] = _encrypt_vector(context, chunk)
    for c, chunk in enumerate(gy_chunks):
        named[f"gy{c}"] = _encrypt_vector(context, chunk)
    # meta = [cases-contribution y, contributor-count sentinel 1] -> folds to
    # [#cases, N]. The sentinel is a live contributor-count integrity check (a
    # dropped upload lowers N), NOT a MAC.
    named["meta"] = _encrypt_vector(context, [y, SENTINEL_VALUE])

    return pack_container(named, container_names(len(g)))
