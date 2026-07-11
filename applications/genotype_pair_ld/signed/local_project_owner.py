#!/usr/bin/env python3
from __future__ import annotations

import math
import struct


DEFAULT_POLY_MODULUS_DEGREE = 16384
DEFAULT_PLAIN_MODULUS = 786433
DEFAULT_SECURITY = 128
SECURITY = {
    128: [60, 60, 60, 60, 60, 60],
    192: [60, 60, 60, 60],
    256: [60, 40, 40, 60],
}
MOMENT_ORDER = ("sum_a", "sum_b", "sum_a2", "sum_b2", "sum_ab")
_CONTAINER_MAGIC = b"BMCT1\n"


def keygen(
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE,
    plain_modulus: int = DEFAULT_PLAIN_MODULUS,
    security: int = DEFAULT_SECURITY,
    coeff_mod_bit_sizes: tuple[int, ...] | None = None,
) -> tuple[bytes, bytes]:
    import tenseal as ts

    if coeff_mod_bit_sizes is None:
        if security not in SECURITY:
            raise ValueError(f"security must be one of {sorted(SECURITY)}")
        coeff_mod_bit_sizes = tuple(SECURITY[security])
    context = ts.context(
        ts.SCHEME_TYPE.BFV,
        poly_modulus_degree=poly_modulus_degree,
        plain_modulus=plain_modulus,
        coeff_mod_bit_sizes=list(coeff_mod_bit_sizes),
    )
    context.generate_relin_keys()
    secret_bytes = context.serialize(save_secret_key=True)
    public_context = ts.context_from(secret_bytes)
    public_context.make_context_public()
    return secret_bytes, public_context.serialize()


def unpack_results(blob: bytes) -> dict[str, bytes]:
    if blob[: len(_CONTAINER_MAGIC)] != _CONTAINER_MAGIC:
        raise ValueError("bad BMCT1 result container magic")
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


def decrypt(secret_context_bytes: bytes, result_bytes: bytes) -> dict[str, list[int]]:
    import tenseal as ts

    context = ts.context_from(secret_context_bytes)
    if not context.is_private():
        raise ValueError("decrypt stage needs the secret context")
    named = unpack_results(result_bytes)
    return {
        name: [int(value) for value in ts.bfv_vector_from(context, named[name]).decrypt()]
        for name in MOMENT_ORDER
    }


def _split(vector: list[int], pair_count: int, name: str) -> tuple[list[int], int]:
    expected = pair_count + 1
    if len(vector) != expected:
        raise ValueError(f"{name}: expected {expected} slots, got {len(vector)}")
    return [int(value) for value in vector[:pair_count]], int(vector[pair_count])


def _r_and_r2(covariance: float, variance_a: float, variance_b: float) -> tuple[float | None, float | None]:
    denominator = variance_a * variance_b
    if denominator <= 0:
        return None, None
    r = covariance / math.sqrt(denominator)
    return r, r * r


def decode(plain: dict[str, list[int]], length: int) -> dict:
    """Decode aggregate LD moments.

    `length` is the public pair count. The result includes both compact moment
    names (`sum_a`) and explicit genotype names (`sum_g_a`) for compatibility.
    """
    pair_count = length
    moments: dict[str, list[int]] = {}
    sentinels: dict[str, int] = {}
    for name in MOMENT_ORDER:
        values, sentinel = _split(plain[name], pair_count, name)
        moments[name] = values
        sentinels[name] = sentinel
    if len(set(sentinels.values())) != 1:
        raise ValueError(f"sentinel mismatch: {sentinels}")
    n = next(iter(sentinels.values()))
    if n <= 0:
        raise ValueError(f"sentinel decoded to N={n}; expected N > 0")

    mean_a: list[float] = []
    mean_b: list[float] = []
    var_a: list[float] = []
    var_b: list[float] = []
    covariance: list[float] = []
    r_values: list[float | None] = []
    r2_values: list[float | None] = []
    for sa, sb, sa2, sb2, sab in zip(
        moments["sum_a"],
        moments["sum_b"],
        moments["sum_a2"],
        moments["sum_b2"],
        moments["sum_ab"],
    ):
        ma = sa / n
        mb = sb / n
        va = sa2 / n - ma**2
        vb = sb2 / n - mb**2
        cov = sab / n - ma * mb
        r, r2 = _r_and_r2(cov, va, vb)
        mean_a.append(ma)
        mean_b.append(mb)
        var_a.append(va)
        var_b.append(vb)
        covariance.append(cov)
        r_values.append(r)
        r2_values.append(r2)

    return {
        "protocol": "genotype_pair_ld",
        "pair_count": pair_count,
        "n_contributors": n,
        **moments,
        "sum_g_a": moments["sum_a"],
        "sum_g_b": moments["sum_b"],
        "sum_g_a2": moments["sum_a2"],
        "sum_g_b2": moments["sum_b2"],
        "sum_g_a_g_b": moments["sum_ab"],
        "mean_a": mean_a,
        "mean_b": mean_b,
        "mean_g_a": mean_a,
        "mean_g_b": mean_b,
        "var_a": var_a,
        "var_b": var_b,
        "variance_g_a": var_a,
        "variance_g_b": var_b,
        "covariance": covariance,
        "r": r_values,
        "r2": r2_values,
    }
