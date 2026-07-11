#!/usr/bin/env python3
from __future__ import annotations

import struct
from collections.abc import Sequence


VALUE_DOMAIN = (0, 1, 2)
MISSING_ENCODED_AS = 0
SENTINEL_VALUE = 1
PAIR_ORDER = ("a", "b")
_CONTAINER_MAGIC = b"BMCT1\n"


def adjacent_pairs(pair_count: int) -> list[tuple[int, int]]:
    if pair_count <= 0:
        raise ValueError(f"pair_count must be positive, got {pair_count}")
    return [(index, index + 1) for index in range(pair_count)]


def _pack(named_blobs: dict[str, bytes], order: tuple[str, ...] = PAIR_ORDER) -> bytes:
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(order))
    for name in order:
        blob = named_blobs[name]
        name_bytes = name.encode("utf-8")
        out += struct.pack(">B", len(name_bytes)) + name_bytes
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def _coerce_pair(pair, index: int) -> tuple[int, int]:
    if not isinstance(pair, Sequence) or isinstance(pair, (str, bytes)):
        raise ValueError(f"pair {index}: expected a two-element index pair")
    if len(pair) != 2:
        raise ValueError(f"pair {index}: expected 2 indexes, got {len(pair)}")
    left, right = pair
    if not isinstance(left, int) or not isinstance(right, int):
        raise ValueError(f"pair {index}: indexes must be integers")
    if left < 0 or right < 0:
        raise ValueError(f"pair {index}: indexes must be non-negative")
    if left == right:
        raise ValueError(f"pair {index}: indexes must refer to two distinct variants")
    return int(left), int(right)


def validate_pairs(raw_pairs, pair_count: int) -> list[tuple[int, int]]:
    if raw_pairs is None:
        return adjacent_pairs(pair_count)
    if not isinstance(raw_pairs, list):
        raise ValueError("raw 'pairs' must be a JSON list of index pairs")
    pairs = [_coerce_pair(pair, index) for index, pair in enumerate(raw_pairs)]
    if len(pairs) != pair_count:
        raise ValueError(
            f"pair list length {len(pairs)} does not match published pair_count {pair_count}"
        )
    return pairs


def encode_genotype(raw: list[int | None], minimum_length: int) -> list[int]:
    if not isinstance(raw, list):
        raise ValueError("raw genotype must be a JSON list")
    checked: list[int] = []
    for index, value in enumerate(raw):
        if value is None:
            checked.append(MISSING_ENCODED_AS)
        elif value in VALUE_DOMAIN:
            checked.append(int(value))
        else:
            raise ValueError(f"coordinate {index}: dosage {value!r} not in {VALUE_DOMAIN}")
    if len(checked) < minimum_length:
        checked.extend([MISSING_ENCODED_AS] * (minimum_length - len(checked)))
    return checked


def _raw_genotype_and_pairs(raw, pair_count: int) -> tuple[list[int | None], list[tuple[int, int]]]:
    if isinstance(raw, list):
        return raw, adjacent_pairs(pair_count)
    if not isinstance(raw, dict):
        raise ValueError("raw LD input must be a genotype list or an object")
    genotype = raw.get("genotype", raw.get("vector"))
    if genotype is None:
        raise ValueError("raw LD input object needs a 'genotype' or 'vector' key")
    return genotype, validate_pairs(raw.get("pairs"), pair_count)


def encode(raw, length: int) -> dict[str, list[int]]:
    """Encode genotype input into pair-aligned vectors.

    `length` is the public pair count. A plain genotype list uses adjacent pairs;
    an object may provide `pairs: [[left, right], ...]` for a bounded pair list.
    """
    pair_count = length
    genotype, pairs = _raw_genotype_and_pairs(raw, pair_count)
    max_index = max(max(left, right) for left, right in pairs)
    checked = encode_genotype(genotype, minimum_length=max_index + 1)
    return {
        "a": [checked[left] for left, _right in pairs],
        "b": [checked[right] for _left, right in pairs],
    }


def append_sentinel(values: list[int]) -> list[int]:
    return list(values) + [SENTINEL_VALUE]


def encrypt(public_context_bytes: bytes, encoded: dict[str, list[int]]) -> bytes:
    import tenseal as ts

    if set(encoded) != set(PAIR_ORDER):
        raise ValueError(f"encoded must contain {PAIR_ORDER}")
    if len(encoded["a"]) != len(encoded["b"]):
        raise ValueError("encoded 'a' and 'b' vectors must have the same length")
    context = ts.context_from(public_context_bytes)
    encrypted = {
        name: ts.bfv_vector(context, append_sentinel(encoded[name])).serialize()
        for name in PAIR_ORDER
    }
    return _pack(encrypted)
