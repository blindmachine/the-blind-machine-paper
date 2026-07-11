#!/usr/bin/env python3
from __future__ import annotations

import struct
from collections.abc import Iterable
from typing import Protocol


PAIR_ORDER = ("a", "b")
MOMENT_ORDER = ("sum_a", "sum_b", "sum_a2", "sum_b2", "sum_ab")
_CONTAINER_MAGIC = b"BMCT1\n"


class Evaluator(Protocol):
    def add(self, a, b): ...
    def mul(self, a, b): ...


class BFVEvaluator:
    def __init__(self, context) -> None:
        self.context = context

    def add(self, a, b):
        return a + b

    def mul(self, a, b):
        return a * b

    def load(self, blob: bytes):
        import tenseal as ts

        return ts.bfv_vector_from(self.context, blob)


def _pack(named_blobs: dict[str, bytes], order: tuple[str, ...]) -> bytes:
    out = bytearray(_CONTAINER_MAGIC)
    out += struct.pack(">B", len(order))
    for name in order:
        blob = named_blobs[name]
        name_bytes = name.encode("utf-8")
        out += struct.pack(">B", len(name_bytes)) + name_bytes
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out)


def _unpack(blob: bytes) -> dict[str, bytes]:
    if blob[: len(_CONTAINER_MAGIC)] != _CONTAINER_MAGIC:
        raise ValueError("bad BMCT1 container magic")
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


def aggregate(pairs: Iterable[tuple], evaluator: Evaluator) -> dict:
    acc = None
    for a, b in pairs:
        current = {
            "sum_a": a,
            "sum_b": b,
            "sum_a2": evaluator.mul(a, a),
            "sum_b2": evaluator.mul(b, b),
            "sum_ab": evaluator.mul(a, b),
        }
        if acc is None:
            acc = current
        else:
            for name in MOMENT_ORDER:
                acc[name] = evaluator.add(acc[name], current[name])
    if acc is None:
        raise ValueError("aggregate needs at least one input")
    return acc


def unpack_pair(blob: bytes) -> tuple[bytes, bytes]:
    named = _unpack(blob)
    if "a" not in named or "b" not in named:
        raise ValueError(f"expected packed (a, b) container, found {sorted(named)}")
    return named["a"], named["b"]


def compute(inputs: list[bytes], public_context: bytes) -> bytes:
    import tenseal as ts

    context = ts.context_from(public_context)
    if context.is_private():
        raise ValueError("compute stage received a context holding a secret key")
    if not inputs:
        raise ValueError("compute needs at least one input")

    evaluator = BFVEvaluator(context)
    pairs = []
    for blob in inputs:
        a_bytes, b_bytes = unpack_pair(blob)
        pairs.append((evaluator.load(a_bytes), evaluator.load(b_bytes)))
    results = aggregate(pairs, evaluator)
    return _pack({name: results[name].serialize() for name in MOMENT_ORDER}, MOMENT_ORDER)
