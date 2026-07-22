#!/usr/bin/env python3
"""_packing.py — length-prefixed byte framing shared by the author role files.

The `aggregate` scenario's stage shims move ONE blob per contributor
(`20_encrypt.py --out`) and ONE result blob (`30_compute_encrypted.py --out`).
This application needs to move a *list* of ciphertexts through those single-blob
slots:

  * a data owner's genotype for a large model spans K chunk-ciphertexts
    (TenSEAL packs at most N/2 = 4096 dosages per BFV ciphertext), and
  * the server returns N per-individual scalar ciphertexts (one PRS each).

So both the per-contributor upload and the server result are a `frame(...)` of
several serialized ciphertexts. The framing is deliberately trivial and
crypto-free — an 8-byte big-endian length prefix per item — so a reviewer can
see there is no hidden state: `unframe(frame(xs)) == xs` for any list of byte
strings. It is covered by the bundle digest like every other signed file.
"""
from __future__ import annotations

import struct

_HEADER = struct.Struct(">Q")  # 8-byte big-endian unsigned length prefix


def frame(items: list[bytes]) -> bytes:
    """Concatenate ``items`` as ``(len, bytes)*`` — order-preserving, unambiguous."""
    out = bytearray()
    for item in items:
        out += _HEADER.pack(len(item))
        out += item
    return bytes(out)


def unframe(blob: bytes) -> list[bytes]:
    """Inverse of :func:`frame`. Raises ValueError on a truncated / malformed blob."""
    items: list[bytes] = []
    offset = 0
    total = len(blob)
    while offset < total:
        if offset + _HEADER.size > total:
            raise ValueError("framed blob truncated in length header")
        (length,) = _HEADER.unpack_from(blob, offset)
        offset += _HEADER.size
        end = offset + length
        if end > total:
            raise ValueError("framed blob truncated in payload")
        items.append(blob[offset:end])
        offset = end
    return items
