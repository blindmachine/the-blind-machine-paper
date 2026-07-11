#!/usr/bin/env python3
"""Stage 20 — encrypt (LOCAL, data owner). KIT-OWNED SHIM — do not edit.

Maps the argparse CLI onto ``local_data_owner.encrypt`` (which appends the
append-1 sentinel and BFV-encrypts under the PUBLIC context). Logic lives in
local_data_owner.py.

    python 20_encrypt.py --context CTX --encoded ENC.json --out OUT.bin

The encoded shape is application-defined — a JSON list, or a ``{"g", "y"}`` object
for the covariance scenario (whose ``encrypt`` co-packs both ciphertexts into ONE
uploadable blob) — so this shim does NOT constrain it; the author's ``encrypt``
validates its own input. Every shipped scenario emits ONE ``--out`` blob per
contributor.
"""
from __future__ import annotations

import argparse
import json
import pathlib

from local_data_owner import encrypt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 20 — encrypt (local).")
    parser.add_argument("--context", required=True, type=pathlib.Path)
    parser.add_argument("--encoded", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)

    # Encoded shape is application-defined (list, or {"g","y"} object); encrypt validates.
    encoded = json.loads(args.encoded.read_text())
    args.out.write_bytes(encrypt(args.context.read_bytes(), encoded))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
