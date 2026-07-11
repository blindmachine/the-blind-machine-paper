#!/usr/bin/env python3
"""Stage 30 — compute (SERVER, the only server-side stage). KIT-OWNED SHIM.

Do not edit. Maps the argparse CLI the hosted worker drives onto the reserved
``server.compute`` function — the entire blind computation lives in server.py.
The worker pins this filename verbatim in its runtime adapters (docker.rb/process.rb)
and runs it in the network-isolated sandbox:

    python 30_compute_encrypted.py --context CTX --inputs C0 C1 … --out OUT

``compute`` receives the ciphertext bytes and the PUBLIC context bytes only —
never a secret key. Input order is fixed by the harness (digest-sorted).
"""
from __future__ import annotations

import argparse
import pathlib

from server import compute


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 30 — compute (server).")
    parser.add_argument("--context", required=True, type=pathlib.Path)
    parser.add_argument("--inputs", required=True, nargs="+", type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)

    result_bytes = compute(
        [path.read_bytes() for path in args.inputs],
        args.context.read_bytes(),
    )
    args.out.write_bytes(result_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
