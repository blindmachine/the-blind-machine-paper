#!/usr/bin/env python3
"""Stage 40 — decrypt (LOCAL, project owner). KIT-OWNED SHIM — do not edit.

Maps the argparse CLI onto ``local_project_owner.decrypt`` — the ONLY use of the
secret key, on the owner's machine. Logic lives in local_project_owner.py.

    python 40_decrypt.py --context SECRET --result RESULT.bin --out PLAIN.json
"""
from __future__ import annotations

import argparse
import json
import pathlib

from local_project_owner import decrypt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 40 — decrypt (local).")
    parser.add_argument("--context", required=True, type=pathlib.Path)
    parser.add_argument("--result", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)

    plain = decrypt(args.context.read_bytes(), args.result.read_bytes())
    args.out.write_text(json.dumps(plain))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
