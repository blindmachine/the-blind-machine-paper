#!/usr/bin/env python3
"""Stage 50 — decode (LOCAL, project owner). KIT-OWNED SHIM — do not edit.

Maps the argparse CLI onto ``local_project_owner.decode`` (splits the sentinel
from the counts and derives the released statistic). Logic lives in
local_project_owner.py.

    python 50_decode.py --plain PLAIN.json --length L --out RESULT.json [--scale S]

The decrypted ``plain`` shape is application-defined — a JSON list, or a labelled
object of moment vectors for the multiplicative scenarios — so this shim does NOT
constrain it; the author's ``decode`` validates its own input. Optional
per-application params (currently only ``--scale``, for the polygenic-score
scenario's ``decode(plain, length, scale=...)``) are forwarded ONLY when the
caller passes them.
"""
from __future__ import annotations

import argparse
import json
import pathlib

from local_project_owner import decode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 50 — decode (local).")
    parser.add_argument("--plain", required=True, type=pathlib.Path)
    parser.add_argument("--length", required=True, type=int)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    # Optional per-application decode params, forwarded only when set (default None ⇒
    # filtered out). `--scale` feeds the polygenic-score scenario's
    # `decode(plain, length, scale=...)`.
    parser.add_argument("--scale", type=int, default=None)
    args = parser.parse_args(argv)

    # Decrypted `plain` shape is application-defined (list, or labelled moments); decode validates.
    plain = json.loads(args.plain.read_text())

    extra = {"scale": args.scale}
    args.out.write_text(
        json.dumps(
            decode(plain, args.length, **{k: v for k, v in extra.items() if v is not None}),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
