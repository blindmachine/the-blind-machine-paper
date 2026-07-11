#!/usr/bin/env python3
"""Stage 10 — encode (LOCAL, data owner). KIT-OWNED SHIM — do not edit.

Maps the argparse CLI onto ``local_data_owner.encode``. The encoding logic lives
in local_data_owner.py.

    python 10_encode.py --raw RAW.json --length L --out OUT.json
                        [--phenotype-domain D0 D1 ...]

The raw record shape is application-defined — a JSON list of dosages, a single
bucket index, or a ``{"genotype", "phenotype"}`` object — so this shim does NOT
constrain it; the author's ``encode`` validates its own input. Optional
per-application params (currently only ``--phenotype-domain``, for the covariance
scenario's ``encode(raw, length, phenotype_domain=...)``) are forwarded ONLY when
the caller passes them, so applications whose ``encode(raw, length)`` takes no extra
args are unaffected.
"""
from __future__ import annotations

import argparse
import json
import pathlib

from local_data_owner import encode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 10 — encode (local).")
    parser.add_argument("--raw", required=True, type=pathlib.Path)
    parser.add_argument("--length", required=True, type=int)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    # Optional per-application encode params, forwarded only when set (default None ⇒
    # filtered out), like the keygen shim. `--phenotype-domain` feeds the
    # covariance scenario's `encode(raw, length, phenotype_domain=...)`.
    parser.add_argument("--phenotype-domain", type=int, nargs="+", default=None)
    args = parser.parse_args(argv)

    # Raw record shape is application-defined (list / int / object); encode validates.
    raw = json.loads(args.raw.read_text())

    extra = {"phenotype_domain": args.phenotype_domain}
    args.out.write_text(
        json.dumps(encode(raw, args.length, **{k: v for k, v in extra.items() if v is not None}))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
