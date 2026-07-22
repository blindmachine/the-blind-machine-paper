#!/usr/bin/env python3
"""Require a release tag to match the reviewed package version exactly."""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def expected_tag() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return f"v{project['version']}"


def validate_release_ref(
    *,
    ref_name: str,
    ref_type: str,
    expected: str,
    allow_main: bool,
) -> None:
    exact_tag = ref_type == "tag" and ref_name == expected
    protected_main = allow_main and ref_type == "branch" and ref_name == "main"
    if not exact_tag and not protected_main:
        raise SystemExit(
            f"release ref must be the exact tag {expected}"
            + (" or protected branch main" if allow_main else "")
            + f"; received {ref_type}:{ref_name}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-main", action="store_true")
    parser.add_argument("--print-tag", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    expected = expected_tag()
    validate_release_ref(
        ref_name=os.environ.get("GITHUB_REF_NAME", ""),
        ref_type=os.environ.get("GITHUB_REF_TYPE", ""),
        expected=expected,
        allow_main=args.allow_main,
    )
    if args.print_tag:
        print(expected)
    else:
        print(f"release source verified: {os.environ.get('GITHUB_REF_TYPE')}:{os.environ.get('GITHUB_REF_NAME')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
