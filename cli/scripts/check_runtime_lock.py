#!/usr/bin/env python3
"""Prove wheel metadata pins the complete uv-locked runtime closure."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)==([^;\s]+)(?:\s*;\s*(.+))?$")


def canonical(requirement: str) -> tuple[str, str, str]:
    match = REQUIREMENT.fullmatch(requirement.strip())
    if not match:
        raise SystemExit(f"runtime dependency is not exactly pinned: {requirement}")
    name, version, marker = match.groups()
    normalized_name = re.sub(r"[-_.]+", "-", name).lower()
    normalized_marker = re.sub(r"\s+", "", marker or "").replace('"', "'").lower()
    return normalized_name, version, normalized_marker


def requirement_map(lines: list[str]) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for line in lines:
        name, version, marker = canonical(line)
        if name in result:
            raise SystemExit(f"duplicate runtime dependency pin: {name}")
        result[name] = (version, marker)
    return result


def main() -> int:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    declared = requirement_map(project["project"]["dependencies"])
    exported = subprocess.run(
        [
            "uv", "export", "--project", str(ROOT), "--locked", "--no-dev",
            "--no-emit-project", "--no-hashes", "--format", "requirements-txt",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    locked_lines = [line for line in exported if line and not line.startswith(("#", " "))]
    locked = requirement_map(locked_lines)
    if declared != locked:
        missing = sorted(set(locked) - set(declared))
        extra = sorted(set(declared) - set(locked))
        changed = sorted(name for name in set(declared) & set(locked) if declared[name] != locked[name])
        raise SystemExit(
            f"runtime metadata/lock mismatch: missing={missing}, extra={extra}, changed={changed}"
        )
    print(f"runtime closure locked: {len(locked)} exact packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
