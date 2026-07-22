#!/usr/bin/env python3
"""Reject reachable commits that expose an unapproved email address."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAFE_EMAIL = re.compile(
    r"(?:"
    r"noreply@github[.]com|"
    r"[^@\s]+@users[.]noreply[.]github[.]com|"
    r"[^@\s]+@blindmachine[.]org"
    r")",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CommitMetadata:
    oid: str
    author_email: str
    committer_email: str


def email_is_safe(email: str) -> bool:
    return SAFE_EMAIL.fullmatch(email) is not None


def reachable_metadata(
    ref: str = "HEAD",
    *,
    exclude_oids: frozenset[str] = frozenset(),
) -> list[CommitMetadata]:
    output = subprocess.run(
        ["git", "log", "-z", "--format=%H%x00%ae%x00%ce", ref],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    fields = output.decode("utf-8", errors="strict").split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 3:
        raise SystemExit("git returned malformed commit metadata")
    records = [
        CommitMetadata(*fields[index : index + 3])
        for index in range(0, len(fields), 3)
    ]
    return [record for record in records if record.oid not in exclude_oids]


def pull_request_merge_exclusion(
    *,
    event_name: str,
    github_ref: str,
    github_sha: str,
    head_oid: str,
    parent_oids: list[str],
) -> str | None:
    if event_name != "pull_request":
        return None
    if re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", github_ref) is None:
        raise SystemExit("pull-request event does not use a merge ref")
    if github_sha != head_oid or re.fullmatch(r"[0-9a-f]{40,64}", head_oid) is None:
        raise SystemExit("pull-request merge identity does not match checked-out HEAD")
    if len(parent_oids) != 2 or any(
        re.fullmatch(r"[0-9a-f]{40,64}", oid) is None for oid in parent_oids
    ):
        raise SystemExit("pull-request merge HEAD must have exactly two valid parents")
    return head_oid


def git_text(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def enforce_safe_metadata(records: list[CommitMetadata]) -> None:
    for record in records:
        for role, email in (
            ("author", record.author_email),
            ("committer", record.committer_email),
        ):
            if not email_is_safe(email):
                raise SystemExit(
                    f"disallowed {role} email at commit {record.oid}; "
                    "use a GitHub noreply or @blindmachine.org address"
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-pull-request-merge",
        action="store_true",
        help="exclude only GitHub's verified synthetic refs/pull/*/merge HEAD",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    excluded: frozenset[str] = frozenset()
    if args.allow_pull_request_merge:
        head_oid = git_text("rev-parse", "HEAD")
        exclusion = pull_request_merge_exclusion(
            event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
            github_ref=os.environ.get("GITHUB_REF", ""),
            github_sha=os.environ.get("GITHUB_SHA", ""),
            head_oid=head_oid,
            parent_oids=git_text("show", "-s", "--format=%P", "HEAD").split(),
        )
        if exclusion:
            excluded = frozenset({exclusion})

    records = reachable_metadata(exclude_oids=excluded)
    if not records:
        raise SystemExit("no reachable commits found")
    enforce_safe_metadata(records)
    print(f"commit metadata privacy verified: {len(records)} reachable commits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
