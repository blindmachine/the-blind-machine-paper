#!/usr/bin/env python3
"""Create the immutable package-version tag from a clean, verified remote main."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from typing import Any

from scripts.check_commit_metadata import email_is_safe
from scripts.check_release_tag import expected_tag
from scripts.secure_merge import repository_name, run_gh

TAG = re.compile(r"v[0-9A-Za-z][0-9A-Za-z._-]*")


def validate_release_commit(commit: dict[str, Any]) -> None:
    metadata = commit.get("commit", {})
    author = metadata.get("author", {})
    committer = metadata.get("committer", {})
    verification = metadata.get("verification", {})
    if not email_is_safe(author.get("email", "")):
        raise SystemExit("release commit has a disallowed author email")
    if not email_is_safe(committer.get("email", "")):
        raise SystemExit("release commit has a disallowed committer email")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise SystemExit("release commit does not have a valid GitHub signature")


def local_git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def existing_tag(repository: str, tag: str) -> str | None:
    try:
        response = run_gh("api", f"repos/{repository}/git/ref/tags/{tag}")
    except subprocess.CalledProcessError as error:
        if "HTTP 404" in error.stderr:
            return None
        raise SystemExit("unable to verify whether the release tag exists") from error
    return response.get("object", {}).get("sha")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="repository in owner/name form; defaults to the current repo")
    parser.add_argument("--yes", action="store_true", help="create the immutable tag")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repository = repository_name(args.repo)
    tag = expected_tag()
    if TAG.fullmatch(tag) is None:
        raise SystemExit("package version produced an invalid release tag")

    if local_git("branch", "--show-current") != "main":
        raise SystemExit("release tags can only be created from local main")
    if local_git("status", "--porcelain"):
        raise SystemExit("release checkout must be clean")

    local_sha = local_git("rev-parse", "HEAD")
    remote_ref = run_gh("api", f"repos/{repository}/git/ref/heads/main")
    remote_sha = remote_ref.get("object", {}).get("sha", "")
    if local_sha != remote_sha:
        raise SystemExit("local main must exactly match remote main")

    commit = run_gh("api", f"repos/{repository}/commits/{remote_sha}")
    validate_release_commit(commit)
    current_tag = existing_tag(repository, tag)
    if current_tag is not None:
        if current_tag != remote_sha:
            raise SystemExit("release tag already points to a different commit")
        print(f"immutable release tag already verified: {tag}")
        return 0

    if not args.yes:
        print(f"ready to tag verified {repository}@{remote_sha} as {tag}; rerun with --yes")
        return 0

    run_gh(
        "api",
        "--method",
        "POST",
        f"repos/{repository}/git/refs",
        "-f",
        f"ref=refs/tags/{tag}",
        "-f",
        f"sha={remote_sha}",
    )
    if existing_tag(repository, tag) != remote_sha:
        raise SystemExit("release tag verification failed after creation")
    print(f"created immutable release tag {tag} at verified commit {remote_sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
