#!/usr/bin/env python3
"""Squash a clean pull request with an explicit noreply author and verified signature."""

from __future__ import annotations

import argparse
import json
import re
import string
import subprocess
import sys
from typing import Any

LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}")
REPOSITORY_CHARACTERS = frozenset(string.ascii_letters + string.digits + "_.-")

PULL_REQUEST_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  viewer {
    databaseId
    login
  }
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      headRefOid
      id
      isDraft
      mergeable
      mergeStateStatus
      merged
      number
      url
    }
  }
}
"""

MERGE_MUTATION = """
mutation($input: MergePullRequestInput!) {
  mergePullRequest(input: $input) {
    pullRequest {
      mergeCommit {
        oid
      }
      merged
      number
      url
    }
  }
}
"""


def run_gh(*arguments: str, stdin: str | None = None) -> Any:
    result = subprocess.run(
        ["gh", *arguments],
        check=True,
        capture_output=True,
        text=True,
        input=stdin,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit("GitHub CLI returned malformed JSON") from error


def graphql(query: str, variables: dict[str, Any]) -> dict[str, Any]:
    response = run_gh(
        "api",
        "graphql",
        "--input",
        "-",
        stdin=json.dumps({"query": query, "variables": variables}),
    )
    if response.get("errors"):
        messages = [error.get("message", "unknown GraphQL error") for error in response["errors"]]
        raise SystemExit("GitHub rejected the operation: " + "; ".join(messages))
    data = response.get("data")
    if not isinstance(data, dict):
        raise SystemExit("GitHub response did not contain data")
    return data


def repository_name(explicit: str | None) -> str:
    if explicit:
        candidate = explicit
    else:
        response = run_gh("repo", "view", "--json", "nameWithOwner")
        candidate = response.get("nameWithOwner", "")
    if not isinstance(candidate, str) or candidate.count("/") != 1:
        raise SystemExit("repository must be formatted as owner/name")
    owner, name = candidate.split("/", 1)
    valid_lengths = 1 <= len(owner) <= 39 and 1 <= len(name) <= 100
    valid_characters = all(character in REPOSITORY_CHARACTERS for character in owner + name)
    if not valid_lengths or not valid_characters:
        raise SystemExit("repository must be formatted as owner/name")
    return candidate


def noreply_email(database_id: int, login: str) -> str:
    if (
        type(database_id) is not int
        or database_id <= 0
        or not isinstance(login, str)
        or LOGIN.fullmatch(login) is None
    ):
        raise SystemExit("GitHub returned an invalid viewer identity")
    return f"{database_id}+{login}@users.noreply.github.com"


def validate_pull_request(pull_request: dict[str, Any]) -> None:
    if pull_request.get("merged"):
        raise SystemExit("pull request is already merged")
    if pull_request.get("isDraft"):
        raise SystemExit("refusing to merge a draft pull request")
    if pull_request.get("mergeable") != "MERGEABLE":
        raise SystemExit("pull request is not currently mergeable")
    if pull_request.get("mergeStateStatus") != "CLEAN":
        raise SystemExit("pull request is not clean and fully ready to merge")
    head_oid = pull_request.get("headRefOid", "")
    if not isinstance(head_oid, str) or not re.fullmatch(r"[0-9a-f]{40,64}", head_oid):
        raise SystemExit("pull request head is missing or malformed")


def verify_merged_commit(commit: dict[str, Any], expected_email: str) -> None:
    metadata = commit.get("commit", {})
    author = metadata.get("author", {})
    committer = metadata.get("committer", {})
    verification = metadata.get("verification", {})
    if author.get("email") != expected_email:
        raise SystemExit("merged commit did not use the expected noreply author")
    if committer.get("email") != "noreply@github.com":
        raise SystemExit("merged commit did not use GitHub's noreply committer")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise SystemExit("merged commit does not have a valid GitHub signature")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("number", type=int, help="pull request number")
    parser.add_argument("--repo", help="repository in owner/name form; defaults to the current repo")
    parser.add_argument("--yes", action="store_true", help="perform the merge after validation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.number <= 0:
        raise SystemExit("pull request number must be positive")

    repository = repository_name(args.repo)
    owner, name = repository.split("/", 1)
    data = graphql(
        PULL_REQUEST_QUERY,
        {"owner": owner, "name": name, "number": args.number},
    )
    pull_request = (data.get("repository") or {}).get("pullRequest")
    if not isinstance(pull_request, dict):
        raise SystemExit("pull request was not found")
    validate_pull_request(pull_request)

    viewer = data.get("viewer") or {}
    author_email = noreply_email(viewer.get("databaseId", 0), viewer.get("login", ""))
    if not args.yes:
        print(f"ready to securely merge {repository}#{args.number}; rerun with --yes")
        return 0

    merged = graphql(
        MERGE_MUTATION,
        {
            "input": {
                "pullRequestId": pull_request["id"],
                "expectedHeadOid": pull_request["headRefOid"],
                "mergeMethod": "SQUASH",
                "authorEmail": author_email,
            }
        },
    )["mergePullRequest"]["pullRequest"]
    merge_commit = merged.get("mergeCommit") or {}
    oid = merge_commit.get("oid", "")
    if not re.fullmatch(r"[0-9a-f]{40,64}", oid):
        raise SystemExit("GitHub did not return the merged commit")

    commit = run_gh("api", f"repos/{repository}/commits/{oid}")
    verify_merged_commit(commit, author_email)
    print(f"securely merged {repository}#{args.number} as verified commit {oid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
