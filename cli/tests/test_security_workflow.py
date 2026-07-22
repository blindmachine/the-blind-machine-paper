from __future__ import annotations

import pytest

from scripts import check_commit_metadata, check_release_tag, create_release_tag, secure_merge


@pytest.mark.parametrize(
    "email",
    [
        "noreply@github.com",
        "1+maintainer@users.noreply.github.com",
        "security@blindmachine.org",
    ],
)
def test_commit_metadata_accepts_public_safe_email(email: str) -> None:
    assert check_commit_metadata.email_is_safe(email)


def test_commit_metadata_rejects_private_email_without_reprinting_it() -> None:
    private_email = "person@private.test"
    records = [
        check_commit_metadata.CommitMetadata(
            oid="a" * 40,
            author_email=private_email,
            committer_email="noreply@github.com",
        )
    ]

    with pytest.raises(SystemExit) as error:
        check_commit_metadata.enforce_safe_metadata(records)

    assert "disallowed author email" in str(error.value)
    assert private_email not in str(error.value)


def test_commit_metadata_excludes_only_verified_synthetic_pull_request_merge() -> None:
    oid = "a" * 40
    assert (
        check_commit_metadata.pull_request_merge_exclusion(
            event_name="pull_request",
            github_ref="refs/pull/5/merge",
            github_sha=oid,
            head_oid=oid,
            parent_oids=["b" * 40, "c" * 40],
        )
        == oid
    )


def test_commit_metadata_rejects_malformed_pull_request_merge() -> None:
    oid = "a" * 40
    with pytest.raises(SystemExit, match="exactly two"):
        check_commit_metadata.pull_request_merge_exclusion(
            event_name="pull_request",
            github_ref="refs/pull/5/merge",
            github_sha=oid,
            head_oid=oid,
            parent_oids=["b" * 40],
        )


def test_secure_merge_derives_id_based_noreply_email() -> None:
    assert (
        secure_merge.noreply_email(12345, "maintainer")
        == "12345+maintainer@users.noreply.github.com"
    )


@pytest.mark.parametrize("repository", ["missing-slash", "owner/", "owner/bad name"])
def test_secure_merge_rejects_invalid_repository_name(repository: str) -> None:
    with pytest.raises(SystemExit, match="owner/name"):
        secure_merge.repository_name(repository)


@pytest.mark.parametrize("database_id,login", [(0, "maintainer"), (1, "bad/login")])
def test_secure_merge_rejects_invalid_viewer(database_id: int, login: str) -> None:
    with pytest.raises(SystemExit, match="invalid viewer identity"):
        secure_merge.noreply_email(database_id, login)


def test_secure_merge_requires_a_clean_pull_request() -> None:
    pull_request = {
        "merged": False,
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "BLOCKED",
        "headRefOid": "a" * 40,
    }

    with pytest.raises(SystemExit, match="not clean"):
        secure_merge.validate_pull_request(pull_request)


def test_secure_merge_verifies_author_committer_and_signature() -> None:
    expected_email = "12345+maintainer@users.noreply.github.com"
    commit = {
        "commit": {
            "author": {"email": expected_email},
            "committer": {"email": "noreply@github.com"},
            "verification": {"verified": True, "reason": "valid"},
        }
    }

    secure_merge.verify_merged_commit(commit, expected_email)


def test_secure_merge_rejects_unsigned_commit() -> None:
    expected_email = "12345+maintainer@users.noreply.github.com"
    commit = {
        "commit": {
            "author": {"email": expected_email},
            "committer": {"email": "noreply@github.com"},
            "verification": {"verified": False, "reason": "unsigned"},
        }
    }

    with pytest.raises(SystemExit, match="valid GitHub signature"):
        secure_merge.verify_merged_commit(commit, expected_email)


@pytest.mark.parametrize(
    "ref_type,ref_name,allow_main",
    [("tag", "v0.1.0", False), ("branch", "main", True)],
)
def test_release_source_accepts_exact_tag_or_explicit_main(
    ref_type: str,
    ref_name: str,
    allow_main: bool,
) -> None:
    check_release_tag.validate_release_ref(
        ref_name=ref_name,
        ref_type=ref_type,
        expected="v0.1.0",
        allow_main=allow_main,
    )


def test_release_source_rejects_feature_branch() -> None:
    with pytest.raises(SystemExit, match="protected branch main"):
        check_release_tag.validate_release_ref(
            ref_name="feature",
            ref_type="branch",
            expected="v0.1.0",
            allow_main=True,
        )


def test_release_tag_requires_a_verified_private_metadata_commit() -> None:
    commit = {
        "commit": {
            "author": {"email": "1+maintainer@users.noreply.github.com"},
            "committer": {"email": "noreply@github.com"},
            "verification": {"verified": True, "reason": "valid"},
        }
    }

    create_release_tag.validate_release_commit(commit)


def test_release_tag_rejects_unsigned_commit() -> None:
    commit = {
        "commit": {
            "author": {"email": "1+maintainer@users.noreply.github.com"},
            "committer": {"email": "noreply@github.com"},
            "verification": {"verified": False, "reason": "unsigned"},
        }
    }

    with pytest.raises(SystemExit, match="valid GitHub signature"):
        create_release_tag.validate_release_commit(commit)
