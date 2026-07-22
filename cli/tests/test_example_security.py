"""The side-effectful public example must fail closed around remote targets."""

from __future__ import annotations

import pytest

from examples.register_and_run import validate_server_target


def test_loopback_example_target_is_allowed_without_remote_opt_in():
    assert validate_server_target(
        "http://127.0.0.1:3000", allow_remote=False, allow_production=False
    ) == "http://127.0.0.1:3000"


def test_remote_example_target_requires_explicit_opt_in():
    with pytest.raises(SystemExit):
        validate_server_target(
            "https://staging.example.com", allow_remote=False, allow_production=False
        )
    assert validate_server_target(
        "https://staging.example.com/", allow_remote=True, allow_production=False
    ) == "https://staging.example.com"


@pytest.mark.parametrize("host", ["blindmachine.org", "BLINDMACHINE.ORG."])
def test_production_example_target_requires_separate_confirmation(host):
    with pytest.raises(SystemExit):
        validate_server_target(
            f"https://{host}", allow_remote=True, allow_production=False
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://remote.example.com",
        "https://user:password@remote.example.com",
        "https://remote.example.com/api",
        "https://remote.example.com?token=value",
    ],
)
def test_example_target_rejects_unsafe_origins(url):
    with pytest.raises(SystemExit):
        validate_server_target(url, allow_remote=True, allow_production=True)
