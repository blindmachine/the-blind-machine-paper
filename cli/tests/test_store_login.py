"""~/.blind storage (perms, secret fallback, config) and the login flows."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from blind.api import ApiClient
from blind.errors import BlindError, UsageError, VerificationError
from blind.login import login_with_api_key, login_with_device
from blind.store import Store, _validate_private_file_info, blind_home, enforce_https
from tests.conftest import mock_transport


def test_token_file_is_chmod_600():
    store = Store()
    p = store.save_token("default", "tok_secret")
    mode = stat.S_IMODE(p.stat().st_mode)
    assert mode == 0o600
    assert store.load_token("default") == "tok_secret"
    assert store.delete_token("default") is True
    assert store.load_token("default") is None


def test_production_home_ignores_legacy_environment_override(monkeypatch, tmp_path):
    monkeypatch.setenv("BLIND_HOME", str(tmp_path / "attacker-selected"))
    assert blind_home() == (Path.home() / ".blind").absolute()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission enforcement")
def test_private_file_metadata_refuses_open_permissions(tmp_path):
    info = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o644,
        st_size=10,
        st_uid=os.geteuid(),
    )
    with pytest.raises(VerificationError):
        _validate_private_file_info(info, tmp_path / "token", "token file", max_bytes=1024)


def test_secret_fallback_file_is_600(monkeypatch):
    # The autouse fixture explicitly selects the test-only file backend.
    store = Store()
    backend = store.store_secret("proj_x", "SECRET-KEY-MATERIAL")
    assert backend == "file"
    secret, got_backend = store.load_secret("proj_x")
    assert secret == "SECRET-KEY-MATERIAL"
    assert got_backend == "file"
    keyfile = store.key_dir("proj_x") / "private.key"
    assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
    assert store.delete_secret("proj_x") is True


def test_config_defaults_and_set():
    store = Store()
    cfg = store.load_config()
    assert cfg["api"] == "https://blindmachine.org"
    assert cfg["profile"] == "default"
    store.set_config("api", "https://self.hosted")
    assert store.load_config()["api"] == "https://self.hosted"


def test_perms_report_flags_open_key(monkeypatch):
    store = Store()
    store.store_secret("proj_open", "x")
    keyfile = store.key_dir("proj_open") / "private.key"
    real_mode = Store._permission_mode
    monkeypatch.setattr(
        Store,
        "_permission_mode",
        staticmethod(lambda path: 0o644 if path == keyfile else real_mode(path)),
    )
    report = store.perms_report()
    assert any("proj_open" in f for f in report["world_readable"])


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("auth_path", ("../../stolen",)),
        ("key_dir", ("/tmp/escaped",)),
        ("result_dir", ("project", "../../escaped",)),
        ("application_dir", ("../../evil@" + "a" * 64,)),
        ("application_dir", ("safe@not-a-digest",)),
    ],
)
def test_local_state_paths_reject_traversal(method, args):
    with pytest.raises(BlindError):
        getattr(Store(), method)(*args)


def test_local_state_rejects_symlink_escape(tmp_path):
    store = Store()
    store.ensure_layout()
    outside = tmp_path / "outside"
    outside.mkdir()
    (store.home / "keys" / "projects" / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(VerificationError):
        store.key_dir("escape")


def test_keyring_failure_does_not_write_plaintext(monkeypatch):
    class BrokenKeyring:
        @staticmethod
        def set_password(*_args):
            raise RuntimeError("locked")

    monkeypatch.setenv("BLIND_SECRET_BACKEND", "keyring")
    monkeypatch.setattr(Store, "_keyring", lambda _self: BrokenKeyring())
    store = Store()
    with pytest.raises(VerificationError):
        store.store_secret("proj_secure", "TOP-SECRET")
    assert not (store.key_dir("proj_secure") / "private.key").exists()


def test_keyring_delete_failure_is_not_silently_ignored(monkeypatch):
    class BrokenDeleteKeyring:
        @staticmethod
        def get_password(*_args):
            return "secret"

        @staticmethod
        def delete_password(*_args):
            raise RuntimeError("locked")

    monkeypatch.setenv("BLIND_SECRET_BACKEND", "keyring")
    monkeypatch.setattr(Store, "_keyring", lambda _self: BrokenDeleteKeyring())
    with pytest.raises(VerificationError):
        Store().delete_secret("proj_secure")


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@example.com",
        "https://example.com/api",
        "https://example.com?token=secret",
        "https://example.com/#fragment",
        "http://example.com",
    ],
)
def test_server_url_rejects_credential_and_routing_ambiguity(url):
    with pytest.raises(UsageError):
        enforce_https(url)


@pytest.mark.parametrize("project", ["CON", "nul.txt", "name."])
def test_local_state_rejects_cross_platform_reserved_names(project):
    with pytest.raises(UsageError):
        Store().key_dir(project)


def test_perms_report_covers_owner_signing_key(monkeypatch):
    store = Store()
    store.store_signing_key("proj_owner", "a" * 64)
    keyfile = store.key_dir("proj_owner") / "owner_signing.key"
    real_mode = Store._permission_mode
    monkeypatch.setattr(
        Store,
        "_permission_mode",
        staticmethod(lambda path: 0o644 if path == keyfile else real_mode(path)),
    )
    report = store.perms_report()
    assert str(keyfile) in report["world_readable"]


def test_login_api_key_flow():
    client = ApiClient("https://x.test", token=None, transport=mock_transport({
        ("POST", "/api/v1/auth/token"): {"access_token": "tok_1"},
        ("GET", "/api/v1/me"): {"email": "a@b.test"},
    }))
    result = login_with_api_key(client, "sk_key")
    assert result.token == "tok_1"
    assert result.method == "api_key"
    assert result.account["email"] == "a@b.test"


def test_login_device_flow_single_attempt():
    prompts = []
    client = ApiClient("https://x.test", token=None, transport=mock_transport({
        ("POST", "/api/v1/auth/device"): {"device_code": "dev_1", "user_code": "ABCD",
                                          "verification_uri": "https://x.test/device",
                                          "interval": 1},
        ("POST", "/api/v1/auth/token"): {"access_token": "tok_dev"},
        ("GET", "/api/v1/me"): {"email": "dev@b.test"},
    }))
    result = login_with_device(
        client, on_prompt=lambda code, uri: prompts.append((code, uri)), poll=False
    )
    assert result.token == "tok_dev"
    assert prompts == [("ABCD", "https://x.test/device")]
