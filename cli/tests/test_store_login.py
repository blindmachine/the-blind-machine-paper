"""~/.blind storage (perms, secret fallback, config) and the login flows."""

from __future__ import annotations

import os
import stat

from blind.api import ApiClient
from blind.login import login_with_api_key, login_with_device
from blind.store import Store
from tests.conftest import mock_transport


def test_token_file_is_chmod_600():
    store = Store()
    p = store.save_token("default", "tok_secret")
    mode = stat.S_IMODE(p.stat().st_mode)
    assert mode == 0o600
    assert store.load_token("default") == "tok_secret"
    assert store.delete_token("default") is True
    assert store.load_token("default") is None


def test_secret_fallback_file_is_600(monkeypatch):
    # BLIND_NO_KEYRING is set by the autouse fixture → file fallback.
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
    os.chmod(keyfile, 0o644)  # deliberately too open
    report = store.perms_report()
    assert any("proj_open" in f for f in report["world_readable"])


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
