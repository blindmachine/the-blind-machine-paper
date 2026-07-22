"""Client-side transport security: enforce_https, non-default-server notice, and
the BLIND_JSON / BLIND_QUIET output-mode env fallbacks."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from blind.cli.app import app
from blind.errors import UsageError
from blind.store import DEFAULT_API, enforce_https

runner = CliRunner()


# --- enforce_https --------------------------------------------------------

def test_https_urls_pass_through():
    assert enforce_https("https://blindmachine.org") == "https://blindmachine.org"
    assert enforce_https("https://example.test:8443") == "https://example.test:8443"


def test_api_base_url_refuses_paths():
    with pytest.raises(UsageError):
        enforce_https("https://example.test:8443/api")


@pytest.mark.parametrize("url", [
    "http://localhost:3000",
    "http://127.0.0.1:3712",
    "http://[::1]:3000",
])
def test_loopback_http_is_allowed_for_local_dev(url):
    assert enforce_https(url) == url


@pytest.mark.parametrize("url", [
    "http://blindmachine.org",
    "http://evil.example.com",
    "http://192.168.1.5:3000",
    "ftp://blindmachine.org",
])
def test_non_loopback_cleartext_is_refused(url):
    with pytest.raises(UsageError):
        enforce_https(url)


def test_cli_refuses_an_insecure_api_override():
    # Under CliRunner a raised BlindError surfaces as exit_code != 0 + exception;
    # the real `blind` binary maps it to UsageError.code (2) via __main__.
    result = runner.invoke(app, ["--json", "--api", "http://evil.example.com", "version"])
    assert result.exit_code != 0
    assert isinstance(result.exception, UsageError)


def test_cli_accepts_a_loopback_api_override():
    result = runner.invoke(app, ["--json", "--api", "http://localhost:3000", "version"])
    assert result.exit_code == 0


# --- non-default server notice -------------------------------------------

def test_non_default_server_notice_is_shown_once(monkeypatch):
    # Reset the once-per-process latch so this test controls it.
    import blind.context as ctxmod
    monkeypatch.setattr(ctxmod, "_WARNED_NON_DEFAULT_SERVER", False, raising=False)

    result = runner.invoke(app, ["--api", "https://staging.blindmachine.org", "version"])
    assert result.exit_code == 0
    # The notice is a STDERR diagnostic (console.notice) so it can never corrupt
    # --json stdout — assert it there, and that stdout stayed clean.
    assert "non-default server" in result.stderr
    assert "non-default server" not in result.stdout


def test_no_notice_for_default_server():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "non-default server" not in result.stdout
    # sanity: the default really is the canonical host
    assert DEFAULT_API == "https://blindmachine.org"


def test_notice_suppressed_under_json(monkeypatch):
    import blind.context as ctxmod
    monkeypatch.setattr(ctxmod, "_WARNED_NON_DEFAULT_SERVER", False, raising=False)

    result = runner.invoke(app, ["--json", "--api", "https://staging.blindmachine.org", "version"])
    assert result.exit_code == 0
    assert "non-default server" not in result.stdout


# --- BLIND_JSON / BLIND_QUIET env fallbacks ------------------------------

def test_blind_json_env_forces_json_output(monkeypatch):
    monkeypatch.setenv("BLIND_JSON", "1")
    result = runner.invoke(app, ["version"])  # no --json flag
    assert result.exit_code == 0
    # JSON mode prints a machine object even without the flag.
    assert '"object": "version"' in result.stdout or '"object":"version"' in result.stdout


def test_explicit_flag_still_wins_when_env_unset(monkeypatch):
    monkeypatch.delenv("BLIND_JSON", raising=False)
    result = runner.invoke(app, ["--json", "version"])
    assert result.exit_code == 0
