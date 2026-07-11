"""Console-script entrypoint behavior."""

from __future__ import annotations

import sys

import blind.__main__ as entrypoint


def test_bare_blind_shows_startup_art(monkeypatch):
    calls: list[str] = []
    argv_seen: list[list[str]] = []

    monkeypatch.setattr(sys, "argv", ["blind"])
    monkeypatch.setattr(entrypoint.console, "revolving_ascii_art", lambda: calls.append("art"))

    def fake_app(standalone_mode=False):
        argv_seen.append(sys.argv[:])
        return 0

    monkeypatch.setattr(entrypoint, "app", fake_app)

    entrypoint.main()

    assert calls == ["art"]
    assert argv_seen == [["blind", "--help"]]


def test_command_invocation_does_not_show_startup_art(monkeypatch):
    calls: list[str] = []
    argv_seen: list[list[str]] = []

    monkeypatch.setattr(sys, "argv", ["blind", "version"])
    monkeypatch.setattr(entrypoint.console, "revolving_ascii_art", lambda: calls.append("art"))

    def fake_app(standalone_mode=False):
        argv_seen.append(sys.argv[:])
        return 0

    monkeypatch.setattr(entrypoint, "app", fake_app)

    entrypoint.main()

    assert calls == []
    assert argv_seen == [["blind", "version"]]


def test_json_env_suppresses_startup_art(monkeypatch):
    calls: list[str] = []

    monkeypatch.setenv("BLIND_JSON", "1")
    monkeypatch.setattr(sys, "argv", ["blind"])
    monkeypatch.setattr(entrypoint.console, "revolving_ascii_art", lambda: calls.append("art"))
    monkeypatch.setattr(entrypoint, "app", lambda standalone_mode=False: 0)

    entrypoint.main()

    assert calls == []
