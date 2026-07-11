"""Per-invocation context + the single output switch (pretty vs --json vs --quiet).

The root Typer callback builds one ``Context`` and stashes it in ``ctx.obj``.
Every command ends by calling ``emit(context, view)`` — the ONE place where
pretty-vs-machine is decided, so ``--json`` is guaranteed on every command.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Callable

from blind import console
from blind.api import ApiClient
from blind.errors import BlindError
from blind.store import DEFAULT_API, Store, enforce_https

# Test seam: a mock httpx transport the CLI's clients should use (set by tests).
_TEST_TRANSPORT = None

# The most-recently-built Context, so main() can render errors in the right mode.
_CURRENT: "Context | None" = None

# Print the "non-default server" notice at most once per process.
_WARNED_NON_DEFAULT_SERVER = False


def set_test_transport(transport) -> None:
    global _TEST_TRANSPORT
    _TEST_TRANSPORT = transport


def set_current(ctx: "Context") -> None:
    global _CURRENT
    _CURRENT = ctx


def current_context() -> "Context | None":
    return _CURRENT


@dataclass
class Context:
    json: bool = False
    quiet: bool = False
    color: str = "auto"
    api: str | None = None
    profile: str = "default"
    api_key: str | None = None
    project: str | None = None
    assume_yes: bool = False
    store: Store = field(default_factory=Store)

    def __post_init__(self):
        self.store.ensure_layout()
        self._config = self.store.load_config()
        console.set_color_mode(self.color)
        # Resolve + validate the base URL once: a bearer token must never travel
        # in cleartext, so a non-loopback http:// URL is refused here (raises).
        self._base_url = enforce_https(self.api or self._config.get("api") or DEFAULT_API)
        self._warn_if_non_default_server()

    @property
    def config(self) -> dict:
        return self._config

    @property
    def base_url(self) -> str:
        return self._base_url

    def billing_url(self) -> str:
        """The web top-up page, derived from the configured API base — the same
        host serves both the API (/api/v1) and the money page (/billing)."""
        return f"{self._base_url}/billing"

    # A single dim notice the first time a command runs against anything other
    # than the canonical server, so the operator is never silently talking to a
    # non-default host. Suppressed under --json / --quiet.
    def _warn_if_non_default_server(self) -> None:
        global _WARNED_NON_DEFAULT_SERVER
        if self.quiet or _WARNED_NON_DEFAULT_SERVER:
            return
        if self._base_url != DEFAULT_API:
            _WARNED_NON_DEFAULT_SERVER = True
            # STDERR notice (see console.notice) so it can't corrupt --json stdout.
            console.notice("warn", "non-default server", self._base_url)

    def token(self) -> str | None:
        if self.api_key:
            return self.api_key
        return self.store.load_token(self.profile)

    def client(self, token: str | None = None) -> ApiClient:
        return ApiClient(
            self.base_url,
            token if token is not None else self.token(),
            transport=_TEST_TRANSPORT,
        )


def emit(ctx: Context, view: dict, render: Callable[[], None] | None = None) -> None:
    """Render a command's typed result. `view` is the machine contract (always a
    dict); `render` draws the pretty form. Guarantees --json on every command."""
    if ctx.json:
        console.console.print_json(_json.dumps(view))
    elif ctx.quiet:
        ident = view.get("id") or view.get("sha256") or view.get("digest") \
            or view.get("certificate_hash") or view.get("sim_run_hash") or ""
        if ident:
            console.console.print(ident)
    elif render is not None:
        render()
    else:
        console.console.print_json(_json.dumps(view))


def handle_error(ctx: Context | None, exc: BlindError) -> int:
    """Uniform error output: JSON envelope under --json, else a red line."""
    use_json = bool(ctx and ctx.json)
    if use_json:
        console.console.print_json(_json.dumps(exc.envelope()))
    else:
        console.line("error", exc.message, detail=exc.detail or "")
    return exc.code
