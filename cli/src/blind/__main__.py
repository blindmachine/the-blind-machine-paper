"""`blind` console-script entrypoint.

Runs the Typer app in non-standalone mode so typed BlindErrors map to stable exit
codes and (under --json) a machine-readable error envelope, instead of a traceback.

Typer may ship its own vendored click (``typer._click``) or use the real ``click``
package; we resolve the exception classes from whichever is present so the exit-code
contract holds regardless.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from blind import console
from blind.cli.app import app
from blind.context import current_context, handle_error
from blind.errors import BlindError

try:  # real click (older typer)
    import click.exceptions as _click_exc  # type: ignore
except ModuleNotFoundError:  # typer >= 0.13 vendors click
    from typer._click import exceptions as _click_exc  # type: ignore


def main() -> None:
    argv = sys.argv[1:]
    if _should_show_startup_art(argv):
        console.revolving_ascii_art()
    if _is_bare_invocation(argv):
        sys.argv = [sys.argv[0], "--help"]

    try:
        # In non-standalone mode click RETURNS a typer.Exit's code rather than
        # raising it, so capture and propagate the return value.
        rv = app(standalone_mode=False)
    except BlindError as exc:
        sys.exit(handle_error(current_context(), exc))
    except _click_exc.Abort:
        sys.exit(130)
    except _click_exc.Exit as exc:  # some click versions still raise it
        sys.exit(getattr(exc, "exit_code", 0))
    except _click_exc.ClickException as exc:  # usage / bad-flag errors
        exc.show()
        sys.exit(2)
    except SystemExit:
        raise
    else:
        if isinstance(rv, int) and rv:
            sys.exit(rv)


def _should_show_startup_art(argv: Sequence[str]) -> bool:
    return (
        _is_bare_invocation(argv)
        and not _env_flag("BLIND_JSON")
        and not _env_flag("BLIND_QUIET")
    )


def _is_bare_invocation(argv: Sequence[str]) -> bool:
    return not argv


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


if __name__ == "__main__":
    main()
