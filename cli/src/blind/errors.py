"""Typed errors mapped to stable exit codes and a JSON error envelope.

Exit-code contract (UX.md Part D):
  0  ok
  2  usage        — malformed input / bad flags
  3  auth         — missing or rejected credentials
  4  network      — could not reach the platform
  5  precondition — server-side gate refused (e.g. cohort not frozen, min-N unmet)
  6  verify       — a hash / signature / equivalence check did not match
"""

from __future__ import annotations


class BlindError(Exception):
    """Base class for every error the CLI raises deliberately."""

    code: int = 1
    kind: str = "error"

    def __init__(self, message: str, *, detail: str | None = None, reason: str | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail
        # The server's machine-readable gate code (the flat {"error": <code>}
        # body, e.g. "insufficient_credits") so callers can branch on the
        # refusal without parsing the human message.
        self.reason = reason

    def envelope(self) -> dict:
        env = {"object": "error", "code": self.code, "kind": self.kind, "message": self.message}
        if self.detail:
            env["detail"] = self.detail
        return env


class UsageError(BlindError):
    code = 2
    kind = "usage"


class AuthError(BlindError):
    code = 3
    kind = "auth"


class NetworkError(BlindError):
    code = 4
    kind = "network"


class PreconditionError(BlindError):
    code = 5
    kind = "precondition"


class VerificationError(BlindError):
    code = 6
    kind = "verify"
