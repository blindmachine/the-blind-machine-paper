"""blind — The Blind Machine trust CLI.

An orchestrator / verifier / API client. The cryptography lives in the application
bundles (their own sealed uv env), never in this package. See cli/README.md.
"""

from blind.version import __version__

__all__ = ["__version__"]
