"""Environment sealing with uv (application_structure.md "Environment sealing").

The BUILD phase — network allowed, NO data — runs

    uv --project env sync --frozen --no-dev

inside the bundle to materialize the pinned environment from ``env/uv.lock``,
then records an ``env_lock`` digest over ``uv.lock`` + ``.python-version`` +
runner metadata. Later RUN phases (stage execution) have no network.

Sealing is best-effort in the CLI: if ``uv`` is absent, or ``--no-seal`` is
passed, we still record the ``env_lock`` (it is a pure hash of the pinned lock),
and stage execution can fall back to the system interpreter (see stages.py). The
digest is what the trust surface binds; the materialized venv is a local cache.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from blind.runtime.bundle import Bundle


@dataclass
class SealResult:
    env_lock: str
    sealed: bool  # did `uv sync` actually run?
    detail: str


def uv_available() -> bool:
    return shutil.which("uv") is not None


def seal_env(bundle: Bundle, *, no_seal: bool = False, timeout: int = 600) -> SealResult:
    """Run the BUILD phase and record ``env_lock``. Writes the digest to the
    bundle's ``env_lock`` file for offline re-verification."""
    env_lock = bundle.compute_env_lock()
    (bundle.root / "env_lock").write_text(env_lock + "\n")
    # Persist the recomputed canonical digest too, for `applications verify` offline.
    (bundle.root / ".digest").write_text(bundle.digest + "\n")

    if no_seal or not uv_available():
        detail = "skipped (--no-seal)" if no_seal else "uv not found; recorded env_lock only"
        return SealResult(env_lock=env_lock, sealed=False, detail=detail)

    try:
        subprocess.run(
            ["uv", "--project", "env", "sync", "--frozen", "--no-dev"],
            cwd=str(bundle.root),
            check=True,
            capture_output=True,
            timeout=timeout,
        )
        return SealResult(env_lock=env_lock, sealed=True, detail="uv sync --frozen --no-dev ok")
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode("utf-8", "replace")[-500:]
        return SealResult(env_lock=env_lock, sealed=False, detail=f"uv sync failed: {stderr}")
    except subprocess.TimeoutExpired:
        return SealResult(env_lock=env_lock, sealed=False, detail="uv sync timed out")


def verify_env_lock(bundle: Bundle) -> bool:
    """Re-verify the recorded ``env_lock`` equals a fresh recomputation (offline)."""
    recorded_path = bundle.root / "env_lock"
    if not recorded_path.exists():
        return False
    recorded = recorded_path.read_text().strip()
    return recorded == bundle.compute_env_lock()
