"""Environment sealing inside the digest-pinned container build boundary.

The BUILD phase — network allowed, NO data — runs

    uv --project env sync --frozen --no-dev

inside a data-free container to materialize the pinned environment from ``env/uv.lock``,
then records an ``env_lock`` digest over ``uv.lock`` + ``.python-version`` +
runner metadata. Later RUN phases have no network. Normal operation fails closed:
there is no system-interpreter fallback and an unsuccessful build is not installable.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from blind.errors import VerificationError
from blind.runtime.bundle import Bundle
from blind.runtime.sandbox import ContainerSandbox, unsafe_direct_enabled
from blind.store import Store


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
    if no_seal or os.environ.get("BLIND_UNSAFE_SKIP_SEAL", "").strip() == "1":
        if not unsafe_direct_enabled():
            raise VerificationError(
                "Skipping environment sealing is restricted to explicit unsafe tests"
            )
        detail = "UNSAFE test-only seal bypass"
        sealed = False
    else:
        # A signed application's build can execute arbitrary package build hooks.
        # Give each digest its own cache so it cannot poison another application's
        # future environment build through a shared writable uv cache.
        cache = Store().uv_cache_dir(bundle.digest)
        ContainerSandbox().build_environment(bundle.root, cache, timeout=timeout)
        # A build backend executes arbitrary code. The signed tree is mounted ro,
        # and this post-build check proves it did not change through another path.
        from blind.runtime.bundle import verify_digest

        verify_digest(bundle.package_root or bundle.root, bundle.digest)
        detail = "container build ok; signed payload reverified"
        sealed = True

    (bundle.root / "env_lock").write_text(env_lock + "\n")
    (bundle.root / ".digest").write_text(bundle.digest + "\n")
    return SealResult(env_lock=env_lock, sealed=sealed, detail=detail)


def verify_env_lock(bundle: Bundle) -> bool:
    """Re-verify the recorded ``env_lock`` equals a fresh recomputation (offline)."""
    recorded_path = bundle.root / "env_lock"
    if not recorded_path.exists():
        return False
    recorded = recorded_path.read_text().strip()
    return recorded == bundle.compute_env_lock()
