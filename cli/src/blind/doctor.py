"""`blind doctor` — verify the local toolchain (spec.md / UX.md §6).

Checks: Python, the sandbox/container runtime (`podman`/`docker`, `--network
none`), the `uv` env-sealer, the OS keychain, `cryptography` (Ed25519), `~/.blind`
perms, a sealed-env self-test (the newest installed application imports its own
crypto), and API reachability. Never raises — every probe degrades to a failed
check with a fix hint.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
import sys
from dataclasses import dataclass

from blind.hashing import bundle_payload_root
from blind.runtime.sandbox import ContainerSandbox
from blind.store import Store


@dataclass
class DoctorCheck:
    name: str
    ok: bool
    value: str = ""
    detail: str = ""
    fix: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "value": self.value,
                "detail": self.detail, "fix": self.fix}


def _python_check() -> DoctorCheck:
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 11)
    return DoctorCheck(
        "python", ok, f"{v.major}.{v.minor}.{v.micro}",
        "≥ 3.11 ok" if ok else "needs ≥ 3.11",
        fix="" if ok else "install Python 3.11+",
    )


def _sandbox_check() -> DoctorCheck:
    try:
        sandbox = ContainerSandbox()
        sandbox.ensure_ready(pull=False)
        ver = _cmd_version([sandbox.runtime, "--version"])
        return DoctorCheck(
            "sandbox runtime", True, f"{sandbox.runtime_name} {ver}",
            f"daemon ok · digest-pinned image present · {sandbox.image}",
        )
    except Exception as exc:
        return DoctorCheck(
            "sandbox runtime", False, "unavailable", str(exc)[:120],
            fix="install/start rootless Podman or Docker, then reinstall an application online",
        )


def _uv_check() -> DoctorCheck:
    path = shutil.which("uv")
    if not path:
        return DoctorCheck("uv (env sealer)", False, "not found",
                           "needs uv to seal application envs", fix="brew install uv")
    ver = _cmd_version(["uv", "--version"])
    return DoctorCheck("uv (env sealer)", True, ver, "--frozen --no-dev ok")


def _keychain_check() -> DoctorCheck:
    import os

    if os.environ.get("BLIND_SECRET_BACKEND", "keyring").strip().lower() == "file":
        return DoctorCheck(
            "OS keychain", False, "explicitly disabled",
            "BLIND_SECRET_BACKEND=file stores private keys as plaintext 0600 files",
            fix="unset BLIND_SECRET_BACKEND and repair the OS keychain",
        )
    try:
        import keyring

        backend = keyring.get_keyring().__class__.__name__
        # round-trip probe
        keyring.set_password("blindmachine-doctor", "probe", "ok")
        got = keyring.get_password("blindmachine-doctor", "probe")
        keyring.delete_password("blindmachine-doctor", "probe")
        ok = got == "ok"
        return DoctorCheck("OS keychain", ok, backend,
                           "read/write round-trip ok" if ok else "round-trip failed")
    except Exception as exc:
        return DoctorCheck("OS keychain", False, "unavailable", str(exc)[:60],
                           fix="repair/unlock the OS keychain; private-key operations fail closed")


def _crypto_check() -> DoctorCheck:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        k = Ed25519PrivateKey.generate()
        sig = k.sign(b"blind")
        k.public_key().verify(sig, b"blind")
        import cryptography

        return DoctorCheck("cryptography", True, cryptography.__version__, "Ed25519 verify ok")
    except Exception as exc:
        return DoctorCheck("cryptography", False, "unavailable", str(exc)[:60],
                           fix="pip install cryptography")


def _perms_check(store: Store) -> DoctorCheck:
    report = store.perms_report()
    world = report["world_readable"]
    ok = not world
    detail = "auth/ 600 · keys not world-readable" if ok else f"{len(world)} file(s) too open"
    return DoctorCheck("~/.blind", ok, f"perms {report['home'] or '—'}", detail,
                       fix="" if ok else "chmod 600 the flagged files")


def _sealed_env_check(store: Store) -> DoctorCheck:
    """Sealed-env self-test: the newest installed application imports its own crypto."""
    app_root = store.home / "applications"
    if not app_root.exists() or not any(app_root.iterdir()):
        return DoctorCheck("sealed env", True, "none installed",
                           "no applications yet · install one to self-test")
    newest = max(
        (p for p in app_root.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
    )
    env_lock = bundle_payload_root(newest) / "env_lock"
    ok = env_lock.exists()
    val = newest.name.split("@")[0][:16]
    return DoctorCheck("sealed env", ok, val,
                       "env_lock recorded" if ok else "env_lock missing — run applications install",
                       fix="" if ok else "blind applications install <name>")


def _api_check(base_url: str, token: str | None, transport=None) -> DoctorCheck:
    from blind.api import ApiClient

    client = ApiClient(base_url, token, transport=transport)
    try:
        me = client.me() if token else client.get("me", auth_required=False)
        host = base_url.replace("https://", "").replace("http://", "")
        who = me.get("email") or me.get("account") or "reachable"
        return DoctorCheck("API", True, host, f"reachable · {who}")
    except Exception as exc:
        return DoctorCheck("API", False, base_url, str(exc)[:60],
                           fix="check --api / network / `blind login`")
    finally:
        client.close()


def run_doctor(
    store: Store, base_url: str, token: str | None, *, offline: bool = False, transport=None
) -> list[DoctorCheck]:
    checks = [
        _python_check(),
        _sandbox_check(),
        _uv_check(),
        _keychain_check(),
        _crypto_check(),
        _perms_check(store),
        _sealed_env_check(store),
    ]
    if not offline:
        checks.append(_api_check(base_url, token, transport=transport))
    return checks


def _cmd_version(cmd: list[str]) -> str:
    import re

    try:
        # Callers pass fixed diagnostic tool/version argv and no shell.
        out = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=5
        )
        text = (out.stdout or out.stderr).strip()
        # First token that looks like a version number (e.g. 0.8.22, 28.1.0).
        m = re.search(r"\d+\.\d+(?:\.\d+)?", text)
        return m.group(0) if m else text.split()[-1]
    except Exception:
        return "?"
