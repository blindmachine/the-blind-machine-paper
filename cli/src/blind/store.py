"""~/.blind local state: config.yml, auth tokens, applications, keys, results.

Everything the CLI persists lives under a single root (default ``~/.blind``,
overridable with ``$BLIND_HOME`` — the tests point it at a temp dir). Restrictive
permissions are enforced: the root is 0700, token and fallback-key files 0600.

Secret keys live in the OS keychain via ``keyring``; the on-disk tree holds only
a *reference*. When keyring is unavailable (headless CI, or ``$BLIND_NO_KEYRING``)
we fall back to a 0600 file and record that fact so ``keys retrieve`` / ``doctor``
can report it. No secret material ever has an upload path (COMMANDS.md invariant).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import yaml

KEYRING_SERVICE = "blindmachine"
DEFAULT_API = "https://blindmachine.org"

# Hosts allowed to speak cleartext http:// — only the local loopback (Rails dev
# on http://localhost:PORT). Any other http:// host would leak the bearer token
# on the wire.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def enforce_https(url: str) -> str:
    """Return `url` unchanged when it is safe to send a bearer token to, else
    raise. https:// is always allowed; http:// only for a loopback host. A
    non-loopback http:// URL — a stale/planted config value or a typo'd `--api`
    — must never receive a token, so it is refused rather than silently used.
    """
    from urllib.parse import urlparse

    from blind.errors import UsageError

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        return url
    if scheme == "http" and (parsed.hostname or "").lower() in LOOPBACK_HOSTS:
        return url

    raise UsageError(
        f"Refusing an insecure server URL: {url}",
        detail="Only https:// (or http:// to localhost) is allowed — a bearer token must never travel in cleartext.",
    )


def blind_home() -> Path:
    return Path(os.environ.get("BLIND_HOME", str(Path.home() / ".blind")))


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _ensure_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _chmod(path, mode)
    return path


class Store:
    """Filesystem + keychain gateway for ~/.blind."""

    def __init__(self, home: Path | None = None):
        self.home = home or blind_home()

    # -- directory layout ---------------------------------------------------
    def ensure_layout(self) -> None:
        _ensure_dir(self.home, 0o700)
        for sub in ("auth", "applications", "keys/projects", "cache/encoded",
                    "cache/encrypted", "results", "simulations", "logs"):
            _ensure_dir(self.home / sub, 0o700)

    @property
    def config_path(self) -> Path:
        return self.home / "config.yml"

    def auth_path(self, profile: str) -> Path:
        return self.home / "auth" / f"{profile}.token"

    def application_dir(self, application_id: str) -> Path:
        # application_id is `name@<digest>`. The digest reaches us in two legitimate
        # encodings — the server's bare 64-hex (what `applications install` pins) and
        # the CLI's canonical `sha256:<hex>` (what `bundle.application_id` / project
        # meta carry). Canonicalize to bare hex so BOTH map to the SAME directory;
        # otherwise install writes `name@<hex>` but `keys create`/`decrypt` later
        # look for `name@sha256-<hex>` and the bundle "isn't installed".
        if "@" in application_id:
            name, digest = application_id.split("@", 1)
            digest = digest.strip().lower()
            for prefix in ("sha256:", "sha256-"):
                if digest.startswith(prefix):
                    digest = digest[len(prefix):]
            safe = f"{name}@{digest}"
        else:
            safe = application_id.replace(":", "-")
        return self.home / "applications" / safe

    def key_dir(self, project_id: str) -> Path:
        # project_id often arrives as an int (straight from a JSON body/cert);
        # coerce so `home / ... / project_id` never trips on Path / int.
        return self.home / "keys" / "projects" / str(project_id)

    def result_dir(self, project_id: str, job_id: str) -> Path:
        return self.home / "results" / str(project_id) / str(job_id)

    def simulation_dir(self, sim_hash: str) -> Path:
        return self.home / "simulations" / sim_hash

    # -- config.yml ---------------------------------------------------------
    def load_config(self) -> dict:
        if self.config_path.exists():
            data = yaml.safe_load(self.config_path.read_text()) or {}
        else:
            data = {}
        data.setdefault("api", DEFAULT_API)
        data.setdefault("profile", "default")
        data.setdefault("color", "auto")
        data.setdefault("json", False)
        return data

    def save_config(self, config: dict) -> None:
        self.ensure_layout()
        self.config_path.write_text(yaml.safe_dump(config, sort_keys=True))
        _chmod(self.config_path, 0o600)

    def set_config(self, key: str, value) -> dict:
        cfg = self.load_config()
        cfg[key] = value
        self.save_config(cfg)
        return cfg

    # -- auth tokens --------------------------------------------------------
    def save_token(self, profile: str, token: str) -> Path:
        self.ensure_layout()
        p = self.auth_path(profile)
        p.write_text(token.strip() + "\n")
        _chmod(p, 0o600)
        return p

    def load_token(self, profile: str) -> str | None:
        p = self.auth_path(profile)
        if p.exists():
            return p.read_text().strip() or None
        return None

    def delete_token(self, profile: str) -> bool:
        p = self.auth_path(profile)
        if p.exists():
            p.unlink()
            return True
        return False

    # -- secret key material (keychain, with file fallback) -----------------
    def _keyring(self):
        if os.environ.get("BLIND_NO_KEYRING"):
            return None
        try:
            import keyring  # lazy: absence must not crash imports

            return keyring
        except Exception:
            return None

    def store_secret(self, project_id: str, secret: str) -> str:
        """Persist a project's secret key material. Returns the backend used:
        'keychain' or 'file'. Never uploaded — there is no endpoint for it."""
        kr = self._keyring()
        account = f"project:{project_id}"
        if kr is not None:
            try:
                kr.set_password(KEYRING_SERVICE, account, secret)
                d = _ensure_dir(self.key_dir(project_id))
                (d / "private.ref").write_text(f"{KEYRING_SERVICE}:{account}\n")
                _chmod(d / "private.ref", 0o600)
                return "keychain"
            except Exception:
                pass
        # Fallback: 0600 file (doctor + keys retrieve will report this).
        d = _ensure_dir(self.key_dir(project_id))
        f = d / "private.key"
        f.write_text(secret)
        _chmod(f, 0o600)
        return "file"

    def load_secret(self, project_id: str) -> tuple[str | None, str | None]:
        """Return (secret, backend). backend in {'keychain','file',None}."""
        kr = self._keyring()
        account = f"project:{project_id}"
        if kr is not None:
            try:
                secret = kr.get_password(KEYRING_SERVICE, account)
                if secret is not None:
                    return secret, "keychain"
            except Exception:
                pass
        f = self.key_dir(project_id) / "private.key"
        if f.exists():
            return f.read_text(), "file"
        return None, None

    def delete_secret(self, project_id: str) -> bool:
        removed = False
        kr = self._keyring()
        account = f"project:{project_id}"
        if kr is not None:
            try:
                kr.delete_password(KEYRING_SERVICE, account)
                removed = True
            except Exception:
                pass
        d = self.key_dir(project_id)
        if d.exists():
            for f in d.iterdir():
                f.unlink()
            d.rmdir()
            removed = True
        return removed

    # -- perms audit (doctor) ----------------------------------------------
    def perms_report(self) -> dict:
        report = {"home": None, "auth": None, "world_readable": []}
        if self.home.exists():
            report["home"] = oct(stat.S_IMODE(self.home.stat().st_mode))
        auth = self.home / "auth"
        if auth.exists():
            report["auth"] = oct(stat.S_IMODE(auth.stat().st_mode))
        # Flag any token/key file that is group- or world-readable.
        for pattern in ("auth/*.token", "keys/projects/*/private.key"):
            for f in self.home.glob(pattern):
                mode = stat.S_IMODE(f.stat().st_mode)
                if mode & 0o077:
                    report["world_readable"].append(str(f))
        return report
