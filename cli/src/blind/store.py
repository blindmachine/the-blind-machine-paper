"""~/.blind local state: config.yml, auth tokens, applications, keys, results.

Everything the CLI persists lives under the fixed ``~/.blind`` root. Restrictive
permissions are enforced: the root is 0700, token and fallback-key files 0600.
Tests inject a temporary root directly rather than accepting a path from the
process environment.

Secret keys live in the OS keychain via ``keyring``; the on-disk tree holds only
a *reference*. Keyring failure is fatal by default. A plaintext 0600 backend is
available only through the explicit ``BLIND_SECRET_BACKEND=file`` escape hatch.
No secret material ever has an upload path (COMMANDS.md invariant).
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path

import yaml

from blind.errors import UsageError, VerificationError

KEYRING_SERVICE = "blindmachine"
DEFAULT_API = "https://blindmachine.org"

# The `<name>@local` sentinel: an UNPINNED local bundle used ONLY by the
# `bench`/`simulate` offline conventions (e.g. the paper's E1–E4 reproduction
# harness copies a signed bundle to `<name>@local`). Its trust surface is its
# OWN bytes — signature-, structure-, and env-lock-verified — but it carries no
# EXTERNAL 64-hex digest to pin against. Server, contribution, and decrypt flows
# NEVER use this sentinel: those inputs always carry a real sha256 digest, so
# accepting `local` here cannot reopen the fail-open class.
LOCAL_DIGEST_SENTINEL = "local"

# Hosts allowed to speak cleartext http:// — only the local loopback (Rails dev
# on http://localhost:PORT). Any other http:// host would leak the bearer token
# on the wire.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def enforce_https(url: str) -> str:
    """Return `url` unchanged when it is safe to send a bearer token to, else
    raise. https:// is always allowed; http:// only for a loopback host. A
    non-loopback http:// URL — a stale/planted config value or a typo'd `--api`
    — must never receive a token, so it is refused rather than silently used.
    """
    from urllib.parse import urlparse

    if not isinstance(url, str) or not url or url != url.strip():
        raise UsageError("Server URL must be a non-empty URL without surrounding whitespace")
    parsed = urlparse(url)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise UsageError(f"Refusing an invalid server URL: {url}") from exc
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise UsageError(
            "Server URL must contain only a scheme, hostname, and optional port",
            detail="Credentials, paths, queries, and fragments are not allowed in the API base URL.",
        )
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
    """Return the one production state root; callers cannot redirect secrets."""
    return (Path.home() / ".blind").absolute()


def validate_component(value: str | int, label: str) -> str:
    component = str(value).strip()
    reserved = component.split(".", 1)[0].upper() in _WINDOWS_RESERVED
    if (
        not _COMPONENT_PATTERN.fullmatch(component)
        or component in {".", ".."}
        or component.endswith(".")
        or reserved
    ):
        raise UsageError(
            f"Invalid {label}: {component!r}",
            detail="Identifiers must be one 1-128 character ASCII path component.",
        )
    return component


def validate_digest(value: str, label: str = "SHA-256 digest") -> str:
    digest = str(value).strip().lower()
    for prefix in ("sha256:", "sha256-"):
        if digest.startswith(prefix):
            digest = digest[len(prefix):]
    if not _DIGEST_PATTERN.fullmatch(digest):
        raise VerificationError(f"Invalid {label}; expected exactly 64 hexadecimal characters")
    return digest


def _chmod(path: Path, mode: int) -> None:
    os.chmod(path, mode, follow_symlinks=False)
    if os.name == "posix" and stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != mode:
        raise VerificationError(f"Could not enforce permissions {oct(mode)} on {path}")


def _ensure_dir(path: Path, mode: int = 0o700) -> Path:
    if path.is_symlink():
        raise VerificationError(f"Refusing a symlinked private directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise VerificationError(f"Private storage path is not a regular directory: {path}")
    _chmod(path, mode)
    return path


def _atomic_write(path: Path, data: str | bytes, mode: int = 0o600) -> Path:
    """Atomically replace ``path`` without following an existing final symlink."""
    _ensure_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(fd, mode)
        payload = data.encode("utf-8") if isinstance(data, str) else data
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        _chmod(path, mode)
        return path
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    finally:
        temp_path.unlink(missing_ok=True)


def _validate_private_file_info(
    info: os.stat_result, path: Path, label: str, *, max_bytes: int
) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise VerificationError(f"Refusing non-regular {label}: {path}")
    if info.st_size > max_bytes:
        raise VerificationError(f"Refusing oversized {label}: {path}")
    if os.name == "posix":
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise VerificationError(f"{label.capitalize()} permissions are too open: {path}")
        if info.st_uid != os.geteuid():
            raise VerificationError(f"{label.capitalize()} is not owned by the current user: {path}")


def _read_private_text(path: Path, label: str, *, max_bytes: int) -> str | None:
    if path.is_symlink():
        raise VerificationError(f"Refusing symlinked {label}: {path}")
    if not path.exists():
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(f"Could not securely open {label}: {path}") from exc
    try:
        info = os.fstat(fd)
        _validate_private_file_info(info, path, label, max_bytes=max_bytes)
        with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as handle:
            fd = -1
            try:
                data = handle.read(max_bytes + 1)
            except UnicodeError as exc:
                raise VerificationError(f"{label.capitalize()} is not valid UTF-8: {path}") from exc
            if len(data.encode("utf-8")) > max_bytes:
                raise VerificationError(f"Refusing oversized {label}: {path}")
            return data
    finally:
        if fd >= 0:
            os.close(fd)


class Store:
    """Filesystem + keychain gateway for ~/.blind."""

    def __init__(self, home: Path | None = None):
        selected = Path(home).expanduser() if home is not None else blind_home()
        if not selected.is_absolute():
            raise UsageError("Local state directory must be an absolute path")
        self.home = selected.absolute()
        if self.home.exists() and self.home.is_symlink():
            raise VerificationError("The private state root may not be a symlink")

    def _path(self, *components: str) -> Path:
        candidate = self.home.joinpath(*components)
        root = self.home.resolve(strict=False)
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise VerificationError("Computed local-state path escapes the private state root")
        if candidate.exists() and candidate.is_symlink():
            raise VerificationError(f"Refusing symlinked local-state path: {candidate}")
        current = self.home
        for component in components[:-1]:
            current = current / component
            if current.exists() and current.is_symlink():
                raise VerificationError(f"Refusing symlinked local-state path: {current}")
        return candidate

    # -- directory layout ---------------------------------------------------
    def ensure_layout(self) -> None:
        _ensure_dir(self.home, 0o700)
        for sub in ("auth", "applications", "keys/projects", "cache/encoded",
                    "cache/encrypted", "cache/uv", "results", "simulations", "logs", "tmp"):
            _ensure_dir(self._path(*sub.split("/")), 0o700)

    def temporary_root(self) -> Path:
        """Return the private host scratch root after enforcing its layout."""
        self.ensure_layout()
        return self._path("tmp")

    def uv_cache_dir(self, bundle_digest: str) -> Path:
        """Return an isolated, private build cache for one verified bundle digest."""
        digest = validate_digest(bundle_digest, "bundle digest")
        self.ensure_layout()
        return _ensure_dir(self._path("cache", "uv", digest), 0o700)

    @property
    def config_path(self) -> Path:
        return self._path("config.yml")

    def auth_path(self, profile: str) -> Path:
        profile = validate_component(profile, "profile")
        return self._path("auth", f"{profile}.token")

    def application_dir(self, application_id: str) -> Path:
        # application_id is `name@<digest>`. The digest reaches us in two legitimate
        # encodings — the server's bare 64-hex (what `applications install` pins) and
        # the CLI's canonical `sha256:<hex>` (what `bundle.application_id` / project
        # meta carry). Canonicalize to bare hex so BOTH map to the SAME directory;
        # otherwise install writes `name@<hex>` but `keys create`/`decrypt` later
        # look for `name@sha256-<hex>` and the bundle "isn't installed".
        if application_id.count("@") > 1:
            raise UsageError("Application identifier must contain at most one '@'")
        if "@" in application_id:
            name, digest = application_id.split("@", 1)
            name = validate_component(name, "application name")
            if digest == LOCAL_DIGEST_SENTINEL:
                # `<name>@local` is the local-bench/simulate sentinel: an unpinned
                # bundle whose digest IS its own bytes, so there is no external
                # 64-hex digest to validate. Server/contribution/decrypt flows
                # always carry a real sha256 digest and go through the branch below.
                safe = f"{name}@{LOCAL_DIGEST_SENTINEL}"
            else:
                digest = validate_digest(digest, "application digest")
                safe = f"{name}@{digest}"
        else:
            safe = validate_component(application_id, "application name")
        return self._path("applications", safe)

    def key_dir(self, project_id: str) -> Path:
        # project_id often arrives as an int (straight from a JSON body/cert);
        # coerce so `home / ... / project_id` never trips on Path / int.
        project = validate_component(project_id, "project id")
        return self._path("keys", "projects", project)

    def result_dir(self, project_id: str, job_id: str) -> Path:
        project = validate_component(project_id, "project id")
        job = validate_component(job_id, "job id")
        return self._path("results", project, job)

    def simulation_dir(self, sim_hash: str) -> Path:
        digest = validate_digest(sim_hash, "simulation hash")
        return self._path("simulations", digest)

    # -- config.yml ---------------------------------------------------------
    def load_config(self) -> dict:
        raw = _read_private_text(self.config_path, "configuration file", max_bytes=1024 * 1024)
        data = yaml.safe_load(raw) if raw is not None else {}
        data = data or {}
        if not isinstance(data, dict):
            raise VerificationError("Configuration file must contain a mapping")
        data.setdefault("api", DEFAULT_API)
        data.setdefault("profile", "default")
        data.setdefault("color", "auto")
        data.setdefault("json", False)
        return data

    def save_config(self, config: dict) -> None:
        self.ensure_layout()
        _atomic_write(self.config_path, yaml.safe_dump(config, sort_keys=True))

    def set_config(self, key: str, value) -> dict:
        cfg = self.load_config()
        cfg[key] = value
        self.save_config(cfg)
        return cfg

    # -- auth tokens --------------------------------------------------------
    def save_token(self, profile: str, token: str) -> Path:
        self.ensure_layout()
        p = self.auth_path(profile)
        return _atomic_write(p, token.strip() + "\n")

    def load_token(self, profile: str) -> str | None:
        p = self.auth_path(profile)
        token = _read_private_text(p, "token file", max_bytes=64 * 1024)  # gitleaks:allow
        return (token.strip() or None) if token is not None else None

    def delete_token(self, profile: str) -> bool:
        p = self.auth_path(profile)
        if p.exists():
            if p.is_symlink() or not p.is_file():
                raise VerificationError(f"Refusing non-regular token file: {p}")
            p.unlink()
            return True
        return False

    # -- secret key material (keychain, explicit file escape hatch) ---------
    def secret_backend(self) -> str:
        backend = os.environ.get("BLIND_SECRET_BACKEND", "keyring").strip().lower()
        if backend not in {"keyring", "file"}:
            raise UsageError("BLIND_SECRET_BACKEND must be 'keyring' or 'file'")
        return backend

    def _keyring(self):
        if self.secret_backend() == "file":
            return None
        try:
            import keyring

            return keyring
        except Exception as exc:
            raise VerificationError(
                "OS keychain is unavailable; refusing to store private keys on disk",
                detail="Repair the keychain, or explicitly accept plaintext storage with "
                "BLIND_SECRET_BACKEND=file.",
            ) from exc

    def _store_file_secret(self, project_id: str, filename: str, secret: str) -> str:
        d = _ensure_dir(self.key_dir(project_id))
        _atomic_write(d / filename, secret)
        return "file"

    @staticmethod
    def _read_private_file(path: Path) -> str | None:
        return _read_private_text(
            path, "private-key file", max_bytes=64 * 1024 * 1024  # gitleaks:allow
        )

    def store_secret(self, project_id: str, secret: str) -> str:
        """Persist a project's secret key material. Returns the backend used:
        'keychain' or 'file'. Never uploaded — there is no endpoint for it."""
        project_id = validate_component(project_id, "project id")
        if self.secret_backend() == "file":
            return self._store_file_secret(project_id, "private.key", secret)
        kr = self._keyring()
        account = f"project:{project_id}"
        try:
            kr.set_password(KEYRING_SERVICE, account, secret)
        except Exception as exc:
            raise VerificationError(
                "OS keychain rejected the private key; no plaintext fallback was written",
                detail="Repair the keychain, or explicitly set BLIND_SECRET_BACKEND=file.",
            ) from exc
        d = _ensure_dir(self.key_dir(project_id))
        _atomic_write(d / "private.ref", f"{KEYRING_SERVICE}:{account}\n")
        (d / "private.key").unlink(missing_ok=True)
        return "keychain"

    def load_secret(self, project_id: str) -> tuple[str | None, str | None]:
        """Return (secret, backend). backend in {'keychain','file',None}."""
        project_id = validate_component(project_id, "project id")
        if self.secret_backend() == "keyring":
            kr = self._keyring()
            account = f"project:{project_id}"
            try:
                secret = kr.get_password(KEYRING_SERVICE, account)
                if secret is not None:
                    return secret, "keychain"
            except Exception as exc:
                raise VerificationError("Could not read the private key from the OS keychain") from exc
            fallback = self.key_dir(project_id) / "private.key"
            if fallback.exists():
                raise VerificationError(
                    "A plaintext private key exists but BLIND_SECRET_BACKEND is not explicitly 'file'"
                )
            return None, None
        f = self.key_dir(project_id) / "private.key"
        return (secret, "file") if (secret := self._read_private_file(f)) is not None else (None, None)

    # -- owner Ed25519 signing key (RFC 0003; distinct slot from the FHE secret) --
    def store_signing_key(self, project_id: str, private_hex: str) -> str:
        """Persist a project's OWNER signing private key (hex). Kept in a keychain
        account SEPARATE from the FHE secret (`:owner_signing` suffix) so the two
        never collide. Returns the backend used ('keychain' or 'file'). Like the FHE
        secret, it has no upload path — the public half is what leaves the machine."""
        project_id = validate_component(project_id, "project id")
        if self.secret_backend() == "file":
            return self._store_file_secret(project_id, "owner_signing.key", private_hex)
        kr = self._keyring()
        account = f"project:{project_id}:owner_signing"
        try:
            kr.set_password(KEYRING_SERVICE, account, private_hex)
        except Exception as exc:
            raise VerificationError(
                "OS keychain rejected the owner signing key; no plaintext fallback was written",
                detail="Repair the keychain, or explicitly set BLIND_SECRET_BACKEND=file.",
            ) from exc
        d = _ensure_dir(self.key_dir(project_id))
        _atomic_write(d / "owner_signing.ref", f"{KEYRING_SERVICE}:{account}\n")
        (d / "owner_signing.key").unlink(missing_ok=True)
        return "keychain"

    def load_signing_key(self, project_id: str) -> tuple[str | None, str | None]:
        """Return (private_hex, backend). backend in {'keychain','file',None}."""
        project_id = validate_component(project_id, "project id")
        if self.secret_backend() == "keyring":
            kr = self._keyring()
            account = f"project:{project_id}:owner_signing"
            try:
                secret = kr.get_password(KEYRING_SERVICE, account)
                if secret is not None:
                    return secret, "keychain"
            except Exception as exc:
                raise VerificationError("Could not read the signing key from the OS keychain") from exc
            fallback = self.key_dir(project_id) / "owner_signing.key"
            if fallback.exists():
                raise VerificationError(
                    "A plaintext signing key exists but BLIND_SECRET_BACKEND is not explicitly 'file'"
                )
            return None, None
        f = self.key_dir(project_id) / "owner_signing.key"
        secret = self._read_private_file(f)
        return (secret.strip(), "file") if secret is not None else (None, None)

    def delete_secret(self, project_id: str) -> bool:
        project_id = validate_component(project_id, "project id")
        removed = False
        kr = self._keyring()
        if kr is not None:
            # Sweep BOTH the FHE secret and the owner signing key accounts.
            for account in (f"project:{project_id}", f"project:{project_id}:owner_signing"):
                try:
                    present = kr.get_password(KEYRING_SERVICE, account)
                except Exception as exc:
                    raise VerificationError("Could not inspect the OS keychain before deletion") from exc
                if present is None:
                    continue
                try:
                    kr.delete_password(KEYRING_SERVICE, account)
                except Exception as exc:
                    raise VerificationError("OS keychain refused to delete private key material") from exc
                removed = True
        d = self.key_dir(project_id)
        if d.exists():
            allowed = {
                "private.key", "private.ref", "owner_signing.key", "owner_signing.ref",
                "owner_signing.pub", "public.context", "meta.yml",
            }
            entries = list(d.iterdir())
            unexpected = [entry.name for entry in entries if entry.name not in allowed]
            if unexpected:
                raise VerificationError(
                    f"Refusing to delete project key directory with unexpected entries: {unexpected}"
                )
            for f in entries:
                if f.is_symlink() or not f.is_file():
                    raise VerificationError(f"Refusing non-regular key artifact: {f}")
                f.unlink()
            d.rmdir()
            removed = True
        return removed

    # -- perms audit (doctor) ----------------------------------------------
    @staticmethod
    def _permission_mode(path: Path) -> int:
        return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)

    def perms_report(self) -> dict:
        report = {"home": None, "auth": None, "world_readable": []}
        if self.home.exists():
            report["home"] = oct(self._permission_mode(self.home))
        auth = self.home / "auth"
        if auth.exists():
            report["auth"] = oct(self._permission_mode(auth))
        # Flag any token/key file that is group- or world-readable.
        for pattern in (
            "config.yml", "auth/*.token", "keys/projects/*/private.key",
            "keys/projects/*/owner_signing.key", "keys/projects/*/*.ref",
        ):
            for f in self.home.glob(pattern):
                if f.is_symlink() or not f.is_file():
                    report["world_readable"].append(str(f))
                    continue
                mode = self._permission_mode(f)
                if mode & 0o077:
                    report["world_readable"].append(str(f))
        return report
