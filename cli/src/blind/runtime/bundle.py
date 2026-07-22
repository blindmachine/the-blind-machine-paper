"""Load, content-address, and signature-verify an application bundle.

An application package is the fixed uv-native layout (application_structure.md):

    signed/{manifest.yml, server.py, local_*.py, env/}
    README.md
    SECURITY.md
    tests/
    .blind-signature

The client-side supply-chain gate (COMMANDS.md `applications install`/`verify`):
the recomputed canonical digest must equal the name suffix AND the server's, and
The Blind Machine Ed25519 signature over that digest must validate, or the
bundle will not load.
"""

from __future__ import annotations

import tarfile
import os
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from blind.errors import UsageError, VerificationError
from blind.hashing import (
    DERIVED_BUNDLE_FILES,
    EXCLUDED_BUNDLE_COMPONENTS,
    EXCLUDED_BUNDLE_SUFFIXES,
    RUNTIME_SHIM_FILES,
    SIGNED_BUNDLE_DIR,
    bundle_payload_root,
    canonical_bundle_digest,
    digests_match,
    env_lock_digest,
    normalize_digest,
    split_application_id,
)

STAGE_FILES = {
    "keygen": "00_keygen.py",
    "encode": "10_encode.py",
    "encrypt": "20_encrypt.py",
    "compute": "30_compute_encrypted.py",
    "decrypt": "40_decrypt.py",
    "decode": "50_decode.py",
}
# Legacy self-contained bundles ship the six numbered stage files. RFC-0002
# new-contract bundles ship the author's pure-function role files instead; the
# numbered shims are materialized at run time (see blind.runtime.shims).
AUTHOR_FILES = ["server.py", "local_project_owner.py", "local_data_owner.py"]
REQUIRED_FILES = ["manifest.yml", *STAGE_FILES.values(), "env/pyproject.toml"]
NEW_CONTRACT_REQUIRED = ["manifest.yml", *AUTHOR_FILES, "env/pyproject.toml"]

# The Blind Machine's Ed25519 bundle-signing PUBLIC key, PINNED into the CLI at
# ship time — the root of the client-side supply-chain trust. A downloaded bundle
# whose `.blind-signature` does not verify against this key (or an explicit
# override) is REFUSED: `applications install` fails closed rather than executing
# unsigned code on the data owner's machine. This value matches config/deploy.yml's
# job-role BLIND_SIGNING_PUBKEY (env.clear). Hardcoding it is the point — the key
# is public (Kerckhoffs) and is rotated only by shipping a CLI update.
_PINNED_SIGNING_KEY_HEX = "7e998cc937c394810eb00702aa9b6fabf1e70adcc2cd91f7bca953b7c312dd36"  # gitleaks:allow

# Explicit dev / self-host override slot. Empty by default; kept as a module
# attribute so tests / self-hosted registries can point verification at their own
# key. $BLIND_SIGNING_KEY overrides at runtime. Resolution NEVER falls back to
# "no key" — verification can therefore never silently no-op.
_BUILTIN_SIGNING_KEY_HEX = ""

_ALL_ZERO_KEY_HEX = "0" * 64
_CUSTOM_KEY_OPT_IN = "BLIND_UNSAFE_ALLOW_CUSTOM_SIGNING_KEY"
_warned_nondefault_key = False


def _reject_weak_key(key_hex: str) -> None:
    """A pinned/override signing key must be a real 32-byte Ed25519 public key.
    Refuse anything that is not exactly 64 hex chars, and refuse the all-zero
    low-order point — a weak key turns 'verified' into 'trivially forgeable'."""
    cleaned = (key_hex or "").strip().lower()
    if len(cleaned) != 64 or any(ch not in "0123456789abcdef" for ch in cleaned):
        raise VerificationError(
            "Bundle-signing key is not a 64-hex Ed25519 public key — refusing to verify"
        )
    if cleaned == _ALL_ZERO_KEY_HEX:
        raise VerificationError(
            "Bundle-signing key is the all-zero (forgeable) key — refusing to verify"
        )


def active_signing_key_hex(override: str | None = None) -> str:
    """Resolve the signing key to verify against: explicit override → $BLIND_SIGNING_KEY
    → module override → the PINNED shipped key. ALWAYS returns a key (never empty),
    so a bundle signature can never be silently skipped. Warns once (to stderr) when
    a non-default key is in force, so a dev/self-host override is visible."""
    global _warned_nondefault_key
    if override:
        return override
    env = os.environ.get("BLIND_SIGNING_KEY", "").strip()
    builtin = (_BUILTIN_SIGNING_KEY_HEX or "").strip()
    chosen = env or builtin or _PINNED_SIGNING_KEY_HEX
    if (
        override is None
        and chosen != _PINNED_SIGNING_KEY_HEX
        and os.environ.get(_CUSTOM_KEY_OPT_IN, "").strip() != "1"
    ):
        raise VerificationError(
            f"A custom signing key requires explicit {_CUSTOM_KEY_OPT_IN}=1 opt-in"
        )
    if chosen != _PINNED_SIGNING_KEY_HEX and not _warned_nondefault_key:
        _warned_nondefault_key = True
        print(
            "warning: verifying bundle signatures against a NON-DEFAULT signing key "
            "(from $BLIND_SIGNING_KEY / override) — unsafe dev / self-host mode.",
            file=sys.stderr,
        )
    return chosen


@dataclass
class Manifest:
    raw: dict

    @property
    def name(self) -> str:
        return self.raw.get("name", "")

    @property
    def crypto(self) -> str:
        return self.raw.get("crypto", "")

    @property
    def computation(self) -> str:
        return self.raw.get("computation", "")

    @property
    def min_contributors(self) -> int:
        return int(self.raw.get("min_contributors", 0))

    @property
    def length(self) -> int:
        """Coordinate length L the stages encode/decode against (manifest
        ``input.length``). 0 when the application has no fixed-length vector input."""
        return int(self.raw.get("input", {}).get("length", 0))

    @property
    def tolerance(self) -> float:
        return float(self.raw.get("output", {}).get("tolerance", 0))

    @property
    def coordinates(self) -> dict:
        return self.raw.get("input", {}).get("coordinates", {})

    @property
    def release_policy(self) -> dict:
        return self.raw.get("release_policy", {})


@dataclass
class Bundle:
    root: Path  # signed payload root; stage execution happens here
    manifest: Manifest
    digest: str  # sha256:<hex>, the canonical bundle digest
    package_root: Path | None = None

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def application_id(self) -> str:
        return f"{self.name}@{self.digest}"

    def stage_file(self, stage: str) -> Path:
        if stage not in STAGE_FILES:
            raise UsageError(f"Unknown stage {stage!r}")
        return self.root / STAGE_FILES[stage]

    def env_dir(self) -> Path:
        return self.root / "env"

    def tests_dir(self) -> Path:
        return (self.package_root or self.root) / "tests"

    def compute_env_lock(self) -> str:
        # Canonical convention: EMPTY runner metadata (the deps-only fingerprint).
        # This is what applications/hash_bundle.py, the Ruby twin, the server DB, and
        # the published reference vector all compute. Runner/platform pinning is
        # carried separately by the @sha256:-pinned runner image, never in env_lock.
        env = self.env_dir()
        uv_lock = (env / "uv.lock").read_bytes() if (env / "uv.lock").exists() else b""
        pyver = (
            (env / ".python-version").read_bytes()
            if (env / ".python-version").exists()
            else b""
        )
        return env_lock_digest(uv_lock, pyver, runner_meta="")


def read_manifest(root: Path) -> Manifest:
    mpath = root / "manifest.yml"
    if not mpath.exists():
        raise UsageError(f"No manifest.yml in {root}")
    data = yaml.safe_load(mpath.read_text()) or {}
    return Manifest(raw=data)


def load_bundle(root: str | Path) -> Bundle:
    """Load a bundle directory, checking the fixed layout and recomputing the digest."""
    package_root = Path(root)
    if not package_root.is_dir():
        raise UsageError(f"Application bundle not found: {package_root}")
    payload_root = bundle_payload_root(package_root)
    if package_root.name == SIGNED_BUNDLE_DIR and package_root.parent.is_dir():
        package_root = package_root.parent
        payload_root = package_root / SIGNED_BUNDLE_DIR
    required = NEW_CONTRACT_REQUIRED if (payload_root / "server.py").is_file() else REQUIRED_FILES
    missing = [f for f in required if not (payload_root / f).exists()]
    if missing:
        raise UsageError(f"Malformed bundle {payload_root}: missing {', '.join(missing)}")
    manifest = read_manifest(payload_root)
    digest = canonical_bundle_digest(package_root)
    return Bundle(root=payload_root, package_root=package_root, manifest=manifest, digest=digest)


# V7.2 — a downloaded bundle is untrusted (a hostile server can serve a
# decompression bomb). Cap the total declared uncompressed size and the entry
# count so extraction cannot exhaust client memory / inodes. A real bundle is a
# few dozen small files; these caps are generous.
_MAX_BUNDLE_BYTES = 32 * 1024 * 1024
_MAX_BUNDLE_MEMBER_BYTES = 8 * 1024 * 1024
_MAX_BUNDLE_ENTRIES = 1024


def verify_download_structure(bundle_root: Path) -> None:
    """Reject unsigned/derived files that could shadow the sealed environment."""
    package_root = Path(bundle_root)
    payload_root = bundle_payload_root(package_root)
    new_contract = (payload_root / "server.py").is_file()
    # The server's archive ships the detached signature at the package root
    # (BundleArchiver: excluded from identity, required for offline review).
    # `applications install` overwrites it with the separately fetched signature
    # before verifying, so its presence in the tar carries no authority.
    allowed_derived = {package_root / ".blind-signature"}
    for path in package_root.rglob("*"):
        relative_package = path.relative_to(package_root)
        relative_payload = path.relative_to(payload_root) if path.is_relative_to(payload_root) else None
        if path.is_symlink():
            raise VerificationError(f"Downloaded bundle contains a symlink: {relative_package}")
        if any(part in EXCLUDED_BUNDLE_COMPONENTS for part in relative_package.parts):
            raise VerificationError(
                f"Downloaded bundle contains an unsigned build artifact: {relative_package}"
            )
        if path.is_file() and path.suffix in EXCLUDED_BUNDLE_SUFFIXES:
            raise VerificationError(
                f"Downloaded bundle contains unsigned bytecode: {relative_package}"
            )
        if path.name in DERIVED_BUNDLE_FILES and path not in allowed_derived:
            raise VerificationError(
                f"Downloaded bundle contains a locally derived file: {relative_package}"
            )
        if (
            new_contract
            and relative_payload is not None
            and relative_payload.as_posix() in RUNTIME_SHIM_FILES
        ):
            raise VerificationError(
                f"Downloaded bundle attempts to shadow a trusted stage shim: {relative_payload}"
            )


def verify_installed_structure(bundle_root: Path) -> None:
    """Reject post-install unsigned artifacts outside the one sealed venv."""
    package_root = Path(bundle_root)
    payload_root = bundle_payload_root(package_root)
    venv_root = payload_root / "env" / ".venv"
    new_contract = (payload_root / "server.py").is_file()
    allowed_derived = {
        package_root / ".blind-signature",
        payload_root / ".digest",
        payload_root / "env_lock",
    }
    for path in package_root.rglob("*"):
        if path == venv_root or path.is_relative_to(venv_root):
            continue
        relative_package = path.relative_to(package_root)
        relative_payload = path.relative_to(payload_root) if path.is_relative_to(payload_root) else None
        if path.is_symlink():
            raise VerificationError(f"Installed bundle contains a symlink: {relative_package}")
        if any(part in EXCLUDED_BUNDLE_COMPONENTS for part in relative_package.parts):
            raise VerificationError(
                f"Installed bundle contains an unsigned build artifact: {relative_package}"
            )
        if path.is_file() and path.suffix in EXCLUDED_BUNDLE_SUFFIXES:
            raise VerificationError(
                f"Installed bundle contains unsigned bytecode: {relative_package}"
            )
        if path.name in DERIVED_BUNDLE_FILES and path not in allowed_derived:
            raise VerificationError(
                f"Installed bundle contains an unexpected derived file: {relative_package}"
            )
        if (
            new_contract
            and relative_payload is not None
            and relative_payload.as_posix() in RUNTIME_SHIM_FILES
        ):
            raise VerificationError(
                f"Installed bundle shadows a trusted stage shim: {relative_payload}"
            )


def extract_bundle(
    tar_bytes: bytes, dest: Path, *, max_bytes: int = _MAX_BUNDLE_BYTES,
    max_entries: int = _MAX_BUNDLE_ENTRIES,
) -> Path:
    """Unpack a downloaded bundle tarball into ``dest`` (the content-addressed dir).

    Members are validated so a malicious tar cannot escape ``dest`` (path
    traversal / absolute paths / symlinks are rejected) and cannot exhaust memory
    or inodes (total-bytes + entry-count caps — V7.2).
    """
    import io

    if len(tar_bytes) > max_bytes:
        raise VerificationError(
            f"Bundle archive is {len(tar_bytes)} bytes, over the {max_bytes}-byte cap")

    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        raise VerificationError(f"Bundle destination is not a private directory: {dest}")
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(dest.iterdir()):
        raise VerificationError("Bundle extraction destination must be empty")
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tf:
        members = tf.getmembers()
        if len(members) > max_entries:
            raise VerificationError(
                f"Bundle tar has {len(members)} entries, over the {max_entries}-entry cap")
        total = 0
        member_names: set[str] = set()
        for member in members:
            name = member.name
            if "\\" in name:
                raise VerificationError(f"Unsafe backslash path in bundle tar: {name!r}")
            path = PurePosixPath(name)
            if (
                path.is_absolute()
                or not path.parts
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise VerificationError(f"Unsafe path in bundle tar: {name!r}")
            canonical_name = path.as_posix()
            if canonical_name in member_names:
                raise VerificationError(f"Duplicate path in bundle tar: {name!r}")
            member_names.add(canonical_name)
            if not (member.isdir() or member.isfile()):
                raise VerificationError(f"Refusing link or special file in bundle tar: {name!r}")
            if member.isfile():
                if member.size < 0 or member.size > _MAX_BUNDLE_MEMBER_BYTES:
                    raise VerificationError(f"Bundle member is too large: {name!r}")
                total += member.size
                if total > max_bytes:
                    raise VerificationError(
                        f"Bundle expands past the {max_bytes}-byte cap — refusing to extract")
        # Flatten an archive wrapper, but preserve the signed/ trust boundary when
        # it is itself the sole top-level directory.
        tops = {PurePosixPath(m.name).parts[0] for m in members if m.name}
        strip = len(tops) == 1 and next(iter(tops)) != SIGNED_BUNDLE_DIR
        targets: set[PurePosixPath] = set()
        for member in members:
            parts = PurePosixPath(member.name).parts
            if strip:
                parts = parts[1:]
            if not parts:
                continue
            relative = PurePosixPath(*parts)
            if relative in targets:
                raise VerificationError(f"Bundle members collide after flattening: {member.name!r}")
            targets.add(relative)
            target = dest.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise VerificationError(f"Could not read bundle member: {member.name!r}")
                payload = extracted.read(member.size + 1)
                if len(payload) != member.size:
                    raise VerificationError(f"Bundle member size mismatch: {member.name!r}")
                with target.open("xb") as handle:
                    handle.write(payload)
    return dest


def verify_digest(bundle_root: Path, expected: str) -> str:
    """Recompute the canonical digest and require it to equal ``expected``.
    Returns the digest on success; raises VerificationError otherwise."""
    actual = canonical_bundle_digest(bundle_root)
    # The server pins bundles by bare 64-hex; the CLI's canonical form is
    # `sha256:<hex>`. Compare on the hex value so the `sha256:` prefix alone can
    # never read as a mismatch (both encode the same SHA-256).
    if expected and not digests_match(actual, expected):
        raise VerificationError(
            f"Bundle digest mismatch: recomputed {actual} != expected {expected}"
        )
    return actual


def verify_signature(bundle_root: Path, *, signing_key_hex: str | None = None) -> bool:
    """Verify the Ed25519 ``.blind-signature`` over the canonical digest against the
    PINNED signing key (or an explicit / $BLIND_SIGNING_KEY override).

    Returns True ONLY on a valid signature by the resolved key. Raises
    VerificationError if the signature is missing, malformed, forged, or the key is
    weak. There is NO 'no key configured → return False' path: a key is always
    pinned (``_PINNED_SIGNING_KEY_HEX``), so the client can never silently accept
    unsigned or server-substituted code. Callers therefore FAIL CLOSED — a bundle
    that does not verify is never sealed or executed.
    """
    sig_path = signature_path(bundle_root)
    if not sig_path.exists():
        raise VerificationError("Bundle is missing .blind-signature")
    if sig_path.is_symlink() or not sig_path.is_file() or sig_path.stat().st_size > 256:
        raise VerificationError("Bundle signature file is not a small regular file")
    key_hex = active_signing_key_hex(signing_key_hex)
    _reject_weak_key(key_hex)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:  # pragma: no cover - dep missing
        raise VerificationError(f"cryptography unavailable for signature verify: {exc}")

    # The curator (BlindMachine::BundleSigner) and the worker verifier both sign /
    # verify over the BARE 64-hex digest string — not the CLI's `sha256:<hex>`
    # canonical form. Sign over the same bytes or every real signature is rejected.
    message = normalize_digest(canonical_bundle_digest(bundle_root)).encode("utf-8")
    try:
        signature = bytes.fromhex(sig_path.read_text().strip())
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    except (OSError, ValueError) as exc:
        raise VerificationError("Bundle signature or signing key is malformed") from exc
    if len(signature) != 64:
        raise VerificationError("Bundle signature must be exactly 64 bytes")
    try:
        pub.verify(signature, message)
    except Exception as exc:
        raise VerificationError(f"Ed25519 signature does not verify: {exc}")
    return True


def signature_path(bundle_root: str | Path) -> Path:
    root = Path(bundle_root)
    if root.name == SIGNED_BUNDLE_DIR and root.parent.is_dir():
        return root.parent / ".blind-signature"
    return root / ".blind-signature"


def sign_bundle(bundle_root: Path, private_key_hex: str) -> str:
    """Test/dev helper: sign a bundle's canonical digest, write .blind-signature.
    Returns the hex signature. (Registry signing is a server responsibility; this
    exists so fixtures can produce a real, verifiable signature.)"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # Sign over the BARE 64-hex digest string (matches BlindMachine::BundleSigner
    # and worker/signature_verifier.rb), so fixtures produce signatures the CLI's
    # own verify_signature — and the real platform — accept.
    message = normalize_digest(canonical_bundle_digest(bundle_root)).encode("utf-8")
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    sig = priv.sign(message).hex()
    signature_path(bundle_root).write_text(sig + "\n")
    return sig


def ensure_pinned_digest(application: str, bundle: Bundle) -> None:
    """When the caller pinned `name@digest`, the loaded bundle must match it."""
    name, digest = split_application_id(application)
    if digest and not digests_match(digest, bundle.digest):
        raise VerificationError(
            f"Pinned digest {digest} != installed bundle digest {bundle.digest}"
        )
