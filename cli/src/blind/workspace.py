"""Glue between ~/.blind state and installed application bundles.

Resolves the installed bundle for a project (via a locally cached ``meta.yml``,
falling back to the server's pinned application digest), and runs the LOCAL crypto
pipeline stages (keygen / encode / encrypt / decrypt / decode). No secret ever
leaves the machine here — that is the whole point of these being CLI-local.
"""

from __future__ import annotations

import base64
import binascii
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from blind.errors import UsageError, VerificationError
from blind.hashing import sha256_file, split_application_id
from blind.runtime.bundle import (
    Bundle,
    ensure_pinned_digest,
    load_bundle,
    verify_installed_structure,
    verify_signature,
)
from blind.runtime.compute import (
    run_decode_stage,
    run_decrypt_stage_from_bytes,
    run_encode_stage,
    run_encrypt_stage,
    run_keygen_stage,
)
from blind.store import LOCAL_DIGEST_SENTINEL, Store

# The keygen stage writes these fixed filenames (standardized across every
# shipped bundle — see 00_keygen.py). The secret context is BINARY (a serialized
# TenSEAL context with the secret key), so it is base64-wrapped before it goes
# into the string-only OS keychain / fallback file, and unwrapped on load.
# This is a serialized context filename, not a credential literal.
SECRET_CONTEXT_FILENAME = "secret_context.tenseal"  # nosec B105
PUBLIC_CONTEXT_FILENAME = "public_context.tenseal"


def installed_bundle(store: Store, application_id: str) -> Bundle:
    expected_name, expected_digest = split_application_id(application_id)
    if not expected_digest:
        raise UsageError("Installed applications must be addressed by their full SHA-256 digest")
    d = store.application_dir(application_id)
    if not d.is_dir():
        raise UsageError(
            f"Application {application_id} is not installed. Run `blind applications install {application_id}`."
        )
    verify_installed_structure(d)
    bundle = load_bundle(d)
    if bundle.name != expected_name:
        raise VerificationError(
            f"Installed application name mismatch: {bundle.name!r} != {expected_name!r}"
        )
    if expected_digest != LOCAL_DIGEST_SENTINEL:
        # Real-digest (server/contribution/decrypt) path — fully hardened: pin the
        # bundle to the caller-supplied external digest AND require the
        # install-written `.digest` record to match the recomputed bundle digest.
        ensure_pinned_digest(application_id, bundle)
        recorded_digest = bundle.root / ".digest"
        if (
            recorded_digest.is_symlink()
            or not recorded_digest.is_file()
            or recorded_digest.read_text().strip() != bundle.digest
        ):
            raise VerificationError("Installed application digest record is missing or invalid")
    # else: `<name>@local` is the unpinned local-bench/simulate sentinel. It has no
    # external digest to pin and a cp'd bundle writes no `.digest` record, so those
    # two checks don't apply. Its bytes are still fully signature-, structure-, and
    # env-lock-verified below. This sentinel is never reachable from a
    # server/contribution/decrypt input (those always carry a real sha256 digest).
    verify_signature(d)
    from blind.runtime.sealer import verify_env_lock

    if not verify_env_lock(bundle):
        raise VerificationError("Installed application environment lock is missing or invalid")
    return bundle


def write_project_meta(store: Store, project_id: str, meta: dict) -> Path:
    d = store.key_dir(project_id)
    d.mkdir(parents=True, exist_ok=True)
    p = d / "meta.yml"
    existing = read_project_meta(store, project_id)
    existing.update(meta)
    p.write_text(yaml.safe_dump(existing, sort_keys=True))
    return p


def read_project_meta(store: Store, project_id: str) -> dict:
    p = store.key_dir(project_id) / "meta.yml"
    if p.exists():
        return yaml.safe_load(p.read_text()) or {}
    return {}


def resolve_project_bundle(store: Store, project_id: str, application_id: str | None = None) -> Bundle:
    if application_id is None:
        meta = read_project_meta(store, project_id)
        application_id = meta.get("application")
    if not application_id:
        raise UsageError(
            f"No pinned application known for project {project_id}. "
            "Pass --application or run `blind keys create` first."
        )
    return installed_bundle(store, application_id)


@dataclass
class KeygenResult:
    public_context_path: Path
    public_context_sha256: str
    secret_backend: str
    owner_signing_pubkey: str  # RFC 0003 owner Ed25519 public key (64-hex)
    owner_signing_backend: str


def run_keygen(store: Store, project_id: str, bundle: Bundle) -> KeygenResult:
    """LOCAL keygen: run 00_keygen.py, store the secret in the keychain, keep the
    public context under ~/.blind/keys/projects/<id>/public.context.

    Drives the bundle's real ``00_keygen.py --out-dir DIR`` argparse CLI (the
    interface every shipped stage exposes). The secret context is binary, so it
    is base64-wrapped before it goes into the string-only secret store."""
    d = store.key_dir(project_id)
    d.mkdir(parents=True, exist_ok=True)
    scratch = store.temporary_root()
    # V7.1 — the secret context (holding the FHE secret key) is materialized to a
    # temp dir so the stage subprocess can read it. Use a self-cleaning
    # TemporaryDirectory under the 0700 ~/.blind root (NOT shared /tmp) so the
    # secret never lingers on disk after keygen returns.
    with tempfile.TemporaryDirectory(prefix="blind-keygen-", dir=str(scratch)) as tmp:
        work = Path(tmp)
        public_ctx, secret_ctx = run_keygen_stage(bundle, work)

        public_path = d / "public.context"
        public_path.write_bytes(public_ctx.read_bytes())
        secret_b64 = base64.b64encode(secret_ctx.read_bytes()).decode("ascii")
        backend = store.store_secret(project_id, secret_b64)

    # RFC 0003 — mint the owner's Ed25519 SIGNING key beside the FHE key. The
    # private half joins the FHE secret in the keychain (distinct slot, never
    # uploaded); the public half is written locally (it rides the invite-link
    # fragment) and registered with the server by the calling command.
    from blind.invitations import generate_owner_keypair

    signing_priv, signing_pub = generate_owner_keypair()
    signing_backend = store.store_signing_key(project_id, signing_priv)
    (d / "owner_signing.pub").write_text(signing_pub + "\n")

    write_project_meta(store, project_id, {
        "application": bundle.application_id,
        "crypto": bundle.manifest.crypto,
        "env_lock": bundle.compute_env_lock(),
        "owner_signing_pubkey": signing_pub,
    })
    return KeygenResult(
        public_context_path=public_path,
        public_context_sha256=sha256_file(public_path),
        secret_backend=backend,
        owner_signing_pubkey=signing_pub,
        owner_signing_backend=signing_backend,
    )


def run_encode(bundle: Bundle, raw_path: Path, out_path: Path) -> tuple[Path, str]:
    """Run ``10_encode.py --raw RAW --length L --out OUT`` in the sealed env."""
    run_encode_stage(bundle, raw_path, bundle.manifest.length, out_path)
    return out_path, sha256_file(out_path)


def run_encrypt(
    bundle: Bundle, encoded_path: Path, public_context: Path, out_path: Path
) -> tuple[Path, str]:
    """Run ``20_encrypt.py --context PUB --encoded ENC --out CT`` in the sealed env."""
    outs = run_encrypt_stage(bundle, public_context, encoded_path, [out_path])
    artifact = outs[0]
    return artifact, sha256_file(artifact)


def run_decrypt_decode(
    store: Store, project_id: str, bundle: Bundle, result_ct: Path, out_dir: Path
) -> dict:
    """Run ``40_decrypt`` then ``50_decode`` locally with the project's secret
    context, returning the decoded aggregate dict."""
    secret_b64, _backend = store.load_secret(project_id)
    if secret_b64 is None:
        raise UsageError(f"No secret key for project {project_id} on this machine.")
    try:
        secret_context = base64.b64decode(secret_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError("Stored private context is not valid base64") from exc
    if not secret_context:
        raise VerificationError("Stored private context is empty")

    scratch = store.temporary_root()
    # Only the decrypted aggregate is materialized in this private, self-cleaning
    # directory. The FHE secret itself crosses into the sandbox over an anonymous
    # stdin pipe and is never reconstructed as a host file.
    with tempfile.TemporaryDirectory(prefix="blind-decrypt-", dir=str(scratch)) as tmp:
        work = Path(tmp)
        plain = work / "plain.json"
        run_decrypt_stage_from_bytes(bundle, secret_context, result_ct, plain)

        out_dir.mkdir(parents=True, exist_ok=True)
        result_json = out_dir / "result.json"
        run_decode_stage(bundle, plain, bundle.manifest.length, result_json)
        return json.loads(result_json.read_text())
