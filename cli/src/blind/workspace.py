"""Glue between ~/.blind state and installed application bundles.

Resolves the installed bundle for a project (via a locally cached ``meta.yml``,
falling back to the server's pinned application digest), and runs the LOCAL crypto
pipeline stages (keygen / encode / encrypt / decrypt / decode). No secret ever
leaves the machine here — that is the whole point of these being CLI-local.
"""

from __future__ import annotations

import base64
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from blind.errors import UsageError
from blind.hashing import sha256_file
from blind.runtime.bundle import Bundle, load_bundle
from blind.runtime.compute import (
    run_decode_stage,
    run_decrypt_stage,
    run_encode_stage,
    run_encrypt_stage,
    run_keygen_stage,
)
from blind.store import Store

# The keygen stage writes these fixed filenames (standardized across every
# shipped bundle — see 00_keygen.py). The secret context is BINARY (a serialized
# TenSEAL context with the secret key), so it is base64-wrapped before it goes
# into the string-only OS keychain / fallback file, and unwrapped on load.
SECRET_CONTEXT_FILENAME = "secret_context.tenseal"
PUBLIC_CONTEXT_FILENAME = "public_context.tenseal"


def installed_bundle(store: Store, application_id: str) -> Bundle:
    d = store.application_dir(application_id)
    if not d.is_dir():
        raise UsageError(
            f"Application {application_id} is not installed. Run `blind applications install {application_id}`."
        )
    return load_bundle(d)


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


def run_keygen(store: Store, project_id: str, bundle: Bundle) -> KeygenResult:
    """LOCAL keygen: run 00_keygen.py, store the secret in the keychain, keep the
    public context under ~/.blind/keys/projects/<id>/public.context.

    Drives the bundle's real ``00_keygen.py --out-dir DIR`` argparse CLI (the
    interface every shipped stage exposes). The secret context is binary, so it
    is base64-wrapped before it goes into the string-only secret store."""
    d = store.key_dir(project_id)
    d.mkdir(parents=True, exist_ok=True)
    scratch = store.home / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
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

    write_project_meta(store, project_id, {
        "application": bundle.application_id,
        "crypto": bundle.manifest.crypto,
        "env_lock": bundle.compute_env_lock(),
    })
    return KeygenResult(
        public_context_path=public_path,
        public_context_sha256=sha256_file(public_path),
        secret_backend=backend,
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
    secret_b64, backend = store.load_secret(project_id)
    if secret_b64 is None:
        raise UsageError(f"No secret key for project {project_id} on this machine.")
    scratch = store.home / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    # V7.1 — secret context + decrypted plaintext are written to a temp dir for the
    # decrypt/decode subprocesses. A self-cleaning TemporaryDirectory under the
    # 0700 ~/.blind root removes them promptly, instead of leaving the secret key
    # AND the cleartext result in a world-persistent /tmp file after the process
    # exits. (result.json is written to out_dir, outside the scratch, so it stays.)
    with tempfile.TemporaryDirectory(prefix="blind-decrypt-", dir=str(scratch)) as tmp:
        work = Path(tmp)
        secret_ctx = work / SECRET_CONTEXT_FILENAME
        secret_ctx.write_bytes(base64.b64decode(secret_b64))

        plain = work / "plain.json"
        run_decrypt_stage(bundle, secret_ctx, result_ct, plain)

        out_dir.mkdir(parents=True, exist_ok=True)
        result_json = out_dir / "result.json"
        run_decode_stage(bundle, plain, bundle.manifest.length, result_json)
        return json.loads(result_json.read_text())
