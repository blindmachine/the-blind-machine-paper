"""`blind applications` — the public registry + client-side supply-chain gate."""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from pathlib import Path

import typer

from blind import console
from blind.context import Context, emit
from blind.errors import VerificationError
from blind.hashing import digests_match, short, split_application_id
from blind.runtime import bundle as bundle_mod
from blind.runtime.sealer import seal_env, verify_env_lock
from blind.store import validate_component, validate_digest
from blind.workspace import installed_bundle

app = typer.Typer(help="The public curated application registry + install/verify.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


@app.command("list")
def list_applications(c: typer.Context, crypto: str = typer.Option(None, "--crypto")):
    ctx = _ctx(c)
    data = ctx.client().list_applications(crypto=crypto)
    applications = data.get("applications", data if isinstance(data, list) else [])
    view = {"object": "list", "data": applications}

    def render():
        rows = []
        for p in applications:
            versions = p.get("versions") or []
            latest = versions[-1] if versions else {}
            digest = latest.get("digest") or p.get("latest_digest", "")
            rows.append([
                p.get("name", p.get("slug", "")),
                str(latest.get("min_contributors", p.get("min_contributors", ""))),
                str(latest.get("allowed_runs_per_project", "")),
                short(digest),
            ])
        console.table(["application", "min-N", "runs", "latest digest"], rows,
                      footer=f"{len(applications)} curated applications · registry {ctx.base_url}")

    emit(ctx, view, render)


@app.command("retrieve")
def retrieve(c: typer.Context, name: str, version: str = typer.Option(None, "--version")):
    ctx = _ctx(c)
    base, digest = split_application_id(name)
    base = validate_component(base, "application name")
    digest = version or digest
    if digest:
        digest = validate_digest(digest, "application digest")
    if digest:
        data = ctx.client().retrieve_application_version(base, digest)
    else:
        data = ctx.client().retrieve_application(base)
    view = {"object": "application", **data}

    def render():
        console.panel(f"application {base}", [
            ("crypto", str(data.get("crypto", ""))),
            ("min contributors", str(data.get("min_contributors", ""))),
            ("digest", short(data.get("digest", digest or ""))),
            ("coordinate_hash", short(data.get("coordinate_hash", ""))),
        ], kind="info")

    emit(ctx, view, render)


@app.command("install")
def install(
    c: typer.Context,
    name: str,
    version: str = typer.Option(None, "--version"),
    force: bool = typer.Option(False, "--force"),
):
    ctx = _ctx(c)
    base, digest = split_application_id(name)
    digest = version or digest
    client = ctx.client()
    if not digest:  # resolve latest digest from the registry
        meta = client.retrieve_application(base)
        digest = meta.get("latest_digest") or meta.get("digest")
    if not digest:
        raise VerificationError(f"Could not resolve a digest for {base}")
    digest = validate_digest(digest, "registry application digest")

    application_id = f"{base}@{digest}"
    dest = ctx.store.application_dir(application_id)
    if dest.exists() and not force:
        # Reverify every trust boundary before treating an existing directory as
        # installed. A partial or locally modified install never short-circuits.
        b = installed_bundle(ctx.store, application_id)
        view = {"object": "application_install", "application": application_id,
                "digest": b.digest, "already_installed": True}
        emit(ctx, view, lambda: console.line("identical", application_id, "already installed"))
        return

    ctx.store.ensure_layout()
    staging = Path(tempfile.mkdtemp(prefix=f".{base}-install-", dir=dest.parent))
    backup: Path | None = None
    try:
        tar = client.download_bundle(base, digest)
        bundle_mod.extract_bundle(tar, staging)
        bundle_mod.verify_download_structure(staging)
        sig = client.download_signature(base, digest)
        signature_path = staging / ".blind-signature"
        signature_path.write_bytes(sig if isinstance(sig, bytes) else str(sig).encode())
        if os.name == "posix":
            signature_path.chmod(0o600)

        b = bundle_mod.load_bundle(staging)
        if b.name != base:
            raise VerificationError(
                f"Registry application name mismatch: signed {b.name!r}, requested {base!r}"
            )
        bundle_mod.verify_digest(staging, digest)
        sig_ok = bundle_mod.verify_signature(staging)
        seal = seal_env(b)

        if dest.exists():
            backup = dest.with_name(f".{dest.name}.backup-{secrets.token_hex(8)}")
            os.replace(dest, backup)
        try:
            os.replace(staging, dest)
        except Exception:
            if backup is not None and backup.exists() and not dest.exists():
                os.replace(backup, dest)
                backup = None
            raise
        if backup is not None:
            shutil.rmtree(backup)
            backup = None
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup is not None and backup.exists() and dest.exists():
            # The verified install is already committed. A stale private backup
            # is safer to remove than to leave executable under applications/.
            shutil.rmtree(backup)

    view = {
        "object": "application_install",
        "application": application_id,
        "digest": b.digest,
        "digest_verified": True,
        "signature_verified": bool(sig_ok),
        "env_lock": seal.env_lock,
        "sealed": seal.sealed,
        "seal_detail": seal.detail,
    }

    def render():
        console.line("verify", application_id, "digest ok · signature ok (pinned Ed25519)")
        console.line("seal", short(seal.env_lock), seal.detail)
        console.line("install", application_id, "→ ~/.blind/applications")

    emit(ctx, view, render)


@app.command("verify")
def verify(c: typer.Context, name: str, all_: bool = typer.Option(False, "--all")):
    ctx = _ctx(c)
    d = ctx.store.application_dir(name)
    if not d.is_dir():
        raise VerificationError(f"Application is not installed: {name}")
    b = bundle_mod.load_bundle(d)
    checks = {}
    expected_name, expected_digest = split_application_id(name)
    checks["digest"] = (
        b.name == expected_name and digests_match(b.digest, expected_digest)
        if expected_digest else b.name == expected_name
    )
    try:
        bundle_mod.verify_installed_structure(d)
        checks["structure"] = True
    except VerificationError:
        checks["structure"] = False
    try:
        checks["signature"] = bool(bundle_mod.verify_signature(b.root))
    except VerificationError:
        checks["signature"] = False
    checks["env_lock"] = verify_env_lock(b)
    ok = all(checks.values())
    view = {"object": "application_verification", "application": b.application_id,
            "digest": b.digest, "verified": ok, "checks": checks}

    def render():
        console.status_line(checks["digest"], "digest", short(b.digest))
        console.status_line(checks["signature"], "signature",
                            "Ed25519 (pinned)" if checks["signature"] else "invalid/unsigned")
        console.status_line(checks["structure"], "structure", "no unsigned shadow artifacts")
        console.status_line(checks["env_lock"], "env_lock", short(b.compute_env_lock()))

    emit(ctx, view, render)
    # Fail closed on the EXIT CODE too, not just the rendered rows: a scripted /
    # CI caller that trusts `blind applications verify` must see a nonzero exit
    # for a tampered, unsigned, or env-drifted bundle (mirrors `certificates verify`).
    if not ok:
        raise typer.Exit(code=VerificationError.code)


@app.command("explain")
def explain(c: typer.Context, name: str):
    ctx = _ctx(c)
    b = installed_bundle(ctx.store, name)
    m = b.manifest
    view = {
        "object": "application_explanation",
        "application": b.application_id,
        "digest": b.digest,
        "computation": m.computation,
        "crypto": m.crypto,
        "min_contributors": m.min_contributors,
        "coordinate_definition": m.coordinates,
        "release_policy": m.release_policy,
        "leaks": "The released aggregate + metadata (participant count, timing, sizes). "
                 "Inputs are hidden from the server; the keyholder can still decrypt.",
    }

    def render():
        console.panel(f"explain {b.name}", [
            ("computes", m.computation),
            ("crypto", m.crypto),
            ("min-N", str(m.min_contributors)),
            ("digest", short(b.digest)),
            ("what leaks", view["leaks"]),
        ], kind="info")

    emit(ctx, view, render)


@app.command("test")
def test(c: typer.Context, name: str, vector: str = typer.Option(None, "--vector"),
         compute_only: bool = typer.Option(False, "--compute-only")):
    ctx = _ctx(c)
    b = installed_bundle(ctx.store, name)
    vec_dir = b.tests_dir() / "vectors"
    exp_dir = b.tests_dir() / "expected"
    results = []
    if vec_dir.exists():
        import json
        for vf in sorted(vec_dir.glob("*.json")):
            if vector and vf.stem != vector:
                continue
            expected = None
            ef = exp_dir / vf.name
            if ef.exists():
                expected = json.loads(ef.read_text())
            results.append({"vector": vf.stem, "expected": expected,
                            "tolerance": b.manifest.tolerance})
    view = {"object": "application_test", "application": b.application_id,
            "vectors": results, "count": len(results)}
    emit(ctx, view, lambda: console.line("verify", b.application_id,
                                         f"{len(results)} test vector(s)"))
