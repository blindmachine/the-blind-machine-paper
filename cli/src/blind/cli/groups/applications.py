"""`blind applications` — the public registry + client-side supply-chain gate."""

from __future__ import annotations

import typer

from blind import console
from blind.context import Context, emit
from blind.errors import VerificationError
from blind.hashing import short, split_application_id
from blind.runtime import bundle as bundle_mod
from blind.runtime.sealer import seal_env, verify_env_lock
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
    digest = version or digest
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
    no_seal: bool = typer.Option(False, "--no-seal", help="skip the uv env BUILD phase"),
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

    application_id = f"{base}@{digest}"
    dest = ctx.store.application_dir(application_id)
    if dest.exists() and not force:
        b = installed_bundle(ctx.store, application_id)
        view = {"object": "application_install", "application": application_id,
                "digest": b.digest, "already_installed": True}
        emit(ctx, view, lambda: console.line("identical", application_id, "already installed"))
        return

    tar = client.download_bundle(base, digest)
    if dest.exists():
        import shutil
        shutil.rmtree(dest)
    bundle_mod.extract_bundle(tar, dest)
    sig = client.download_signature(base, digest)
    (dest / ".blind-signature").write_bytes(sig if isinstance(sig, bytes) else str(sig).encode())

    b = bundle_mod.load_bundle(dest)
    bundle_mod.verify_digest(dest, digest)  # recomputed == server/name suffix
    # FAIL CLOSED: verify_signature now always verifies against a pinned key and
    # RAISES VerificationError on a missing / forged / weak signature, so an
    # unsigned or server-tampered bundle never reaches seal_env / execution. A
    # True return is a real pinned-key Ed25519 verification.
    sig_ok = bundle_mod.verify_signature(dest)
    seal = seal_env(b, no_seal=no_seal)

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
    b = installed_bundle(ctx.store, name)
    checks = {}
    checks["digest"] = (b.digest == split_application_id(name)[1]) if "@" in name else True
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
        console.status_line(checks["env_lock"], "env_lock", short(b.compute_env_lock()))

    emit(ctx, view, render)


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
