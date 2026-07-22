"""`blind keys` — the crypto context (100% local keygen).

Key material handling is LOCAL. `create` runs the application's 00_keygen.py in the
sealed env, stores the secret in the OS keychain, and publishes ONLY the public
half. There is no endpoint that could receive a secret key.
"""

from __future__ import annotations

import typer

from blind import console, trust
from blind.context import Context, emit
from blind.errors import UsageError, VerificationError
from blind.hashing import digests_match, sha256_file, sha256_prefixed, short
from blind.workspace import (
    read_project_meta,
    resolve_project_bundle,
    run_keygen,
)

app = typer.Typer(help="Local crypto context (keygen is 100% local).", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def _publish_public_material(ctx: Context, project: str) -> tuple[str, str]:
    key_dir = ctx.store.key_dir(project)
    public_context = key_dir / "public.context"
    owner_public = key_dir / "owner_signing.pub"
    for path, label in (
        (public_context, "public context"),
        (owner_public, "owner signing public key"),
    ):
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"Local {label} is missing or not a regular file: {path}")
    public_digest = sha256_file(public_context)
    owner_public_hex = owner_public.read_text().strip().lower()
    try:
        owner_public_bytes = bytes.fromhex(owner_public_hex)
    except ValueError as exc:
        raise VerificationError("Owner signing public key is malformed") from exc
    if len(owner_public_bytes) != 32 or owner_public_bytes == b"\0" * 32:
        raise VerificationError("Owner signing public key is weak or malformed")
    ctx.client().put_public_context(project, public_digest, public_context.read_bytes())
    ctx.client().put_owner_key(project, owner_public_hex)
    return public_digest, owner_public_hex


@app.command("create")
def create(c: typer.Context, project: str = typer.Option(..., "--project"),
           application: str = typer.Option(None, "--application"),
           force: bool = typer.Option(False, "--force")):
    ctx = _ctx(c)
    bundle = resolve_project_bundle(ctx.store, project, application)
    if not force and (ctx.store.key_dir(project) / "public.context").exists():
        raise UsageError(f"Keys already exist for {project}. Use --force to regenerate.")

    if not ctx.quiet and not ctx.json:
        trust.local_crypto_banner("Keygen")

    kg = run_keygen(ctx.store, project, bundle)

    # Both public artifacts are mandatory. On network failure the private keys stay
    # local and `keys publish` retries without regenerating them.
    _publish_public_material(ctx, project)
    published = True

    view = {
        "object": "keys",
        "project": project,
        "public_context_sha256": kg.public_context_sha256,
        "secret_backend": kg.secret_backend,
        "published": published,
        "trust": {"private": "never_leaves", "public": "uploaded" if published else "local_only"},
    }

    def render():
        console.line("create", "keygen", f"secret → {kg.secret_backend}", trust="private")
        console.line("upload" if published else "skip", short(kg.public_context_sha256),
                     "public context " + ("published" if published else "(publish later)"),
                     trust="public")

    emit(ctx, view, render)


@app.command("publish")
def publish(c: typer.Context, project: str = typer.Option(..., "--project")):
    """Retry publication of existing public material without regenerating keys."""
    ctx = _ctx(c)
    public_digest, owner_public = _publish_public_material(ctx, project)
    view = {
        "object": "keys_publication",
        "project": project,
        "public_context_sha256": public_digest,
        "owner_signing_pubkey": owner_public,
        "published": True,
    }
    emit(
        ctx,
        view,
        lambda: console.line(
            "publish", short(public_digest), "public context + owner signing key", trust="public"
        ),
    )


@app.command("retrieve")
def retrieve(c: typer.Context, project: str = typer.Option(..., "--project")):
    ctx = _ctx(c)
    secret, backend = ctx.store.load_secret(project)
    local_pub = ctx.store.key_dir(project) / "public.context"
    local_hash = sha256_file(local_pub) if local_pub.exists() else None
    # Fetch failures propagate: reporting "local only" would hide a failed tamper check.
    # Hash the BYTES we received rather than trusting the server's self-reported
    # X-Public-Context-Digest header (an untrusted server would just echo a matching
    # header for tampered bytes).
    resp = ctx.client().get_public_context(project)
    server_bytes = resp.get("public_context_bytes") or b""
    server_hash = sha256_prefixed(server_bytes) if server_bytes else None
    matches = digests_match(server_hash, local_hash) if (server_hash and local_hash) else None
    view = {
        "object": "keys_status",
        "project": project,
        "secret_backend": backend,
        "public_context_sha256": local_hash,
        "server_public_context_sha256": server_hash,
        "matches_server": matches,
    }

    def render():
        console.line("local", f"secret in {backend or 'none'}", trust="private")
        console.status_line(bool(matches) if matches is not None else True,
                            "public context",
                            short(local_hash or "—"),
                            "matches server" if matches else ("local only" if matches is None else "MISMATCH"))

    emit(ctx, view, render)
    # A definite local≠server public-context mismatch is a substitution/tamper
    # signal — fail the exit code instead of only rendering "MISMATCH" in red.
    if matches is False:
        raise typer.Exit(code=VerificationError.code)


@app.command("list")
def list_keys(c: typer.Context):
    ctx = _ctx(c)
    root = ctx.store.home / "keys" / "projects"
    rows = []
    data = []
    if root.exists():
        from blind.hashing import sha256_file

        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            meta = read_project_meta(ctx.store, d.name)
            pub = d / "public.context"
            h = sha256_file(pub) if pub.exists() else ""
            backend = "keychain" if (d / "private.ref").exists() else (
                "file" if (d / "private.key").exists() else "—")
            rows.append([d.name, meta.get("crypto", ""), backend, short(h)])
            data.append({"project": d.name, "crypto": meta.get("crypto", ""),
                         "backend": backend, "public_context_sha256": h})
    emit(ctx, {"object": "list", "data": data},
         lambda: console.table(["project", "crypto", "secret", "public context"], rows))


@app.command("export-public")
def export_public(c: typer.Context, project: str = typer.Option(..., "--project"),
                  out: str = typer.Option(None, "--out")):
    ctx = _ctx(c)
    pub = ctx.store.key_dir(project) / "public.context"
    if not pub.exists():
        raise UsageError(f"No public context for {project}. Run `blind keys create` first.")
    from pathlib import Path

    from blind.hashing import sha256_file

    dest = Path(out) if out else Path.cwd() / f"{project}-public.context"
    dest.write_bytes(pub.read_bytes())
    h = sha256_file(dest)
    emit(ctx, {"object": "public_context", "project": project, "path": str(dest),
               "public_context_sha256": h},
         lambda: console.line("create", str(dest), short(h), trust="public"))


@app.command("delete")
def delete(c: typer.Context, project: str = typer.Option(..., "--project"),
           yes: bool = typer.Option(False, "--yes", "-y")):
    ctx = _ctx(c)
    removed = ctx.store.delete_secret(project)
    emit(ctx, {"object": "keys_delete", "project": project, "removed": removed},
         lambda: console.line("freeze", project,
                              "local key material deleted (server untouched)", trust="private"))
