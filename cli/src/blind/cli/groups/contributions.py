"""`blind contributions` — encrypted data in (encode+encrypt LOCAL, upload ciphertext only)."""

from __future__ import annotations

from pathlib import Path

import typer

from blind import console, trust
from blind.context import Context, emit
from blind.errors import UsageError, VerificationError
from blind.hashing import digests_match, sha256_file, sha256_prefixed, short
from blind.workspace import resolve_project_bundle, run_encode, run_encrypt

app = typer.Typer(help="Encrypted data in (only ciphertext is uploaded).", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def _invite_token(link: str) -> str:
    return link.rstrip("/").split("/")[-1].split("?")[0]


def _fetch_public_context(
    ctx: Context, project: str, token: str | None, pin_digest: str | None = None
) -> Path:
    """Return a local path to the project's public context, fetching + caching it
    from the server if we don't already hold it.

    Key-substitution defense (V2.1): a contributor encrypts under the public
    context the SERVER serves. A malicious server could serve *its own* public
    context (and hold the matching secret), defeating IND-CPA not by breaking it
    but by swapping the key. When ``pin_digest`` is supplied out-of-band (from the
    signed invite / a trusted channel), the fetched context's SHA-256 must match it
    or we refuse to encrypt. When it is NOT supplied, we WARN loudly that the
    context is unpinned rather than silently trusting the server."""
    local = ctx.store.key_dir(project) / "public.context"
    if local.exists():
        if pin_digest and not digests_match(sha256_file(local), pin_digest):
            raise VerificationError(
                "Cached public context does not match the pinned --pin-context "
                "digest — refusing to encrypt.")
        return local
    data = ctx.client(token=token).get_public_context(project)
    body = data.get("public_context_bytes", b"")
    if isinstance(body, str):
        body = body.encode()
    got = sha256_prefixed(bytes(body))
    if pin_digest:
        if not digests_match(got, pin_digest):
            raise VerificationError(
                f"Public context digest {got} does not match the pinned "
                f"--pin-context {pin_digest} — refusing to encrypt under a "
                "server-substituted key.")
    elif not ctx.json:
        console.line(
            "warn", short(got),
            "public context is UNPINNED — a malicious server could substitute its "
            "own key. Pass --pin-context <digest> from the signed invite / a "
            "trusted channel.", trust=None)
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(body)
    return local


@app.command("create")
def create(
    c: typer.Context,
    project: str = typer.Option(None, "--project"),
    data: str = typer.Option(..., "--data", help="raw input file (required)"),
    link: str = typer.Option(None, "--link", help="accountless bearer-link owner path"),
    application: str = typer.Option(
        None, "--application",
        help="pinned name@digest to encode against (accountless contributors "
             "with no local project metadata name it explicitly)",
    ),
    pin_context: str = typer.Option(
        None, "--pin-context",
        help="Out-of-band SHA-256 digest of the project's PUBLIC context (from the "
             "signed invite / a trusted channel). When set, encryption refuses "
             "unless the server's context matches it — defeats a malicious server "
             "substituting its own key (V2.1).",
    ),
    append_sentinel: bool = typer.Option(True, "--append-sentinel/--no-append-sentinel"),
):
    ctx = _ctx(c)
    raw = Path(data)
    if not raw.exists():
        raise UsageError(f"Raw input not found: {raw}")
    token = _invite_token(link) if link else None
    if project is None:
        raise UsageError("Pass --project (the id the invite link is scoped to).")

    if not ctx.quiet and not ctx.json:
        trust.contribution_banner()

    # An accountless contributor (bearer link, fresh ~/.blind) has no local
    # project→application metadata, so they name the pinned application explicitly —
    # the same bundle they installed and trust. Owners fall back to the metadata
    # `keys create` wrote.
    bundle = resolve_project_bundle(ctx.store, project, application)
    public_ctx = _fetch_public_context(ctx, project, token, pin_context)

    enc_out = ctx.store.home / "cache" / "encoded" / f"{raw.stem}.enc-in"
    encoded, encoded_sha = run_encode(bundle, raw, enc_out)
    ct_out = ctx.store.home / "cache" / "encrypted" / f"{raw.stem}.ct"
    ciphertext, ct_sha = run_encrypt(bundle, encoded, public_ctx, ct_out)

    resp = ctx.client(token=token).create_contribution(
        project, ct_sha, Path(ciphertext).read_bytes(), token=token
    )

    pub_sha = sha256_file(public_ctx)
    view = {
        "object": "contribution",
        "id": resp.get("id"),
        "ciphertext_sha256": ct_sha,
        "public_context_sha256": pub_sha,
        "public_context_pinned": bool(pin_context),
        "public_context_matches_project": resp.get("public_context_matches_project", True),
        "cohort_size": resp.get("cohort_size"),
        "min_contributors": resp.get("min_contributors"),
        # Server envelope uses `min_n_satisfied`; accept the older key name too.
        "min_contributors_satisfied": resp.get("min_n_satisfied",
                                               resp.get("min_contributors_satisfied")),
        "uploaded": True,
        "local_artifacts": {"raw": str(raw), "encoded_cached": True},
        "trust": {"raw": "local_only", "encoded": "local_only", "encrypted": "uploaded"},
    }

    def render():
        console.line("read", str(raw), trust="raw")
        console.line("encode", short(encoded_sha), "coordinates", trust="encoded")
        console.line("encrypt", short(ct_sha), "encrypted", trust="encrypted")
        if append_sentinel:
            console.line("append", "sentinel +1", "integrity, not a MAC", trust="encrypted")
        console.line("upload", short(ct_sha), "→ server", trust="encrypted_uploaded")
        console.panel("Contributed", [
            ("ciphertext", short(ct_sha)),
            ("public context", short(pub_sha)),
            ("cohort size", str(view["cohort_size"])),
            ("min-N satisfied", "✔" if view["min_contributors_satisfied"] else "✗"),
        ])
        trust.nothing_uploaded_footer(str(raw))

    emit(ctx, view, render)


@app.command("list")
def list_contributions(c: typer.Context, project: str = typer.Option(..., "--project"),
                       mine: bool = typer.Option(False, "--mine")):
    ctx = _ctx(c)
    data = ctx.client().list_contributions(project, mine=mine)
    items = data.get("contributions", data if isinstance(data, list) else [])
    view = {"object": "list", "data": items,
            "cohort_commitment": data.get("cohort_commitment"),
            "min_contributors_satisfied": data.get("min_contributors_satisfied")}

    def render():
        rows = [[short(x.get("ciphertext_sha256", x.get("sha256", ""))),
                 x.get("id", "")] for x in items]
        console.table(["ciphertext", "id"], rows,
                      footer=f"{len(items)} contributions")

    emit(ctx, view, render)


@app.command("retrieve")
def retrieve(c: typer.Context, id: str):
    ctx = _ctx(c)
    data = ctx.client().retrieve_contribution(id)
    emit(ctx, {"object": "contribution", **data},
         lambda: console.panel(f"contribution {id}", [
             ("ciphertext", short(data.get("ciphertext_sha256", ""))),
             ("cohort size", str(data.get("cohort_size", ""))),
             ("min-N satisfied", "✔" if data.get("min_contributors_satisfied") else "✗"),
         ], kind="info"))
