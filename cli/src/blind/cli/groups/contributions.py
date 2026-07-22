"""`blind contributions` — encrypted data in (encode+encrypt LOCAL, upload ciphertext only)."""

from __future__ import annotations

from pathlib import Path

import typer

from blind import console, trust
from blind.context import Context, emit
from blind.errors import UsageError, VerificationError
from blind.hashing import digests_match, sha256_file, sha256_prefixed, short
from blind.invitations import (
    check_intent_matches_link,
    key_fingerprint,
    link_owner_key,
    link_token,
    verify_invitation,
)
from blind.workspace import resolve_project_bundle, run_encode, run_encrypt

app = typer.Typer(help="Encrypted data in (only ciphertext is uploaded).", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def _invite_token(link: str) -> str:
    # Delegates to invitations.link_token, which strips the #k= fragment as well as
    # a trailing slash / ?query (the old inline split did not strip '#').
    return link_token(link)


def _resolve_signed_pin(
    ctx: Context, project: str, token: str | None, link: str | None,
    application_digest: str | None = None,
) -> str | None:
    """Signed-invitation gate (RFC 0003). The decision to REQUIRE verification keys
    ONLY on the client-observable ``#k=`` fragment of the link — never on a
    server-supplied field ([H11]/[H1]/[H12]). If the link carries an owner key, the
    owner signature MUST verify (under that fragment key) and the signed intent MUST
    match this link/project/time, or we hard-refuse — no fallback, and ``--pin-context``
    cannot rescue a signed link that will not verify. Returns the signed
    public-context digest to pin, or None when no link was supplied."""
    owner_key = link_owner_key(link) if link else None
    if not owner_key:
        return None

    packet = ctx.client(token=token).get_invitation_packet(token)
    intent = packet.get("signed_intent")
    signature = packet.get("invitation_signature")
    if not intent or not signature:
        raise VerificationError(
            "This invite link carries a signing key (#k=) but the server returned no "
            "owner signature — refusing to encrypt (possible downgrade). Ask the "
            "keyholder for a fresh signed link.")
    verify_invitation(owner_key, intent, signature)
    check_intent_matches_link(intent, token=token, expected_project_id=project,
                              expected_application_digest=application_digest)
    if not ctx.json:
        console.line("verify", key_fingerprint(owner_key),
                     "invitation signed by keyholder", trust="verify")
    return intent["public_context_digest"]


def _fetch_public_context(
    ctx: Context, project: str, token: str | None, pin_digest: str | None = None,
    *, link: str | None = None,
    application_digest: str | None = None,
) -> tuple[Path, str]:
    """Return (local path to the project's public context, provenance) — fetching +
    caching it from the server if we don't already hold it. Provenance is one of
    ``signed`` / ``pinned`` / ``local``.

    Key-substitution defense (RFC 0003): a contributor encrypts under the public
    context the SERVER serves. A malicious server could serve *its own* public
    context (and hold the matching secret), defeating IND-CPA not by breaking it but
    by swapping the key. The trust anchor is the owner key carried in the invite-link
    ``#k=`` fragment: a SIGNED link's digest is verified and pinned. For low-level
    scripted use, ``--pin-context`` is the manual out-of-band anchor. With neither,
    encryption fails before fetching a server-selected key."""
    signed_pin = _resolve_signed_pin(
        ctx, project, token, link, application_digest=application_digest)
    if signed_pin and pin_digest and not digests_match(signed_pin, pin_digest):
        raise VerificationError(
            "Signed invitation and out-of-band public-context digests disagree"
        )
    effective_pin = signed_pin or pin_digest
    provenance = "signed" if signed_pin else ("pinned" if pin_digest else "local")
    anchor = "signed invitation" if signed_pin else "pinned --pin-context"

    local = ctx.store.key_dir(project) / "public.context"
    if not effective_pin and link:
        raise VerificationError(
            "Contributor invite is unsigned. Ask the keyholder for a link containing #k=, "
            "or use --pin-context with a digest received through a separate trusted channel."
        )
    if local.exists():
        if effective_pin and not digests_match(sha256_file(local), effective_pin):
            raise VerificationError(
                f"Cached public context does not match the {anchor} digest — "
                "refusing to encrypt.")
        return local, provenance
    if not effective_pin:
        raise VerificationError(
            "No trusted public-context digest is available; refusing to fetch a server-selected key"
        )
    data = ctx.client(token=token).get_public_context(project)
    body = data.get("public_context_bytes", b"")
    if isinstance(body, str):
        body = body.encode()
    got = sha256_prefixed(bytes(body))
    if effective_pin:
        if not digests_match(got, effective_pin):
            raise VerificationError(
                f"Public context digest {got} does not match the {anchor} digest "
                f"{effective_pin} — refusing to encrypt under a server-substituted key.")
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(body)
    return local, provenance


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
        help="Out-of-band SHA-256 digest of the project's PUBLIC context (from a "
             "trusted channel separate from the link). When set, encryption refuses "
             "unless the server's context matches it — the two-channel high-assurance "
             "anchor. A signed invite link (#k=) is verified automatically (RFC 0003).",
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
    public_ctx, ctx_provenance = _fetch_public_context(
        ctx, project, token, pin_context, link=link,
        application_digest=bundle.digest)

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
        "public_context_pinned": ctx_provenance in ("signed", "pinned", "local"),
        "public_context_signed": ctx_provenance == "signed",
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
