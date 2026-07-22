"""`blind certificates` — the verifiable record. `verify` is offline (zero network)."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from blind import console
from blind.certificates import verify_certificate
from blind.context import Context, emit
from blind.errors import UsageError, VerificationError
from blind.hashing import digests_match, short
from blind.workspace import installed_bundle

app = typer.Typer(help="The verifiable computation record.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def _bind_to_requested_hash(cert: dict, requested: str) -> None:
    """A certificate is a content-addressed artifact: a hostile server asked for X
    must not be able to answer with a *different* self-consistent certificate Y.
    ``verify_certificate`` only proves internal self-consistency, so we additionally
    require the returned document's own hash to equal the hash we asked for. Fails
    closed on inconsistency or substitution."""
    v = verify_certificate(cert)
    if not v.ok:
        raise VerificationError(
            "Returned certificate is internally inconsistent (recomputed hash mismatch)")
    if requested and not digests_match(v.certificate_hash, requested):
        raise VerificationError(
            f"Server returned certificate {short(v.certificate_hash)}, not the "
            f"requested {short(requested)}")


@app.command("retrieve")
def retrieve(c: typer.Context, hash: str, out: str = typer.Option(None, "--out")):
    ctx = _ctx(c)
    cert = ctx.client().retrieve_certificate(hash)
    # Bind the returned document to the requested content address BEFORE we save it
    # to --out or display its fields as trusted.
    _bind_to_requested_hash(cert, hash)
    if out:
        Path(out).write_text(json.dumps(cert, indent=2))
    view = {"object": "certificate", **cert}

    def render():
        console.panel(f"certificate {short(hash)}", [
            ("application", short(cert.get("application_digest", ""))),
            ("cohort commitment", short(cert.get("cohort_commitment", ""))),
            ("result digest", short(cert.get("result_digest", ""))),
            ("min-N satisfied", "✔" if cert.get("min_contributors_satisfied") else "✗"),
            ("run count", str(cert.get("run_count", ""))),
        ], kind="info")

    emit(ctx, view, render)


@app.command("list")
def list_certificates(c: typer.Context, project: str = typer.Option(..., "--project")):
    ctx = _ctx(c)
    data = ctx.client().list_certificates(project)
    certs = data.get("certificates", data if isinstance(data, list) else [])
    view = {"object": "list", "data": certs}

    def render():
        rows = [[short(x.get("certificate_hash", "")), short(x.get("result_digest", ""))]
                for x in certs]
        console.table(["certificate", "result digest"], rows)

    emit(ctx, view, render)


@app.command("verify")
def verify(
    c: typer.Context,
    hash: str = typer.Argument(None),
    file: str = typer.Option(None, "--file", help="local cert.json (fully offline)"),
    application: str = typer.Option(None, "--application", help="name@digest to re-hash the bundle"),
):
    """Offline re-verify: recompute EVERY hash and check consistency without
    trusting The Blind Machine. Fetches only the public certificate if not given a file."""
    ctx = _ctx(c)
    if file:
        cert = json.loads(Path(file).read_text())
    elif hash:
        # A local cache is preferred; fall back to the public (no-auth) fetch.
        cert = ctx.client().retrieve_certificate(hash)
    else:
        raise UsageError("Pass a certificate hash or --file <cert.json>.")

    application_root = None
    public_context_file = None
    result_file = None
    if application:
        try:
            application_root = installed_bundle(ctx.store, application).root
        except UsageError:
            application_root = None
    # Re-hash any local artifacts we already hold for this project.
    project_id = cert.get("project_id")
    if project_id:
        pub = ctx.store.key_dir(project_id) / "public.context"
        if pub.exists():
            public_context_file = pub

    verification = verify_certificate(
        cert,
        application_root=application_root,
        public_context_file=public_context_file,
        result_file=result_file,
    )
    view = verification.as_dict()
    # When fetched by hash from the untrusted server, also bind the returned
    # document to the REQUESTED content address (verify_certificate only proves
    # internal self-consistency, not that this is the certificate we asked for).
    requested_bound = digests_match(verification.certificate_hash, hash) if (hash and not file) else True
    view["requested_hash_bound"] = requested_bound

    def render():
        for chk in verification.checks:
            console.status_line(chk.ok, chk.name,
                                short(chk.actual) if chk.actual.startswith("sha256") else chk.actual,
                                chk.detail)
        if hash and not file:
            console.status_line(requested_bound, "requested hash", short(hash),
                                "matches the fetched certificate" if requested_bound
                                else "server returned a DIFFERENT certificate")
        ok = verification.ok and requested_bound
        console.panel(
            "Certificate verification",
            "Every hash recomputed locally. No network, no trust in The Blind Machine."
            if ok else "One or more hashes did NOT match — see the red rows.",
            kind="done" if ok else "trust",
        )

    emit(ctx, view, render)
    if not verification.ok or not requested_bound:
        raise typer.Exit(code=VerificationError.code)
