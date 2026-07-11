"""`blind certificates` — the verifiable record. `verify` is offline (zero network)."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from blind import console
from blind.certificates import verify_certificate
from blind.context import Context, emit
from blind.errors import UsageError, VerificationError
from blind.hashing import short
from blind.workspace import installed_bundle

app = typer.Typer(help="The verifiable computation record.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


@app.command("retrieve")
def retrieve(c: typer.Context, hash: str, out: str = typer.Option(None, "--out")):
    ctx = _ctx(c)
    cert = ctx.client().retrieve_certificate(hash)
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

    def render():
        for chk in verification.checks:
            console.status_line(chk.ok, chk.name,
                                short(chk.actual) if chk.actual.startswith("sha256") else chk.actual,
                                chk.detail)
        console.panel(
            "Certificate verification",
            "Every hash recomputed locally. No network, no trust in The Blind Machine."
            if verification.ok else "One or more hashes did NOT match — see the red rows.",
            kind="done" if verification.ok else "trust",
        )

    emit(ctx, view, render)
    if not verification.ok:
        raise typer.Exit(code=VerificationError.code)
