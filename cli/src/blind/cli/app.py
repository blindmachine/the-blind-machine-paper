"""Root Typer app: global callback + top-level commands + resource sub-apps.

The global flags (COMMANDS.md "Conventions") are parsed once in `main` and stashed
as a `Context` in `ctx.obj`; every command reads them from there.
"""

from __future__ import annotations

import json as _json
import os
import sys

import typer

from blind import console
from blind.context import Context, emit, set_current
from blind.errors import UsageError, VerificationError
from blind.hashing import split_application_id
from blind.version import __version__

from blind.cli.groups import (
    applications,
    certificates,
    contributions,
    data,
    dev,
    jobs,
    keys,
    projects,
    results,
    simulations,
)

app = typer.Typer(
    name="blind",
    help="The Blind Machine trust CLI — governed, content-addressed computation on encrypted data.",
    no_args_is_help=True,
    add_completion=False,
)

RESOURCES = [
    "applications", "projects", "keys", "contributions", "data",
    "jobs", "results", "certificates", "simulations", "dev",
]

_MAX_CREDENTIAL_BYTES = 16 * 1024


def _read_secret_stdin(label: str) -> str:
    if sys.stdin.isatty():
        value = typer.prompt(label, hide_input=True)
    else:
        value = sys.stdin.read(_MAX_CREDENTIAL_BYTES + 1)
        if value.endswith("\n"):
            value = value[:-1]
            if value.endswith("\r"):
                value = value[:-1]
        if "\n" in value or "\r" in value:
            raise UsageError(f"Invalid multiline {label} received on stdin")
    if not value or len(value.encode("utf-8")) > _MAX_CREDENTIAL_BYTES:
        raise UsageError(f"Invalid {label} received on stdin")
    return value


def _version_callback(value: bool) -> None:
    # Eager --version: print and exit before the rest of the callback runs, so
    # `blind --version` works with no subcommand (mirrors the `blind version`
    # subcommand's human line).
    if value:
        console.console.print(f"blind {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    json: bool = typer.Option(False, "--json", help="machine-readable output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="suppress trust banners"),
    color: str = typer.Option("auto", "--color", help="auto|on|off"),
    api: str = typer.Option(None, "--api", help="override platform base URL"),
    profile: str = typer.Option("default", "--profile"),
    api_key_stdin: bool = typer.Option(
        False, "--api-key-stdin", help="read the invocation API key from stdin"),
    project: str = typer.Option(None, "--project", help="active project for scoped commands"),
    yes: bool = typer.Option(False, "--yes", "-y", help="assume yes at confirmations"),
    version: bool = typer.Option(
        None, "--version", help="Show the CLI version and exit.",
        is_eager=True, callback=_version_callback),
):
    # Env fallbacks so a wrapping process (CI, the desktop GUI that shells out)
    # can force output mode without threading a flag through every invocation.
    # An explicit flag always wins; the env var only lifts the default.
    json = json or _env_flag("BLIND_JSON")
    quiet = quiet or _env_flag("BLIND_QUIET")

    api_key = _read_secret_stdin("API key") if api_key_stdin else None
    context = Context(json=json, quiet=quiet, color=color, api=api, profile=profile,
                      api_key=api_key, project=project, assume_yes=yes)
    ctx.obj = context
    set_current(context)


def _env_flag(name: str) -> bool:
    """True when an env var is set to a truthy value (1/true/yes/on)."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


# -- resource sub-apps ------------------------------------------------------
app.add_typer(applications.app, name="applications")
app.add_typer(projects.app, name="projects")
app.add_typer(keys.app, name="keys")
app.add_typer(contributions.app, name="contributions")
app.add_typer(data.app, name="data")
app.add_typer(jobs.app, name="jobs")
app.add_typer(results.app, name="results")
app.add_typer(certificates.app, name="certificates")
app.add_typer(simulations.app, name="simulations")
app.add_typer(dev.app, name="dev")


# ==========================================================================
# Top-level commands
# ==========================================================================


@app.command()
def version(ctx: typer.Context):
    """Print CLI version (and env-sealer / sandbox runtime versions)."""
    context: Context = ctx.obj
    from blind.runtime.sealer import uv_available
    import shutil

    view = {
        "object": "version",
        "version": __version__,
        "uv": uv_available(),
        "sandbox_runtime": next((r for r in ("podman", "docker") if shutil.which(r)), None),
    }
    emit(context, view, lambda: console.console.print(f"blind {__version__}"))


@app.command()
def resources(ctx: typer.Context):
    """List the resource types."""
    context: Context = ctx.obj
    emit(context, {"object": "list", "data": RESOURCES},
         lambda: console.table(["resource"], [[r] for r in RESOURCES]))


@app.command()
def credits(ctx: typer.Context):
    """Show the account's credit balance (one credit = one US dollar)."""
    context: Context = ctx.obj
    data = context.client().credits()
    view = {"object": "credits", **data}
    emit(context, view, lambda: console.panel("Credits", [
        ("balance", f"${data.get('balance_usd', '?')}"),
        ("top up", context.billing_url()),
    ], kind="info"))


def _prompt_password(confirm: bool) -> str:
    return typer.prompt("Password", hide_input=True, confirmation_prompt=confirm)


def _persist_login(context: Context, result) -> None:
    """Store the bearer token + account for the active profile, then report it —
    shared by `login` and `register` so both end in the same authenticated state."""
    context.store.save_token(context.profile, result.token)
    cfg = context.config
    cfg["account"] = result.account.get("email") or result.account.get("account")
    context.store.save_config(cfg)
    view = {"object": "login", "profile": context.profile, "method": result.method,
            "account": cfg.get("account")}
    emit(context, view, lambda: console.line("create", "login",
                                             f"{cfg.get('account','')} ({result.method})"))


@app.command()
def login(
    ctx: typer.Context,
    api_key_stdin: bool = typer.Option(False, "--api-key-stdin", help="read an API key from stdin"),
    email: str = typer.Option(None, "--email", help="account email (password login)"),
    password: str = typer.Option(None, "--password", help="account password"),
    password_stdin: bool = typer.Option(
        False, "--password-stdin", help="read the account password from stdin"),
):
    """Obtain and store a token by hidden prompt, stdin, or device flow."""
    context: Context = ctx.obj
    from blind.login import login_with_api_key, login_with_device, login_with_password

    client = context.client(token=None)
    key = _read_secret_stdin("API key") if api_key_stdin else context.api_key
    if email and key:
        raise UsageError("Choose email/password login or API-key login, not both")
    if (password is not None or password_stdin) and not email:
        raise UsageError("--password and --password-stdin require --email")
    if password is not None and password_stdin:
        raise UsageError("Choose --password or --password-stdin, not both")
    if email:
        account_password = password
        if account_password is None:
            account_password = (
                _read_secret_stdin("Password")
                if password_stdin
                else _prompt_password(confirm=False)
            )
        result = login_with_password(client, email, account_password)
    elif key:
        result = login_with_api_key(client, key)
    else:
        def prompt(user_code, uri):
            console.console.print(
                f"Approve this device: {uri}\n  code: {user_code}")
        result = login_with_device(client, on_prompt=prompt)
    _persist_login(context, result)


@app.command()
def register(
    ctx: typer.Context,
    email: str = typer.Option(..., "--email", help="the email to register"),
    password: str = typer.Option(None, "--password", help="the password to register"),
    password_stdin: bool = typer.Option(
        False, "--password-stdin", help="read the password from stdin"),
):
    """Create an account from the CLI and store its token — you never need the web
    app to sign up (that's only for people who prefer a browser). Afterward the CLI
    is fully authenticated, exactly as if you had run `blind login`."""
    context: Context = ctx.obj
    from blind.login import register_with_password

    if password is not None and password_stdin:
        raise UsageError("Choose --password or --password-stdin, not both")
    pw = password
    if pw is None:
        pw = (
            _read_secret_stdin("Password")
            if password_stdin
            else _prompt_password(confirm=True)
        )
    result = register_with_password(context.client(token=None), email, pw)
    _persist_login(context, result)


@app.command()
def logout(ctx: typer.Context):
    """Delete the stored token for the profile."""
    context: Context = ctx.obj
    removed = context.store.delete_token(context.profile)
    emit(context, {"object": "logout", "profile": context.profile, "removed": removed},
         lambda: console.line("freeze", "logout", f"profile {context.profile}"))


@app.command()
def config(
    ctx: typer.Context,
    list_: bool = typer.Option(False, "--list"),
    set_: str = typer.Option(None, "--set", help="k=v"),
):
    """View or edit ~/.blind/config.yml."""
    context: Context = ctx.obj
    if set_:
        if "=" not in set_:
            raise UsageError("--set wants k=v")
        k, v = set_.split("=", 1)
        cfg = context.store.set_config(k, v)
    else:
        cfg = context.config
    view = {"object": "config", **cfg}
    emit(context, view, lambda: console.panel("config", [(k, str(v)) for k, v in cfg.items()],
                                              kind="info"))


@app.command()
def doctor(
    ctx: typer.Context,
    offline: bool = typer.Option(False, "--offline", help="skip the API ping"),
):
    """Verify the local toolchain (python, sandbox, uv, keychain, Ed25519, perms, API)."""
    context: Context = ctx.obj
    from blind.doctor import run_doctor

    checks = run_doctor(context.store, context.base_url, context.token(), offline=offline)
    all_ok = all(c.ok for c in checks)
    view = {"object": "doctor", "ok": all_ok, "checks": [c.as_dict() for c in checks]}

    def render():
        console.console.print(f"     blind doctor   v{__version__}\n")
        for c in checks:
            console.status_line(c.ok, c.name, c.value, c.detail)
            if not c.ok and c.fix:
                console.console.print(console.Text(f"       fix                {c.fix}",
                                                   style="warn"))
        console.console.print("")
        console.status_line(all_ok, "all systems go" if all_ok else "issues found", "")

    emit(context, view, render)
    if not all_ok:
        raise typer.Exit(code=0)  # doctor reports; a red check is not a crash


@app.command()
def get(ctx: typer.Context, path: str):
    """Raw authenticated GET /api/v1/<path>."""
    context: Context = ctx.obj
    data_ = context.client().raw_get(path)
    emit(context, data_ if isinstance(data_, dict) else {"data": data_},
         lambda: console.console.print_json(_json.dumps(data_)))


@app.command()
def post(
    ctx: typer.Context,
    path: str,
    field: list[str] = typer.Option(None, "--field", help="k=v (repeatable)"),
    data_json: str = typer.Option(None, "--data", help="raw JSON body"),
):
    """Raw authenticated POST /api/v1/<path>."""
    context: Context = ctx.obj
    from blind.api import parse_field_pairs

    body = _json.loads(data_json) if data_json else parse_field_pairs(field or [])
    resp = context.client().raw_post(path, body)
    emit(context, resp if isinstance(resp, dict) else {"data": resp},
         lambda: console.console.print_json(_json.dumps(resp)))


# -- the two core trust shortcuts ------------------------------------------


@app.command()
def verify(ctx: typer.Context, target: str = typer.Argument(None),
           project: str = typer.Option(None, "--project")):
    """Core trust command: verify an application, certificate, or project event chain."""
    kind = _classify(target, project)
    if kind == "application":
        from blind.cli.groups.applications import verify as pv
        pv(ctx, target)
    elif kind == "certificate":
        from blind.cli.groups.certificates import verify as cv
        cv(ctx, hash=target, file=None, application=None)
    elif kind == "project":
        from blind.cli.groups.projects import events as pe
        pe(ctx, project or target, since=None, verify=True)
    else:
        raise UsageError(f"Cannot classify verify target {target!r}. "
                         "Use name@digest, a cert hash, or --project <id>. "
                         "To inspect a job, use `blind explain <job_id>`.")


@app.command()
def explain(ctx: typer.Context, target: str = typer.Argument(None),
            project: str = typer.Option(None, "--project")):
    """Core trust command: explain an application, certificate, result, or project."""
    kind = _classify(target, project)
    if kind == "application":
        from blind.cli.groups.applications import explain as pe
        pe(ctx, target)
    elif kind == "certificate":
        from blind.cli.groups.certificates import retrieve as cr
        cr(ctx, hash=target, out=None)
    elif kind == "result":
        from blind.cli.groups.jobs import retrieve as jr
        jr(ctx, target)
    elif kind == "project":
        from blind.cli.groups.projects import retrieve as pr
        pr(ctx, project or target)
    else:
        raise UsageError(f"Cannot classify explain target {target!r}.")


def _classify(target: str | None, project: str | None) -> str:
    if project and not target:
        return "project"
    if not target:
        return "unknown"
    if "@" in target:
        return "application"
    if target.startswith("cert") or target.startswith("sha256:"):
        return "certificate"
    if target.startswith("job"):
        return "result"
    if target.startswith("proj"):
        return "project"
    # bare 64-hex → treat as a certificate hash
    _, digest = split_application_id(target)
    if len(target) == 64 and all(ch in "0123456789abcdef" for ch in target.lower()):
        return "certificate"
    return "unknown"


# -- porcelain: the data owner's one command -------------------------------


@app.command()
def contribute(
    ctx: typer.Context,
    link: str = typer.Argument(
        ..., metavar="LINK_OR_TOKEN",
        help="the owner-signed invite link, as https://…/c/<token>#k=<key> or "
             "<token>#k=<key> (resolved against the configured --api host)"),
    file: str = typer.Argument(..., help="your raw input vector, e.g. ./my_vector.csv"),
    pin_context: str = typer.Option(
        None, "--pin-context",
        help="pin the public-context digest from a channel SEPARATE from the link "
             "(two-channel high-assurance anchor)"),
):
    """Contribute one encrypted vector to a study — the data owner's ONE command.

    Porcelain over `applications install` + `contributions create`. It resolves the
    project and pinned application from the invite LINK alone (no project id to copy),
    installs and verifies the signed application if not already present, then encodes
    and encrypts LOCALLY and uploads only ciphertext. No account is created and the
    raw file never leaves the machine.

    You can pass the full invite link OR just its token/hash — the `https://<host>/c/`
    prefix is optional and the token is resolved against the configured `--api` host.
    The `#k=<key>` fragment is mandatory because it authenticates the keyholder's
    signed invitation before any application is installed or raw input is read.

    Public-context trust (RFC 0003): when the invite link carries the keyholder's
    signing key in its `#k=` fragment, the owner-signed invitation is verified before
    encrypting and the bound digest is pinned — a malicious server cannot substitute
    its own key. Unsigned links are refused. Use the lower-level `contributions
    create --pin-context <digest>` for an explicit two-channel scripted flow.
    """
    context: Context = ctx.obj
    from blind.cli.groups.applications import install as applications_install
    from blind.cli.groups.contributions import _invite_token, create as contributions_create
    from blind.workspace import installed_bundle

    link = link.strip()
    token = _invite_token(link)
    packet = context.client(token=token).get_invitation_packet(token)
    project = packet.get("project_id")
    application = packet.get("application")
    if not project or not application:
        raise UsageError(
            "That invite link did not resolve to a project and application — ask the "
            "researcher for a fresh link.")
    from blind.invitations import (
        check_intent_matches_link,
        link_owner_key,
        verify_invitation,
    )

    owner_key = link_owner_key(link)
    intent = packet.get("signed_intent")
    signature = packet.get("invitation_signature")
    if not owner_key or not intent or not signature:
        raise VerificationError(
            "Contributor link is not owner-signed; ask the keyholder for a fresh link containing #k="
        )
    verify_invitation(owner_key, intent, signature)
    check_intent_matches_link(
        intent,
        token=token,
        expected_project_id=str(project),
        expected_application_digest=split_application_id(application)[1],
    )

    if not context.quiet and not context.json:
        console.line("inspect", packet.get("project_name") or str(project),
                     application.split("@")[0])

    # Ensure the signed application bundle is installed + verified locally. In JSON
    # (scripted) mode we do not auto-install — a scripted contributor pins the
    # bundle explicitly and the install command has its own JSON contract.
    try:
        installed_bundle(context.store, application)
    except Exception:
        if context.json:
            raise
        applications_install(ctx, name=application, version=None, force=False)

    # Reuse the full, hardened contribution path. Verification (owner signature via
    # the link's #k= fragment, or --pin-context) happens inside `contributions create`
    # — we do NOT auto-pin the packet's UNSIGNED digest (that defends against nothing).
    contributions_create(
        ctx, project=str(project), data=file, link=link, application=application,
        pin_context=pin_context, append_sentinel=True)


# `simulate` alias for `simulations create`
@app.command()
def simulate(
    ctx: typer.Context,
    application: str,
    synthetic: bool = typer.Option(False, "--synthetic"),
    n: str = typer.Option("20", "--n"),
    length: int = typer.Option(16, "--length"),
    coordinates: str = typer.Option(None, "--coordinates"),
    maf_dist: str = typer.Option("beta", "--maf-dist"),
    missingness: float = typer.Option(0.0, "--missingness"),
    seed: int = typer.Option(42, "--seed"),
    encrypted: bool = typer.Option(False, "--encrypted"),
    oracle_only: bool = typer.Option(False, "--oracle-only"),
    emit_: str = typer.Option(None, "--emit"),
    sweep: str = typer.Option(None, "--sweep"),
    crypto: str = typer.Option(None, "--crypto"),
    security: str = typer.Option("128", "--security"),
    from_dir: str = typer.Option(None, "--from"),
    against_result: str = typer.Option(None, "--against-result"),
    replay: str = typer.Option(None, "--replay"),
    attack: str = typer.Option(None, "--attack"),
):
    """Alias for `blind simulations create`."""
    context: Context = ctx.obj
    from blind.cli.groups.simulations import render_matrix, run_create

    view = run_create(context, application, n=n, length=length, seed=seed, maf_dist=maf_dist,
                      missingness=missingness, encrypted=(encrypted and not oracle_only),
                      emit_artifacts=emit_, sweep=sweep, crypto=crypto, security=security,
                      coordinates=coordinates, from_dir=from_dir,
                      against_result=against_result, replay=replay, attack=attack)

    def render():
        if view.get("mode") == "sweep":
            render_matrix(view, seed)
        elif "runs" in view:
            console.line("simulate", application,
                         f"{len(view['runs'])} cohort size(s) · seed {seed}")
        else:
            console.line("simulate", application, view.get("mode", ""))

    emit(context, view, render)


# `blind bench` — the benchmark matrix (a thin alias to `simulations create` in
# sweep mode, per the naming reconciliation in the build plan / paper G1).
@app.command()
def bench(
    ctx: typer.Context,
    application: str,
    n: str = typer.Option("20,100", "--n"),
    length: int = typer.Option(16, "--length"),
    coordinates: str = typer.Option(None, "--coordinates"),
    maf_dist: str = typer.Option("beta", "--maf-dist"),
    missingness: float = typer.Option(0.0, "--missingness"),
    seed: int = typer.Option(42, "--seed"),
    sweep: str = typer.Option(None, "--sweep"),
    crypto: str = typer.Option(None, "--crypto"),
    security: str = typer.Option("128", "--security"),
    emit_: str = typer.Option(None, "--emit"),
):
    """Run the benchmark matrix (application × crypto × N × L × security) and emit the
    CSV / Markdown / LaTeX table + feasibility plots. Alias for
    `blind simulations create --sweep …` (see docs/simulation_mode.md §2)."""
    context: Context = ctx.obj
    from blind.cli.groups.simulations import render_matrix, run_create

    view = run_create(context, application, n=n, length=length, seed=seed, maf_dist=maf_dist,
                      missingness=missingness, emit_artifacts=emit_, sweep=sweep,
                      crypto=crypto, security=security, coordinates=coordinates,
                      bench_mode=True)
    emit(context, view, lambda: render_matrix(view, seed))
