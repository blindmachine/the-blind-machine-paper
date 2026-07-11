"""Root Typer app: global callback + top-level commands + resource sub-apps.

The global flags (COMMANDS.md "Conventions") are parsed once in `main` and stashed
as a `Context` in `ctx.obj`; every command reads them from there.
"""

from __future__ import annotations

import json as _json
import os

import typer

from blind import console
from blind.context import Context, emit, set_current
from blind.errors import UsageError
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


@app.callback()
def main(
    ctx: typer.Context,
    json: bool = typer.Option(False, "--json", help="machine-readable output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="suppress trust banners"),
    color: str = typer.Option("auto", "--color", help="auto|on|off"),
    api: str = typer.Option(None, "--api", help="override platform base URL"),
    profile: str = typer.Option("default", "--profile"),
    api_key: str = typer.Option(None, "--api-key", help="API key for this invocation"),
    project: str = typer.Option(None, "--project", help="active project for scoped commands"),
    yes: bool = typer.Option(False, "--yes", "-y", help="assume yes at confirmations"),
):
    # Env fallbacks so a wrapping process (CI, the desktop GUI that shells out)
    # can force output mode without threading a flag through every invocation.
    # An explicit flag always wins; the env var only lifts the default.
    json = json or _env_flag("BLIND_JSON")
    quiet = quiet or _env_flag("BLIND_QUIET")

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


@app.command()
def login(
    ctx: typer.Context,
    api_key: str = typer.Option(None, "--api-key", help="non-interactive key exchange"),
):
    """Obtain and store an API token (device/browser code flow, or --api-key)."""
    context: Context = ctx.obj
    from blind.login import login_with_api_key, login_with_device

    client = context.client(token=None)
    key = api_key or context.api_key
    if key:
        result = login_with_api_key(client, key)
    else:
        def prompt(user_code, uri):
            console.console.print(
                f"Approve this device: {uri}\n  code: {user_code}")
        result = login_with_device(client, on_prompt=prompt)
    context.store.save_token(context.profile, result.token)
    cfg = context.config
    cfg["account"] = result.account.get("email") or result.account.get("account")
    context.store.save_config(cfg)
    view = {"object": "login", "profile": context.profile, "method": result.method,
            "account": cfg.get("account")}
    emit(context, view, lambda: console.line("create", "login",
                                             f"{cfg.get('account','')} ({result.method})"))


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
    """Core trust command: verify an application, certificate, result, or project event chain."""
    kind = _classify(target, project)
    if kind == "application":
        from blind.cli.groups.applications import verify as pv
        pv(ctx, target)
    elif kind == "certificate":
        from blind.cli.groups.certificates import verify as cv
        cv(ctx, hash=target, file=None, application=None)
    elif kind == "result":
        from blind.cli.groups.results import verify as rv
        rv(ctx, target, local=False, inputs=None, context=None, bundle=None,
           project=None, timeout=300, interval=2.0)
    elif kind == "project":
        from blind.cli.groups.projects import events as pe
        pe(ctx, project or target, since=None, verify=True)
    else:
        raise UsageError(f"Cannot classify verify target {target!r}. "
                         "Use name@digest, a cert hash, a job id, or --project <id>.")


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
    link: str = typer.Argument(..., help="the invite link, e.g. https://blindmachine.org/c/abc123"),
    file: str = typer.Argument(..., help="your raw input vector, e.g. ./my_vector.csv"),
    pin_context: str = typer.Option(
        None, "--pin-context", help="override the invite packet's public-context digest"),
):
    """Contribute one encrypted vector to a study — the data owner's ONE command.

    Porcelain over `applications install` + `contributions create`. It resolves the
    project, the pinned application, and the public-context digest from the invite
    LINK alone (no project id to copy), installs and verifies the signed application
    if it is not already present, then encodes and encrypts LOCALLY and uploads only
    ciphertext. No account is created and the raw file never leaves the machine; the
    packet's public-context digest is auto-pinned, so a malicious server cannot
    substitute its own key. Use the lower-level `contributions create` for scripting.
    """
    context: Context = ctx.obj
    from blind.cli.groups.applications import install as applications_install
    from blind.cli.groups.contributions import _invite_token, create as contributions_create
    from blind.workspace import installed_bundle

    token = _invite_token(link)
    packet = context.client(token=token).get_invitation_packet(token)
    project = packet.get("project_id")
    application = packet.get("application")
    context_pin = pin_context or packet.get("public_context_digest")
    if not project or not application:
        raise UsageError(
            "That invite link did not resolve to a project and application — ask the "
            "researcher for a fresh link.")

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
        applications_install(ctx, name=application, version=None, force=False, no_seal=False)

    # Reuse the full, hardened contribution path (encode/encrypt LOCAL, upload
    # ciphertext only, auto-pinning the packet's public-context digest).
    contributions_create(
        ctx, project=str(project), data=file, link=link, application=application,
        pin_context=context_pin, append_sentinel=True)


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
