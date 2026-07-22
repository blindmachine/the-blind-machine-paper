"""`blind projects` — studies + governance (mostly REMOTE)."""

from __future__ import annotations

import typer

from blind import console
from blind.context import Context, emit
from blind.errors import UsageError, VerificationError
from blind.hashing import require_result_digest, short

app = typer.Typer(help="Studies + governance.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def sign_and_mint_invite(ctx: Context, project_id: str, *, expires: str = "7d",
                         count: int = 1, qr: bool = False) -> dict:
    """Mint a contributor invite signed by the local project-owner key.
    and a public context is published (RFC 0003). The owner generates the token,
    signs an intent binding the public-context digest, uploads the signature, and
    returns a link whose ``#k=`` fragment carries the owner public key. Missing
    signing state is a hard failure; unsigned contributor links are never minted."""
    from blind import invitations as inv

    priv, _backend = ctx.store.load_signing_key(project_id)
    pub_path = ctx.store.key_dir(project_id) / "owner_signing.pub"
    if not priv or not pub_path.exists():
        raise VerificationError(
            "Project owner signing key is missing; run `blind keys create --project <id>`"
        )

    project = ctx.client().retrieve_project(project_id)
    public_context_digest = project.get("public_context_digest")
    if not public_context_digest:
        raise VerificationError(
            "Project has no published public-context digest; refusing to mint an unsigned invite"
        )

    token = inv.new_token()
    expires_at = inv.expiry_iso(expires)
    intent = inv.build_intent(
        project_id=str(project_id),
        token=token,
        application_digest=project.get("application_digest", ""),
        public_context_digest=public_context_digest,
        context_epoch=int(project.get("context_epoch", 0)),
        min_contributors=int(project.get("min_contributors", 0)),
        expires_at=expires_at,
    )
    signature = inv.owner_sign(priv, intent)
    data = ctx.client().invite_project(
        project_id, token=token, owner_signature=signature,
        signed_intent=intent, expires=expires,
    )
    owner_pub = pub_path.read_text().strip()
    data["url"] = inv.build_invite_link(data.get("url", data.get("link", "")), owner_pub)
    data["signed"] = True
    data["owner_key_fingerprint"] = inv.key_fingerprint(owner_pub)
    return data


@app.command("create")
def create(
    c: typer.Context,
    application: str = typer.Option(..., "--application", help="name@digest (required)"),
    name: str = typer.Option(None, "--name"),
    min_contributors: int = typer.Option(20, "--min-contributors", min=1),
    scenario: str = typer.Option(None, "--scenario"),
):
    ctx = _ctx(c)
    data = ctx.client().create_project(
        application=application, name=name, min_contributors=min_contributors, scenario=scenario
    )
    view = {"object": "project", **data}

    def render():
        console.line("verify", application, "digest · signature")
        console.line("create", data.get("id", ""), name or "")
        console.panel("Project created", [
            ("project id", data.get("id", "")),
            ("application", application),
            ("min contributors", str(data.get("min_contributors", min_contributors))),
            ("state", data.get("state", "active")),
        ])
        console.console.print(console.Text(
            f"Next  blind keys create --project {data.get('id','')}", style="meta"))

    emit(ctx, view, render)


@app.command("list")
def list_projects(c: typer.Context, state: str = typer.Option(None, "--state")):
    ctx = _ctx(c)
    data = ctx.client().list_projects(state=state)
    projects = data.get("projects", data if isinstance(data, list) else [])
    view = {"object": "list", "data": projects}

    def render():
        rows = [[p.get("id", ""), p.get("name", ""), p.get("state", ""),
                 str(p.get("cohort_size", "")), str(p.get("run_count", ""))] for p in projects]
        console.table(["id", "name", "state", "cohort", "runs"], rows)

    emit(ctx, view, render)


@app.command("retrieve")
def retrieve(c: typer.Context, id: str):
    ctx = _ctx(c)
    data = ctx.client().retrieve_project(id)
    view = {"object": "project", **data}

    satisfied = data.get("min_n_satisfied", data.get("min_contributors_satisfied"))

    def render():
        console.panel(f"project {id}", [
            ("state", data.get("state", "")),
            ("application", short(data.get("application_digest", ""))),
            ("cohort size", str(data.get("cohort_size", ""))),
            ("min-N satisfied", "✔" if satisfied else "✗"),
            ("cohort commitment", short(data.get("cohort_commitment", ""))),
            ("run count", str(data.get("run_count", ""))),
        ], kind="info")

    emit(ctx, view, render)


@app.command("update")
def update(c: typer.Context, id: str, name: str = typer.Option(None, "--name"),
           min_contributors: int = typer.Option(None, "--min-contributors"),
           description: str = typer.Option(None, "--description")):
    ctx = _ctx(c)
    fields = {k: v for k, v in
              {"name": name, "min_contributors": min_contributors, "description": description}.items()
              if v is not None}
    data = ctx.client().update_project(id, **fields)
    emit(ctx, {"object": "project", **data},
         lambda: console.line("create", id, "updated"))


@app.command("delete")
def delete(c: typer.Context, id: str, reason: str = typer.Option(None, "--reason"),
           yes: bool = typer.Option(False, "--yes", "-y")):
    ctx = _ctx(c)
    if not (yes or ctx.assume_yes):
        console.console.print(f"Archive/tombstone project {id}? Audit evidence is retained.")
    data = ctx.client().delete_project(id, reason=reason)
    emit(ctx, {"object": "project", **data},
         lambda: console.line("freeze", id, "archived (audit evidence retained)"))


@app.command("freeze")
def freeze(c: typer.Context, id: str, yes: bool = typer.Option(False, "--yes", "-y")):
    ctx = _ctx(c)
    data = ctx.client().freeze_project(id)
    view = {"object": "project_freeze", **data}

    def render():
        console.panel("Cohort frozen", [
            ("cohort commitment", short(data.get("cohort_commitment", ""))),
            ("contributors", str(data.get("cohort_size", ""))),
            ("minimum contributors satisfied",
             "✔ " + f"(min {data.get('min_contributors','')})"
             if data.get("min_contributors_satisfied") else "✗"),
        ], kind="done")

    emit(ctx, view, render)


@app.command("invite")
def invite(c: typer.Context, id: str, expires: str = typer.Option("7d", "--expires"),
           qr: bool = typer.Option(False, "--qr"), count: int = typer.Option(1, "--count")):
    ctx = _ctx(c)
    data = sign_and_mint_invite(ctx, id, expires=expires, count=count, qr=qr)
    view = {"object": "invitation", **data}

    def render():
        rows = [
            ("link", data.get("url", data.get("link", ""))),
            ("project id", id),
            ("expires", data.get("expires_at", data.get("expires", expires))),
        ]
        if data.get("signed"):
            rows.append(("signed", f"✔ keyholder {data.get('owner_key_fingerprint', '')}"))
        console.panel("Contributor invite", rows, kind="info")

    emit(ctx, view, render)


@app.command("events")
def events(c: typer.Context, id: str, since: str = typer.Option(None, "--since"),
           verify: bool = typer.Option(False, "--verify")):
    ctx = _ctx(c)
    data = ctx.client().project_events(id, since=since)
    evs = data.get("events", data if isinstance(data, list) else [])
    chain_ok = _verify_event_chain(evs) if verify else None
    view = {"object": "list", "data": evs, "chain_verified": chain_ok}

    def render():
        rows = [[e.get("type", ""), short(e.get("event_hash", "")), e.get("created_at", "")]
                for e in evs]
        console.table(["event", "hash", "at"], rows)
        if verify:
            console.status_line(bool(chain_ok), "event chain",
                                "hash chain intact" if chain_ok else "CHAIN BROKEN")

    emit(ctx, view, render)
    # A broken append-only chain must fail the exit code too, not just print red:
    # `blind verify --project <id>` is a gate a reviewer/CI can script on.
    if verify and not chain_ok:
        raise typer.Exit(code=VerificationError.code)


def _verify_event_chain(events: list[dict]) -> bool:
    """Re-check the append-only hash chain: each event's `prev_hash` must equal the
    previous event's `event_hash`."""
    prev = None
    for e in events:
        if prev is not None and e.get("prev_hash") not in (None, prev):
            return False
        prev = e.get("event_hash")
    return True


# ==========================================================================
# Porcelain — the guided study state machine (COMMANDS.md "porcelain vs plumbing").
# One human verb per step of the loop (start -> contribute -> run -> proof); the
# resource commands above are the plumbing they orchestrate. Each porcelain command
# prints a Rails-style state transcript and always ends with the single next action.
# ==========================================================================


def _next_action(project_id: str, data: dict) -> tuple[str, str | None]:
    """Map project state -> (human headline, the single next command)."""
    state = data.get("state", "")
    cohort = int(data.get("cohort_size", 0) or 0)
    min_n = int(data.get("min_contributors", 0) or 0)
    satisfied = bool(data.get("min_n_satisfied", data.get("min_contributors_satisfied")))
    runs = int(data.get("run_count", 0) or 0)
    if state in ("archived", "tombstoned", "deleted"):
        return "Study archived", None
    if state == "running":
        return "Compute running", f"blind projects run {project_id}"
    if runs and (data.get("latest_result_digest") or state == "completed"):
        return "Result ready — share the proof", f"blind projects proof {project_id}"
    if state == "frozen":
        return "Cohort frozen — ready to run", f"blind projects run {project_id}"
    if cohort == 0 and data.get("public_context_published") is False:
        return "Publish the public context", f"blind keys create --project {project_id}"
    if not satisfied or cohort < min_n:
        need = max(min_n - cohort, 0)
        return (f"Collecting contributions ({cohort}/{min_n})",
                f"share the contribute link with {need} more data owner(s)")
    return "Ready to run", f"blind projects run {project_id}"


@app.command("status")
def status(c: typer.Context, id: str):
    """Progress-first study status: what is happening, what is blocked, and the ONE
    next command. Porcelain over `projects retrieve`, reordered so the next action
    sits above the commitment hashes."""
    ctx = _ctx(c)
    data = ctx.client().retrieve_project(id)
    headline, next_cmd = _next_action(id, data)
    cohort = int(data.get("cohort_size", 0) or 0)
    min_n = int(data.get("min_contributors", 0) or 0)
    view = {
        "object": "project_status", "id": id, "state": data.get("state", ""),
        "cohort_size": cohort, "min_contributors": min_n,
        "min_n_satisfied": bool(data.get("min_n_satisfied",
                                         data.get("min_contributors_satisfied"))),
        "run_count": int(data.get("run_count", 0) or 0),
        "next_action": headline, "next_command": next_cmd,
    }

    def render():
        console.panel(headline, [
            ("state", data.get("state", "")),
            ("contributors", f"{cohort} / {min_n}"),
            ("runs", str(view["run_count"])),
        ], kind="info")
        if next_cmd:
            console.console.print(console.Text(f"  next   {next_cmd}", style="meta"))
        console.line("verify", short(data.get("application_digest", "")), "application")
        cc = data.get("cohort_commitment")
        console.line("commit", short(cc) if cc else "—", "cohort commitment")

    emit(ctx, view, render)


@app.command("start")
def start(
    c: typer.Context,
    application: str,
    name: str = typer.Option(None, "--name"),
    min_contributors: int = typer.Option(20, "--min", "--min-contributors", min=1),
    scenario: str = typer.Option(None, "--scenario"),
):
    """Start a study in one guided command: install + verify the signed application,
    create the project, generate LOCAL keys, publish ONLY the public context, and
    mint a contributor link. Porcelain over `applications install` + `projects
    create` + `keys create` + `projects invite`. The secret key never leaves this
    machine; the resource commands remain available for scripting each step."""
    ctx = _ctx(c)
    from blind.cli.groups.applications import install as applications_install
    from blind.workspace import installed_bundle, resolve_project_bundle, run_keygen

    human = not ctx.json and not ctx.quiet

    # 1. install + verify the signed application (idempotent). Under --json a
    #    scripted caller installs first (the install command has its own contract).
    try:
        installed_bundle(ctx.store, application)
        if human:
            console.line("identical", application.split("@")[0], "application installed")
    except Exception:
        if ctx.json:
            raise
        applications_install(c, name=application, version=None, force=False)

    # 2. create the project pinned to the application digest.
    proj = ctx.client().create_project(application=application, name=name,
                                       min_contributors=min_contributors, scenario=scenario)
    project_id = proj.get("id")
    if human:
        console.line("create", project_id, name or "project active")

    # 3. LOCAL keygen + publish ONLY the public context (secret never leaves).
    bundle = resolve_project_bundle(ctx.store, project_id, application)
    kg = run_keygen(ctx.store, project_id, bundle)
    ctx.client().put_public_context(project_id, kg.public_context_sha256,
                                    kg.public_context_path.read_bytes())
    # Registration is mandatory: this guided flow never falls back to unsigned links.
    ctx.client().put_owner_key(project_id, kg.owner_signing_pubkey)
    if human:
        console.line("create", "keypair", "secret in ~/.blind", trust="private")
        console.line("publish", short(kg.public_context_sha256), "public context", trust="public")

    # 4. mint the contributor link (SIGNED when the owner key + context are in place).
    inv = sign_and_mint_invite(ctx, project_id, expires="7d", count=1)
    link = inv.get("url", inv.get("link", ""))

    contribute_cmd = f"blind contribute {link} ./their_vector.csv"
    view = {"object": "project_started", "id": project_id, "application": application,
            "public_context_sha256": kg.public_context_sha256, "invite_link": link,
            "min_contributors": min_contributors, "contribute_command": contribute_cmd}

    def render():
        console.line("create", "link", link, "expires in 7 days")
        console.panel("Project ready for contributions", [
            ("project", project_id),
            ("application", application.split("@")[0]),
            ("min contributors", str(min_contributors)),
        ])
        console.console.print(console.Text(f"  share  {contribute_cmd}", style="meta"))
        console.console.print(console.Text(
            f"  track  blind projects status {project_id}", style="meta"))

    emit(ctx, view, render)


@app.command("run")
def run(
    c: typer.Context,
    id: str,
    yes: bool = typer.Option(False, "--yes", "-y"),
    timeout: int = typer.Option(300, "--timeout"),
    interval: float = typer.Option(2.0, "--interval"),
):
    """Run a study end to end: check readiness, freeze the cohort (explicit confirm —
    freeze is a governance commit), dispatch compute, watch the sandbox stages, and
    decrypt ONLY the aggregate locally. Porcelain over `projects freeze` + `jobs
    create/watch` + `results decrypt`. Refuses cleanly (and says why) when the study
    is not ready."""
    ctx = _ctx(c)
    from blind.workspace import resolve_project_bundle, run_decrypt_decode

    human = not ctx.json and not ctx.quiet
    data = ctx.client().retrieve_project(id)
    state = data.get("state", "")
    cohort = int(data.get("cohort_size", 0) or 0)
    min_n = int(data.get("min_contributors", 0) or 0)
    satisfied = bool(data.get("min_n_satisfied", data.get("min_contributors_satisfied")))

    # Readiness gate: refuse cleanly and explain the single next action.
    if state == "active" and (not satisfied or cohort < min_n):
        need = max(min_n - cohort, 0)
        blocked = {"object": "project_run_blocked", "id": id,
                   "reason": "min_contributors_not_met",
                   "cohort_size": cohort, "min_contributors": min_n,
                   "next_command": f"share the contribute link with {need} more data owner(s)"}
        emit(ctx, blocked, lambda: console.panel("Cannot run yet", [
            ("contributors", f"{cohort} / {min_n}"),
            ("next action", f"share the contribution link with {need} more data owner(s)"),
        ], kind="trust"))
        raise typer.Exit(code=0)

    # Estimate + EXPLICIT freeze confirmation (never auto-freeze silently).
    if state == "active":
        est = ctx.client().estimate_job(id)
        cost = est.get("estimated_cost_usd", "?")
        if human:
            console.panel("Ready to run", [
                ("contributors", f"{cohort} / {min_n}"),
                ("estimated cost", f"~ ${cost}"),
            ], kind="info")
            console.console.print(console.Text(
                "Freeze is permanent for this cohort. New contributions will be rejected.",
                style="warn"))
        if not (yes or ctx.assume_yes or ctx.json):
            if not typer.confirm(f"Freeze the cohort and run compute for ~ ${cost}?"):
                raise typer.Exit(code=0)
        fr = ctx.client().freeze_project(id)
        if human:
            console.line("freeze", short(fr.get("cohort_commitment", "")),
                         "governance commit", trust=None)

    # Dispatch + watch + decrypt.
    job = ctx.client().create_job(id)
    job_id = job.get("id")
    if human:
        console.line("create", job_id, "dispatched → sandbox (network: none)")
    terminal = {"completed", "succeeded", "failed", "error", "cancelled"}
    jstate = job.get("state", "")
    import time as _time
    waited = 0.0
    while jstate not in terminal and waited < timeout:
        _time.sleep(interval)
        waited += interval
        jstate = ctx.client().retrieve_job(job_id).get("state", jstate)
    if jstate in {"failed", "error", "cancelled"}:
        raise UsageError(f"Compute job {job_id} ended in state {jstate!r}.")
    if human:
        console.line("compute", job_id, f"{jstate} (network none, ciphertext only)")

    # Decrypt ONLY the aggregate, locally, with the project's own secret key.
    result = ctx.client().retrieve_result(job_id)
    ct = result.get("ciphertext_bytes", b"")
    ct = ct.encode() if isinstance(ct, str) else bytes(ct)
    # Fail closed on the server-delivered ciphertext BEFORE it touches the local
    # secret key: an absent OR mismatched result digest refuses the bytes (a
    # hostile server can strip the digest as easily as it can swap the payload).
    require_result_digest(result.get("result_digest", ""), ct)
    bundle = resolve_project_bundle(ctx.store, id)
    result_dir = ctx.store.result_dir(id, job_id)
    result_dir.mkdir(parents=True, exist_ok=True)
    ct_path = result_dir / "result.ct"
    ct_path.write_bytes(ct)
    aggregate = run_decrypt_decode(ctx.store, id, bundle, ct_path, result_dir)
    sentinel_n = (aggregate.get("n_contributors") or aggregate.get("sentinel_n")
                  or aggregate.get("n"))

    cert_hash = result.get("certificate_hash") or job.get("certificate_hash")
    view = {"object": "project_run", "id": id, "job": job_id,
            "result_digest": result.get("result_digest", ""),
            "sentinel_n": sentinel_n, "aggregate": aggregate,
            "certificate_hash": cert_hash,
            "verify_command": f"blind verify {cert_hash}" if cert_hash else None,
            "trust": {"result_plain": "local_only"}}

    def render():
        console.line("decrypt", "aggregate", f"sentinel N = {sentinel_n}", trust="raw")
        console.panel("Run complete", [
            ("result digest", short(view["result_digest"])),
            ("certificate", short(cert_hash) if cert_hash else "—"),
        ], kind="done")
        if cert_hash:
            console.console.print(console.Text(
                f"  proof  blind projects proof {id}", style="meta"))

    emit(ctx, view, render)


@app.command("proof")
def proof(c: typer.Context, id: str):
    """Fetch the study's computation certificate and the ONE command a reviewer runs
    to verify it offline. Porcelain over `certificates list` / `certificates
    verify`."""
    ctx = _ctx(c)
    data = ctx.client().list_certificates(id)
    certs = data.get("certificates", data.get("data", data if isinstance(data, list) else []))
    latest = certs[-1] if certs else None
    cert_hash = (latest or {}).get("certificate_hash") if latest else None
    view = {"object": "project_proof", "id": id, "certificate_hash": cert_hash,
            "verify_command": f"blind verify {cert_hash}" if cert_hash else None,
            "public_url": (latest or {}).get("public_url")}

    def render():
        if not cert_hash:
            console.panel("No certificate yet", "Run the study first: "
                          f"blind projects run {id}", kind="info")
            return
        console.panel("Computation certificate", [
            ("certificate", short(cert_hash)),
            ("public url", view["public_url"] or "—"),
        ], kind="done")
        console.console.print(console.Text(
            f"  reviewer runs   blind verify {cert_hash}", style="meta"))

    emit(ctx, view, render)
