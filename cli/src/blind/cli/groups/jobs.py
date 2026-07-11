"""`blind jobs` — compute on ciphertext (REMOTE)."""

from __future__ import annotations

import time

import typer

from blind import console
from blind.context import Context, emit
from blind.errors import BlindError, PreconditionError
from blind.hashing import short

app = typer.Typer(help="Compute on ciphertext.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


@app.command("estimate")
def estimate(c: typer.Context, project: str = typer.Option(..., "--project")):
    ctx = _ctx(c)
    data = ctx.client().estimate_job(project)
    view = {"object": "job_estimate", **data}

    def render():
        console.line("estimate", "compute",
                     f"~ {data.get('estimated_cpu_seconds','?')} CPU-seconds "
                     f"~ ${data.get('estimated_cost_usd','?')}")
        console.panel("Cost estimate", [
            ("cohort", short(data.get("cohort_commitment", "")) or "—"),
            ("est. CPU-seconds", str(data.get("estimated_cpu_seconds", "?"))),
            ("est. cost", f"~ ${data.get('estimated_cost_usd', '?')}"),
        ], kind="info")

    emit(ctx, view, render)


@app.command("create")
def create(c: typer.Context, project: str = typer.Option(..., "--project"),
           yes: bool = typer.Option(False, "--yes", "-y")):
    ctx = _ctx(c)
    est = ctx.client().estimate_job(project)
    cost = est.get("estimated_cost_usd", "?")
    if not (yes or ctx.assume_yes or ctx.json):
        if not typer.confirm(f"Run this compute for ~ ${cost}?"):
            raise typer.Exit(code=0)
    try:
        data = ctx.client().create_job(project)
    except PreconditionError as exc:
        if exc.reason == "insufficient_credits":
            _insufficient_credits(ctx, exc, cost)
            raise typer.Exit(code=exc.code)
        raise
    view = {"object": "job", **data}

    def render():
        console.line("create", data.get("id", ""), "dispatched → sandbox (network: none)")
        console.panel("Job dispatched", [
            ("job id", data.get("id", "")),
            ("application", short(data.get("application_digest", ""))),
            ("cohort", short(data.get("cohort_commitment", ""))),
        ])

    emit(ctx, view, render)


def _insufficient_credits(ctx: Context, exc: PreconditionError, estimated_cost_usd) -> None:
    """The 409 insufficient_credits refusal: print the balance, the estimate,
    and the top-up URL — the price card at the moment of intent (docs/pricing.md
    §Surfaces). The balance fetch is best-effort; a second failure must not mask
    the refusal itself."""
    try:
        balance = ctx.client().credits()
    except BlindError:
        balance = {}
    view = {**exc.envelope(),
            "balance_cents": balance.get("balance_cents"),
            "balance_usd": balance.get("balance_usd"),
            "estimated_cost_usd": estimated_cost_usd,
            "top_up_url": ctx.billing_url()}

    def render():
        console.line("error", "insufficient credits",
                     "the balance does not cover this run's estimate")
        console.panel("Insufficient credits", [
            ("balance", f"${balance.get('balance_usd', '?')}"),
            ("estimated cost", f"~ ${estimated_cost_usd}"),
            ("top up", ctx.billing_url()),
        ], kind="trust")

    emit(ctx, view, render)


@app.command("list")
def list_jobs(c: typer.Context, project: str = typer.Option(..., "--project"),
              state: str = typer.Option(None, "--state")):
    ctx = _ctx(c)
    data = ctx.client().list_jobs(project, state=state)
    jobs = data.get("jobs", data if isinstance(data, list) else [])
    view = {"object": "list", "data": jobs}

    def render():
        rows = [[j.get("id", ""), j.get("state", ""), str(j.get("cost_usd", "")),
                 short(j.get("result_digest", ""))] for j in jobs]
        console.table(["job", "state", "cost", "result digest"], rows)

    emit(ctx, view, render)


@app.command("retrieve")
def retrieve(c: typer.Context, job: str):
    ctx = _ctx(c)
    data = ctx.client().retrieve_job(job)
    rows = [
        ("state", data.get("state", "")),
        ("cost", f"${data.get('cost_usd', '')}"),
        ("result digest", short(data.get("result_digest", "")) or "—"),
    ]
    if data.get("failure_reason"):
        rows.append(("failure reason", data["failure_reason"]))
    emit(ctx, {"object": "job", **data},
         lambda: console.panel(f"job {job}", rows, kind="info"))


@app.command("logs")
def logs(c: typer.Context, job: str, follow: bool = typer.Option(False, "--follow")):
    ctx = _ctx(c)
    data = ctx.client().job_logs(job)
    lines = data.get("logs", data if isinstance(data, list) else [])
    emit(ctx, {"object": "job_logs", "job": job, "logs": lines},
         lambda: [console.console.print(str(x)) for x in lines])


# Lifecycle lines the server always derives; anything else is a fine-grained
# worker stage row (verify_contexts → seal_env → compute → store_result).
TERMINAL_STAGES = frozenset({"completed", "failed"})
LIFECYCLE_STAGES = frozenset({"queued", "running"}) | TERMINAL_STAGES


def _stage_detail(event: dict) -> str:
    """Dim detail column for a fine stage line: elapsed + selected detail keys."""
    parts = []
    if event.get("elapsed_ms") is not None:
        parts.append(f"{event['elapsed_ms']} ms")
    if event.get("env_lock"):
        parts.append(f"env_lock {short(event['env_lock'])}")
    if event.get("cache"):
        parts.append(f"cache {event['cache']}")
    if event.get("ciphertext_count") is not None:
        parts.append(f"{event['ciphertext_count']} ciphertexts")
    if event.get("error"):
        parts.append(f"error {event['error']}")
    return " · ".join(parts)


def _render_event(event: dict) -> None:
    """Render one NEW stage-stream line (each transition renders exactly once)."""
    stage = event.get("stage", "")
    if stage in ("queued", "running"):
        console.line("compute", f"job {stage}", event.get("at") or "")
    elif stage == "completed":
        console.status_line(True, "completed", short(event.get("result_digest") or ""))
    elif stage == "failed":
        console.status_line(False, "failed", event.get("failure_reason") or "")
    elif event.get("status") == "running":
        console.line("compute", stage, _stage_detail(event) or "…")
    else:
        console.status_line(event.get("status") == "ok", stage,
                            short(event["result_digest"]) if event.get("result_digest") else "",
                            _stage_detail(event))


@app.command("watch")
def watch(c: typer.Context, job: str, timeout: int = typer.Option(300, "--timeout"),
          interval: float = typer.Option(2.0, "--interval",
                                         help="poll interval in seconds")):
    """Poll the job stage stream until a terminal completed/failed line (or --timeout)."""
    ctx = _ctx(c)
    client = ctx.client()
    live = not ctx.json and not ctx.quiet
    seen: set[tuple] = set()
    stages: list[dict] = []
    result_digest = None
    failure_reason = None
    terminal = None
    deadline = time.monotonic() + timeout

    while True:
        data = client.job_events(job)
        events = data.get("events", data if isinstance(data, list) else [])
        for event in events:
            if not isinstance(event, dict):
                continue
            key = (event.get("stage"), event.get("at"), event.get("status"))
            if key in seen:
                continue
            seen.add(key)
            stages.append(event)
            if event.get("result_digest"):
                result_digest = event["result_digest"]
            if event.get("failure_reason"):
                failure_reason = event["failure_reason"]
            if event.get("stage") in TERMINAL_STAGES:
                terminal = event["stage"]
            if live:
                _render_event(event)
        if terminal or time.monotonic() >= deadline:
            break
        time.sleep(interval)

    view = {"object": "job_watch", "job": job, "stages": stages, "result_digest": result_digest}
    if failure_reason:
        view["failure_reason"] = failure_reason

    def render():
        if terminal == "completed" and result_digest:
            console.panel("Job complete", [("result (cipher)", short(result_digest))])
        elif terminal == "failed":
            console.panel("Job failed", [("failure reason", failure_reason or "unknown")],
                          kind="trust")
        else:
            console.line("skip", f"watch timed out after {timeout}s",
                         "job not terminal yet")

    emit(ctx, view, render)
    if terminal == "failed":
        raise typer.Exit(code=1)
