"""`blind simulations` (alias `blind simulate`) — the paper-creation engine (LOCAL)."""

from __future__ import annotations

import json

import typer

from blind import benchmark as bench
from blind import console
from blind.context import Context, emit
from blind.hashing import short
from blind.simulate import (
    CohortSpec,
    assert_against_result,
    differencing_demo,
    run_local_oracle,
    simulate,
)
from blind.workspace import installed_bundle

app = typer.Typer(help="Simulation mode — non-authoritative synthetic twin.",
                  no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def _sizes(n: str) -> list[int]:
    return [int(x) for x in str(n).split(",") if x.strip()]


def run_create(
    ctx: Context,
    application: str,
    *,
    n: str = "20",
    length: int = 16,
    seed: int = 42,
    maf_dist: str = "beta",
    missingness: float = 0.0,
    encrypted: bool = False,
    emit_artifacts: str | None = None,
    sweep: str | None = None,
    crypto: str | None = None,
    security: str = "128",
    coordinates: str | None = None,
    bench_mode: bool = False,
    from_dir: str | None = None,
    against_result: str | None = None,
    replay: str | None = None,
    attack: str | None = None,
) -> dict:
    bundle = installed_bundle(ctx.store, application)
    emit_list = [x for x in (emit_artifacts or "").split(",") if x]
    out_root = ctx.store.home / "simulations"

    # --- accepted-but-previously-unimplemented flags -----------------------
    if replay:
        return bench.replay(out_root / replay, bundle, emit_list or ["table"],
                            out_root=out_root)
    if attack:
        if attack != "differencing":
            from blind.errors import UsageError
            raise UsageError(f"Unknown --attack {attack!r} (only 'differencing').")
        return differencing_demo(bundle, n=_sizes(n)[0] if _sizes(n) else 50, seed=seed,
                                 length=length)
    if from_dir:
        if against_result:
            return assert_against_result(bundle, from_dir, against_result)
        return run_local_oracle(bundle, from_dir, encrypted=encrypted)

    # --- matrix mode: --sweep, `blind bench`, or --emit table/plots --------
    sweep_axes = bench.parse_sweep(sweep)
    matrix_mode = bool(sweep_axes) or bench_mode or \
        ("table" in emit_list) or ("plots" in emit_list)
    if matrix_mode:
        default_emit = ["methods", "table", "plots", "threat_model"] if bench_mode \
            else (emit_list or ["table"])
        emit_for = emit_list or default_emit
        base_crypto = crypto or bench.default_crypto_for(bundle)
        base_axes = bench.base_axes_from_flags(n=n, length=length, crypto=base_crypto,
                                               security=security)
        base_spec = CohortSpec(n=0, length=length, seed=seed, maf_dist=maf_dist,
                               missingness=missingness, coordinates=coordinates)
        cells_total = len(bench.expand_cells(sweep_axes, base_axes))
        streamed: list[dict] = []

        def _on_cell(i, total, cell):
            streamed.append({"object": "benchmark_cell", "index": i, "total": total,
                             **cell.as_dict()})

        matrix = bench.run_sweep(bundle, base_spec, sweep_axes, base_axes,
                                 on_cell=_on_cell)
        matrix.directory = bench.write_matrix_dir(matrix, out_root, bundle, base_spec,
                                                  emit_for)
        view = matrix.as_dict()
        view["cell_count"] = cells_total
        view["emitted"] = ["benchmark.csv", "benchmark.md", "benchmark.tex"] + \
            (["plots/"] if "plots" in emit_for else [])
        return view

    # --- legacy single-axis N loop -----------------------------------------
    runs = []
    last = None
    for size in _sizes(n):
        spec = CohortSpec(n=size, length=length, seed=seed, maf_dist=maf_dist,
                          missingness=missingness, coordinates=coordinates,
                          crypto=crypto)
        run = simulate(bundle, spec, encrypted=encrypted, emit=emit_list,
                       out_root=out_root)
        runs.append(run)
        last = run
    view = {
        "object": "simulation_run",
        "authoritative": False,
        "mode": "loop",
        "sim_run_hash": last.sim_hash if last else None,
        "application": bundle.application_id,
        "coordinate_hash": last.provenance.get("coordinate_hash") if last else None,
        "runs": [r.as_dict() for r in runs],
        "directory": str(last.directory) if last and last.directory else None,
    }
    return view


def render_matrix(view: dict, seed: int) -> None:
    """The rich.table matrix + progress-style summary (UX.md §5)."""
    console.line("simulate", view.get("application", ""),
                 f"coordinates {short(view.get('coordinate_hash', '') or '')}  seed {seed}")
    cells = view.get("cells", [])
    console.line("sweeping", f"{len(cells)} cells", "grid: N × L × crypto × security")
    rows = []
    for cell in cells:
        exact = "✔ exact" if cell["exact"] else "✗ " + cell["feasibility"]
        rows.append([cell["n"], cell["crypto"], cell["length"], cell["security"],
                     f"{cell['runtime_ms']:.1f} ms", f"{cell['ct_bytes_total']} B",
                     f"{cell['peak_rss_bytes']} B",
                     f"{cell['marked_up_cost_cents']}¢", exact])
    console.table(["N", "crypto", "L", "sec", "runtime", "ct size", "peak RSS",
                   "cost", "exact?"], rows)
    eq = view.get("equivalence", {})
    console.status_line(eq.get("passed", False), "cleartext oracle == encrypted",
                        f"max err {eq.get('max_observed_error', '')}",
                        "bit-exact" if eq.get("max_observed_error") == 0 else "")
    if view.get("directory"):
        console.line("emitted", view["directory"])
    console.panel("Simulation (non-authoritative)", [
        ("sim run", short(view.get("sim_run_hash") or "")),
        ("synthetic", f"seeded ({seed}) · no real data · nothing uploaded"),
    ], kind="info")


@app.command("create")
def create(
    c: typer.Context,
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
    sweep: str = typer.Option(None, "--sweep",
                              help="feasibility grid, e.g. n=20,100 crypto=bfv-add,bfv-mul"),
    crypto: str = typer.Option(None, "--crypto",
                               help="override the application's crypto approach"),
    security: str = typer.Option("128", "--security", help="security level(s): 128,192,256"),
    from_dir: str = typer.Option(None, "--from", help="run the oracle on LOCAL raw vectors"),
    against_result: str = typer.Option(None, "--against-result",
                                       help="assert oracle == a produced result file"),
    replay: str = typer.Option(None, "--replay", help="reproduce a cited sim-run-hash"),
    attack: str = typer.Option(None, "--attack", help="differencing"),
):
    ctx = _ctx(c)
    view = run_create(ctx, application, n=n, length=length, seed=seed, maf_dist=maf_dist,
                      missingness=missingness, encrypted=(encrypted and not oracle_only),
                      emit_artifacts=emit_, sweep=sweep, crypto=crypto, security=security,
                      coordinates=coordinates, from_dir=from_dir,
                      against_result=against_result, replay=replay, attack=attack)

    def render():
        if view.get("mode") == "sweep":
            render_matrix(view, seed)
            return
        if view.get("object") == "attack_demo":
            console.line("simulate", application, "attack: differencing")
            console.status_line(view["recovered_exactly"], "target recovered",
                                "A_{K+1} − A_K", "exact leak on unfrozen cohort")
            console.panel("Differencing (leak → fix)", [
                ("leak", view["leak"]),
                ("fix", "; ".join(view["fix"])),
                ("not closed", view["not_closed"]),
            ], kind="info")
            return
        if view.get("mode") in ("from-local", "against-result"):
            eq = view["equivalence"]
            console.status_line(eq["passed"], "oracle == produced result",
                                f"max err {eq['max_observed_error']}")
            return
        console.line("simulate", application, f"seed {seed}")
        for r in view["runs"]:
            eq = r["equivalence"]
            size = r["config"]["cohort"]["n"]
            mark = "✔ exact" if eq["passed"] and eq["max_observed_error"] == 0 else \
                (f"~ tol {eq['tolerance']}" if eq["passed"] else "✗ MISMATCH")
            console.line("verify", f"N={size}", f"max err {eq['max_observed_error']}  {mark}")
        if view["directory"]:
            console.line("emitted", view["directory"])
        console.panel("Simulation (non-authoritative)", [
            ("sim run", short(view["sim_run_hash"] or "")),
            ("synthetic", f"seeded ({seed}) · no real data · nothing uploaded"),
        ], kind="info")

    emit(ctx, view, render)


@app.command("list")
def list_sims(c: typer.Context):
    ctx = _ctx(c)
    root = ctx.store.home / "simulations"
    data = []
    rows = []
    if root.exists():
        for d in sorted(root.iterdir()):
            cfg = d / "config.yml"
            if cfg.exists():
                import yaml
                conf = yaml.safe_load(cfg.read_text()) or {}
                data.append({"sim_run_hash": d.name, "application": conf.get("application")})
                rows.append([d.name, short(conf.get("application", ""))])
    emit(ctx, {"object": "list", "data": data},
         lambda: console.table(["sim run", "application"], rows))


@app.command("retrieve")
def retrieve(c: typer.Context, sim_run_hash: str):
    ctx = _ctx(c)
    d = ctx.store.home / "simulations" / sim_run_hash
    from blind.errors import UsageError

    if not d.exists():
        raise UsageError(f"No simulation run {sim_run_hash}")
    eq = json.loads((d / "equivalence.json").read_text()) if (d / "equivalence.json").exists() else {}
    prov = json.loads((d / "provenance.json").read_text()) if (d / "provenance.json").exists() else {}
    view = {"object": "simulation_run", "sim_run_hash": sim_run_hash,
            "equivalence": eq, "provenance": prov}
    emit(ctx, view, lambda: console.panel(f"sim {short(sim_run_hash)}", [
        ("application", short(prov.get("application", ""))),
        ("equivalence", "✔" if eq.get("passed") else "✗"),
        ("max error", str(eq.get("max_observed_error", ""))),
    ], kind="info"))
