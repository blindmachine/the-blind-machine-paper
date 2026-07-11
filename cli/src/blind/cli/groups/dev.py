"""`blind dev` — plaintext-vs-encrypted harness (LOCAL). The daily equivalence primitive."""

from __future__ import annotations

import typer

from blind import console
from blind.context import Context, emit
from blind.simulate import (
    CohortSpec,
    assert_equivalence,
    generate_cohort,
    run_cleartext_oracle,
    run_encrypted_engine,
)
from blind.workspace import installed_bundle

app = typer.Typer(help="Plaintext-vs-encrypted developer harness.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


@app.command("run-local")
def run_local(c: typer.Context, application: str, n: int = typer.Option(20, "--n"),
              length: int = typer.Option(16, "--length"), seed: int = typer.Option(42, "--seed")):
    ctx = _ctx(c)
    bundle = installed_bundle(ctx.store, application)
    cohort = generate_cohort(CohortSpec(n=n, length=length, seed=seed))
    result = run_cleartext_oracle(cohort, bundle.manifest.computation or "additive_bfv")
    emit(ctx, {"object": "dev_run", "engine": "cleartext", "application": bundle.application_id,
               "result": result},
         lambda: console.line("compute", "cleartext oracle", f"N={n} → {len(result)} values"))


@app.command("run-encrypted")
def run_encrypted(c: typer.Context, application: str, n: int = typer.Option(20, "--n"),
                  length: int = typer.Option(16, "--length"), seed: int = typer.Option(42, "--seed")):
    ctx = _ctx(c)
    bundle = installed_bundle(ctx.store, application)
    cohort = generate_cohort(CohortSpec(n=n, length=length, seed=seed))
    result = run_encrypted_engine(bundle, cohort)
    emit(ctx, {"object": "dev_run", "engine": "encrypted", "application": bundle.application_id,
               "result": result},
         lambda: console.line("compute", "encrypted end-to-end", f"N={n} → {len(result)} values"))


@app.command("compare")
def compare(c: typer.Context, application: str, n: int = typer.Option(20, "--n"),
            length: int = typer.Option(16, "--length"), seed: int = typer.Option(42, "--seed"),
            tolerance: float = typer.Option(None, "--tolerance")):
    ctx = _ctx(c)
    bundle = installed_bundle(ctx.store, application)
    comp = bundle.manifest.computation or "additive_bfv"
    tol = tolerance if tolerance is not None else bundle.manifest.tolerance
    cohort = generate_cohort(CohortSpec(n=n, length=length, seed=seed))
    oracle = run_cleartext_oracle(cohort, comp)
    encrypted = run_encrypted_engine(bundle, cohort)
    eq = assert_equivalence(oracle, encrypted, tol)
    view = {"object": "dev_compare", "application": bundle.application_id,
            "passed": eq.passed, "max_observed_error": eq.max_error, "tolerance": tol}

    def render():
        console.status_line(eq.passed, "cleartext == encrypted",
                            f"max err {eq.max_error}",
                            "bit-exact" if eq.max_error == 0 else f"within {tol}")

    emit(ctx, view, render)
    if not eq.passed:
        from blind.errors import VerificationError
        raise typer.Exit(code=VerificationError.code)
