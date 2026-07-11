"""`blind bench` / `blind simulate --sweep` — the benchmark matrix + emitters.

All offline, network-free, against the signed stub bundles from conftest (the
flagship-shaped additive fake + a second multiplicative fake). No real crypto,
no six applications — the stub honors the real stage I/O convention and the
value-preserving "crypto" matches the cleartext oracle bit-for-bit.
"""

from __future__ import annotations

import csv
import json
import math

from typer.testing import CliRunner

import blind.benchmark as bench
import blind.context as ctxmod
from blind.cli.app import app
from blind.simulate import CohortSpec

runner = CliRunner()


def _json_out(result):
    text = result.stdout
    start = text.index("{")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise AssertionError("no JSON object in output:\n" + text)


def _run_sweep(bundle, sweep_spec, *, length=4, security="128"):
    axes = bench.parse_sweep(sweep_spec)
    base_axes = bench.base_axes_from_flags(n="20", length=length,
                                           crypto=bench.default_crypto_for(bundle),
                                           security=security)
    base_spec = CohortSpec(n=0, length=length, seed=42)
    return bench.run_sweep(bundle, base_spec, axes, base_axes)


# --- 1. Cross-product cardinality ------------------------------------------

def test_sweep_cross_product_cardinality(installed):
    store, bundle, application_id = installed
    matrix = _run_sweep(bundle, "n=20,100 crypto=bfv-add,bfv-mul length=4,8")
    # 2 (N) × 2 (crypto) × 2 (length) × 1 (security default) = 8 cells.
    assert len(matrix.cells) == 8
    d = bench.write_matrix_dir(matrix, store.home / "simulations", bundle,
                               CohortSpec(n=0, length=4, seed=42), ["table"])
    with open(d / "benchmark.csv") as fh:
        rows = list(csv.reader(fh))
    assert len(rows) == 1 + 8  # header + 8 data rows


def test_expand_cells_is_full_grid_not_zip():
    axes = bench.parse_sweep("n=20,100,1000 crypto=bfv-add,bfv-mul security=128,192")
    base = bench.base_axes_from_flags(n="20", length=8, crypto="bfv-add", security="128")
    cells = bench.expand_cells(axes, base)
    assert len(cells) == 3 * 2 * 1 * 2  # N × crypto × length(base=1) × security = 12


# --- 2. Emitter round-trip (CSV headers / booktabs TeX / MD pipe table) -----

def test_emitters_shapes(installed):
    store, bundle, application_id = installed
    matrix = _run_sweep(bundle, "n=20,100 crypto=bfv-add")
    d = bench.write_matrix_dir(matrix, store.home / "simulations", bundle,
                               CohortSpec(n=0, length=4, seed=42), ["table"])

    with open(d / "benchmark.csv") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == bench.CSV_COLUMNS
        data_rows = list(reader)
    assert len(data_rows) == 2
    # every §1 measurement column is present
    for col in ("runtime_ms", "ct_bytes_per_contribution", "peak_rss_bytes",
                "cpu_seconds", "raw_cost_cents", "marked_up_cost_cents",
                "max_error", "exact", "feasibility"):
        assert col in bench.CSV_COLUMNS

    tex = (d / "benchmark.tex").read_text()
    assert r"\toprule" in tex and r"\midrule" in tex and r"\bottomrule" in tex

    md_lines = (d / "benchmark.md").read_text().strip().splitlines()
    assert md_lines[0].startswith("|") and md_lines[0].endswith("|")
    assert set(md_lines[1].replace("|", "").split()) == {"---"}
    # header + separator + 2 data rows
    assert len(md_lines) == 4


# --- 3. Cost model purity (mirrors computation_run.rb:63) --------------------

def test_cost_model_matches_server_formula(monkeypatch):
    monkeypatch.setenv("COMPUTE_BASE_CENTS_PER_CPU_SECOND", "3.0")
    monkeypatch.setenv("COMPUTE_MARKUP_MULTIPLIER", "2.0")
    cpu = 7.5
    cost = bench.cost_model(cpu, "bfv-add", n=100, length=16, security=128)
    assert cost.raw_cost_cents == cpu * 3.0                      # raw = cpu × base
    assert cost.marked_up_cost_cents == math.ceil(cpu * 3.0 * 2.0)  # ceil(cpu × base × markup)


def test_cost_model_projection_reconciles_with_server(monkeypatch):
    # At the default approach/security + reference length, the projected CPU-seconds
    # equal N × per_contribution — the server's L-agnostic `jobs estimate`.
    monkeypatch.setenv("COMPUTE_ESTIMATED_CPU_SECONDS_PER_CONTRIBUTION", "1.0")
    monkeypatch.setenv("COMPUTE_BASE_CENTS_PER_CPU_SECOND", "2.0")
    monkeypatch.setenv("COMPUTE_MARKUP_MULTIPLIER", "1.5")
    projected = bench.project_cpu_seconds("bfv-add", n=200, length=bench.REFERENCE_LENGTH,
                                          security=128)
    assert projected == 200.0
    cost = bench.cost_model(None, "bfv-add", n=200, length=bench.REFERENCE_LENGTH, security=128)
    assert cost.marked_up_cost_cents == math.ceil(200.0 * 2.0 * 1.5)


def test_cost_model_scales_with_crypto_and_security():
    add = bench.project_cpu_seconds("bfv-add", 100, 16, 128)
    mul = bench.project_cpu_seconds("bfv-mul", 100, 16, 128)
    sec = bench.project_cpu_seconds("bfv-add", 100, 16, 256)
    assert mul > add        # multiplicative depth costs more
    assert sec > add        # 256-bit security costs more


# --- 4. Additive-vs-multiplicative row (two application shapes, never six) ------

def test_sweep_runs_additive_and_multiplicative_shapes(installed, installed_mul):
    add_store, add_bundle, _ = installed
    add_matrix = _run_sweep(add_bundle, "n=6 crypto=bfv-add,bfv-mul length=4")
    assert {c.crypto for c in add_matrix.cells} == {"bfv-add", "bfv-mul"}
    assert all(c.exact for c in add_matrix.cells)  # additive stub == oracle, both labels

    mul_store, mul_bundle, _ = installed_mul
    mul_matrix = _run_sweep(mul_bundle, "n=6 crypto=bfv-mul length=4")
    # multiplicative compute (squares then sums) == the oracle's multiplicative branch
    assert all(c.exact for c in mul_matrix.cells)
    assert mul_bundle.manifest.computation == "multiplicative_bfv"


# --- 5. Equivalence per cell ------------------------------------------------

def test_every_cell_carries_exactness(installed):
    store, bundle, application_id = installed
    matrix = _run_sweep(bundle, "n=4,8 crypto=bfv-add")
    for cell in matrix.cells:
        assert cell.feasibility == "ok"
        assert cell.exact is True
        assert cell.max_error == 0        # BFV additive → bit-exact
    assert matrix.passed is True


# --- 6. Plots degrade gracefully --------------------------------------------

def test_plots_rendered_when_matplotlib_present(installed):
    import pytest

    pytest.importorskip("matplotlib")
    store, bundle, application_id = installed
    matrix = _run_sweep(bundle, "n=20,100 crypto=bfv-add")
    d = bench.write_matrix_dir(matrix, store.home / "simulations", bundle,
                               CohortSpec(n=0, length=4, seed=42), ["table", "plots"])
    plots = d / "plots"
    assert (plots / "plot.py").exists()
    assert list(plots.glob("*.svg")), "expected rendered SVG plots"
    # each plot ships beside its source CSV slice
    assert (plots / "runtime_vs_n.csv").exists()


def test_plots_skip_gracefully_without_matplotlib(installed, monkeypatch):
    store, bundle, application_id = installed
    monkeypatch.setattr(bench, "_load_pyplot", lambda: None)
    matrix = _run_sweep(bundle, "n=20,100 crypto=bfv-add")
    d = bench.write_matrix_dir(matrix, store.home / "simulations", bundle,
                               CohortSpec(n=0, length=4, seed=42), ["table", "plots"])
    # CSV/MD/TeX still emitted; plots skipped with a note + no SVGs.
    assert (d / "benchmark.csv").exists()
    assert (d / "benchmark.md").exists()
    assert (d / "benchmark.tex").exists()
    assert not list((d / "plots").glob("*.svg"))
    assert (d / "plots" / "README.md").exists()
    assert (d / "plots" / "runtime_vs_n.csv").exists()  # slices still written


# --- 7. Non-authoritative invariant preserved -------------------------------

def test_matrix_is_non_authoritative(installed):
    store, bundle, application_id = installed
    matrix = _run_sweep(bundle, "n=6 crypto=bfv-add")
    d = bench.write_matrix_dir(matrix, store.home / "simulations", bundle,
                               CohortSpec(n=0, length=4, seed=42), ["table"])
    view = matrix.as_dict()
    assert view["authoritative"] is False
    assert view["object"] == "simulation_run"
    assert view["mode"] == "sweep"
    # never a certificate / cohort commitment
    assert "cohort_commitment" not in view
    assert not (d / "certificate.json").exists()
    prov = json.loads((d / "provenance.json").read_text())
    assert "certificate_hash" not in prov
    assert prov["git_commit"] is None or isinstance(prov["git_commit"], str)
    # per-artifact SHA-256 binding (docs/simulation_mode.md §3)
    assert prov["artifacts"]["benchmark.csv"].startswith("sha256:")


# --- provenance completeness -------------------------------------------------

def test_provenance_has_git_and_artifact_hashes(installed):
    store, bundle, application_id = installed
    matrix = _run_sweep(bundle, "n=6 crypto=bfv-add,bfv-mul")
    d = bench.write_matrix_dir(matrix, store.home / "simulations", bundle,
                               CohortSpec(n=0, length=4, seed=42),
                               ["table", "methods", "threat_model"])
    prov = json.loads((d / "provenance.json").read_text())
    assert "git_commit" in prov
    assert prov["cost_model"]["markup_multiplier"] == bench.markup_multiplier()
    for name in ("benchmark.csv", "benchmark.md", "benchmark.tex", "methods.md"):
        assert prov["artifacts"][name].startswith("sha256:")


# --- CLI integration: `blind bench` + `blind simulate --sweep` --------------

def test_bench_cli_emits_matrix(installed):
    store, bundle, application_id = installed
    ctxmod.set_test_transport(None)
    r = runner.invoke(app, ["--json", "bench", application_id, "--n", "6,12",
                            "--sweep", "crypto=bfv-add,bfv-mul"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["object"] == "simulation_run"
    assert data["authoritative"] is False
    assert data["mode"] == "sweep"
    assert len(data["cells"]) == 4  # 2 N × 2 crypto
    d = store.home / "simulations" / data["sim_run_hash"]
    assert (d / "benchmark.csv").exists()
    assert (d / "benchmark.tex").exists()


def test_simulate_sweep_cli(installed):
    store, bundle, application_id = installed
    r = runner.invoke(app, ["--json", "simulate", application_id, "--synthetic",
                            "--sweep", "n=20,100 crypto=bfv-add,bfv-mul"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["mode"] == "sweep"
    assert len(data["cells"]) == 4
    assert all(cell["exact"] for cell in data["cells"])


def test_simulate_emit_table_triggers_matrix(installed):
    store, bundle, application_id = installed
    r = runner.invoke(app, ["--json", "simulate", application_id, "--synthetic",
                            "--n", "6", "--emit", "table"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["mode"] == "sweep"
    d = store.home / "simulations" / data["sim_run_hash"]
    assert (d / "benchmark.csv").exists()


# --- wired flags: --from, --attack differencing, --replay -------------------

def test_from_local_vectors(installed, tmp_path):
    store, bundle, application_id = installed
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "a.json").write_text(json.dumps({"vector": [1, 0, 2, 1]}))
    (raw / "b.json").write_text(json.dumps({"vector": [0, 1, 1, 0]}))
    r = runner.invoke(app, ["--json", "simulate", application_id,
                            "--from", str(raw), "--encrypted"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["mode"] == "from-local"
    assert data["n"] == 2
    assert data["equivalence"]["passed"] is True
    assert data["oracle_result"] == [1, 1, 3, 1]  # column sums


def test_attack_differencing_recovers_target(installed):
    store, bundle, application_id = installed
    r = runner.invoke(app, ["--json", "simulate", application_id,
                            "--attack", "differencing", "--n", "8", "--length", "4"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["object"] == "attack_demo"
    assert data["recovered_exactly"] is True
    assert data["recovered_vector"] == data["target_vector"]


def test_replay_reproduces_sweep(installed):
    store, bundle, application_id = installed
    r1 = runner.invoke(app, ["--json", "bench", application_id, "--n", "6,12",
                             "--sweep", "crypto=bfv-add"])
    h1 = _json_out(r1)["sim_run_hash"]
    r2 = runner.invoke(app, ["--json", "simulate", application_id, "--replay", h1])
    assert r2.exit_code == 0, r2.stdout
    data = _json_out(r2)
    assert data["mode"] == "replay"
    assert data["replayed"] == h1
    assert data["reproduced"] is True  # deterministic sim-run hash reproduced


def test_against_result_local_file(installed, tmp_path):
    store, bundle, application_id = installed
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "a.json").write_text(json.dumps({"vector": [1, 0, 2, 1]}))
    (raw / "b.json").write_text(json.dumps({"vector": [2, 2, 0, 1]}))
    result = tmp_path / "result.json"
    result.write_text(json.dumps({"vector": [3, 2, 2, 2]}))  # column sums
    r = runner.invoke(app, ["--json", "simulate", application_id, "--from", str(raw),
                            "--against-result", str(result)])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["mode"] == "against-result"
    assert data["equivalence"]["passed"] is True
