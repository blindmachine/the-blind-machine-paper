"""The benchmark matrix — ``blind bench`` / ``blind simulate --sweep`` (LOCAL).

Turns the single-axis ``simulate --n`` loop into the full feasibility grid the
paper's §6 evaluation needs (docs/simulation_mode.md §2, paper-plan G1/G2/G7):

  * expand the cross-product of the swept axes — cohort size ``N`` × coordinate
    length ``L`` × crypto approach (``bfv-add`` / ``bfv-mul``) × security level
    (128 / 192 / 256);
  * measure each cell with the encrypted-on-synthetic engine (runtime split,
    ciphertext bytes, peak RSS, CPU-seconds) against the cleartext oracle
    (exactness), and price it through a local feasibility cost model;
  * emit ONE aggregated ``benchmark.{csv,md,tex}`` + ``plots/`` per sweep, plus
    the ``methods.md`` / ``threat_model.md`` / ``provenance.json`` paper artifacts.

The cost model is a *pure* function of ``(cpu_seconds, crypto, N, L, security)``.
It prices simulation/benchmark artifacts; hosted ``jobs estimate`` calls the
server and settlement prices the worker's measured CPU-minutes.
matplotlib is a lazy, optional dependency (the ``plots`` extra): its absence
skips plot rendering but never blocks the CSV/MD/TeX artifacts, keeping the
trust-critical core CLI dependency-light and network-free.
"""

from __future__ import annotations

import ast
import csv
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from blind.errors import UsageError
from blind.hashing import canonical_json, sha256_hex
from blind.provenance import machine_environment
from blind.runtime.bundle import Bundle
from blind.runtime.application_io import application_io_for
from blind.simulate import (
    CohortSpec,
    _coordinate_hash,
    artifact_hashes,
    assert_equivalence,
    generate_cohort,
    git_commit,
    measure_encrypted_engine,
)
from blind.version import __version__

# ---------------------------------------------------------------------------
# Cost model — pure function of (cpu_seconds, crypto, N, L, security)
# ---------------------------------------------------------------------------
#
# Simulation/benchmark projection only. Real `blind jobs estimate` calls the
# server, whose billing forecast follows packed-ciphertext execution and whose
# final charge uses measured CPU-minutes. This model instead projects
# feasibility across hypothetical N/L/crypto/security cells:
#   cost_cents = ceil(cpu_seconds × base × markup)
# We additionally report the paper's *raw* (un-marked-up) compute cost
# (paper-plan G2): raw = cpu_seconds × base.

DEFAULT_BASE_CENTS = 2.0
DEFAULT_MARKUP = 1.5
DEFAULT_CPU_SECONDS_PER_CONTRIBUTION = 1.0
# The CLI's default vector length (`--length 16`); the reference L at which the
# simulation projection's length multiplier is 1.0.
REFERENCE_LENGTH = 16


def base_cents_per_cpu_second() -> float:
    return float(os.environ.get("COMPUTE_BASE_CENTS_PER_CPU_SECOND", DEFAULT_BASE_CENTS))


def markup_multiplier() -> float:
    return float(os.environ.get("COMPUTE_MARKUP_MULTIPLIER", DEFAULT_MARKUP))


def estimated_cpu_seconds_per_contribution() -> float:
    return float(os.environ.get(
        "COMPUTE_ESTIMATED_CPU_SECONDS_PER_CONTRIBUTION", DEFAULT_CPU_SECONDS_PER_CONTRIBUTION))


def _norm_crypto(crypto: str | None) -> str:
    c = (crypto or "bfv-add").strip().lower().replace("_", "-")
    if c in ("additive-bfv", "bfv-additive", "additive"):
        return "bfv-add"
    if c in ("multiplicative-bfv", "bfv-multiplicative", "multiplicative", "bfv-var"):
        return "bfv-mul"
    return c


# Per-op cost multipliers used ONLY to *project* CPU-seconds when a cell is not
# directly measured (the "cheap-to-project, exact-to-validate" trick,
# docs/simulation_mode.md §2). Measured cells use their real CPU-seconds.
_CRYPTO_FACTOR = {"bfv-add": 1.0, "bfv-mul": 3.0}
_SECURITY_FACTOR = {128: 1.0, 192: 1.6, 256: 2.4}


def crypto_factor(crypto: str | None) -> float:
    return _CRYPTO_FACTOR.get(_norm_crypto(crypto), 1.0)


def security_factor(security: int) -> float:
    return _SECURITY_FACTOR.get(int(security), 1.0)


def length_factor(length: int) -> float:
    return max(int(length), 1) / REFERENCE_LENGTH


def project_cpu_seconds(crypto: str | None, n: int, length: int, security: int) -> float:
    """Projected CPU-seconds as a pure function of (crypto, N, L, security).

    At the default approach/security and the reference length this is exactly
    ``N × per_contribution`` — the server's L-agnostic estimate — so the two
    reconcile; longer L, ``bfv-mul``, and higher security scale it up."""
    per = estimated_cpu_seconds_per_contribution()
    return (max(int(n), 1) * per * crypto_factor(crypto)
            * length_factor(length) * security_factor(security))


@dataclass
class CostBreakdown:
    cpu_seconds: float
    raw_cost_cents: float
    marked_up_cost_cents: int
    base_cents_per_cpu_second: float
    markup_multiplier: float

    def as_dict(self) -> dict:
        return {
            "cpu_seconds": self.cpu_seconds,
            "raw_cost_cents": self.raw_cost_cents,
            "marked_up_cost_cents": self.marked_up_cost_cents,
            "base_cents_per_cpu_second": self.base_cents_per_cpu_second,
            "markup_multiplier": self.markup_multiplier,
        }


def cost_model(cpu_seconds: float | None = None, crypto: str | None = "bfv-add",
               n: int = 1, length: int = REFERENCE_LENGTH, security: int = 128) -> CostBreakdown:
    """Pure simulation cost model. Given measured ``cpu_seconds`` returns the
    raw + marked-up benchmark cost; given ``cpu_seconds=None`` it *projects*
    CPU-seconds from ``(crypto, N, L, security)`` first. This is a feasibility
    artifact, not the hosted run quote or settled charge."""
    if cpu_seconds is None:
        cpu_seconds = project_cpu_seconds(crypto, n, length, security)
    base = base_cents_per_cpu_second()
    markup = markup_multiplier()
    raw = cpu_seconds * base
    marked_up = math.ceil(cpu_seconds * base * markup)
    return CostBreakdown(cpu_seconds, raw, marked_up, base, markup)


# ---------------------------------------------------------------------------
# One grid cell
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "application", "crypto", "n", "length", "security",
    "encode_ms", "encrypt_ms", "compute_ms", "decrypt_ms", "runtime_ms",
    "ct_bytes_per_contribution", "ct_bytes_total", "peak_rss_bytes",
    "cpu_seconds", "raw_cost_cents", "marked_up_cost_cents",
    "max_error", "exact", "feasibility",
]


def _fmt(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


@dataclass
class BenchmarkCell:
    application: str
    crypto: str
    n: int
    length: int
    security: int
    encode_ms: float
    encrypt_ms: float
    compute_ms: float
    decrypt_ms: float
    runtime_ms: float
    ct_bytes_per_contribution: float
    ct_bytes_total: int
    peak_rss_bytes: int
    cpu_seconds: float
    raw_cost_cents: float
    marked_up_cost_cents: int
    max_error: float | None
    exact: bool
    feasibility: str

    def values(self) -> list:
        return [getattr(self, col) for col in CSV_COLUMNS]

    def row(self) -> list[str]:
        return [_fmt(v) for v in self.values()]

    def as_dict(self) -> dict:
        return {col: getattr(self, col) for col in CSV_COLUMNS}


# ---------------------------------------------------------------------------
# Sweep-spec parsing + cross-product expansion
# ---------------------------------------------------------------------------

# Split axis groups on whitespace OR on a comma that precedes the next `key=`
# token, so both `n=20,100 crypto=a,b` and `n=20,100,crypto=a,b` parse the same.
_AXIS_SPLIT = re.compile(r"[,\s]+(?=[A-Za-z_][A-Za-z0-9_]*=)")
_AXIS_ALIASES = {"n": "n", "size": "n", "sizes": "n", "length": "length",
                 "l": "length", "crypto": "crypto", "security": "security", "sec": "security"}


def parse_sweep(spec: str | None) -> dict[str, list[str]]:
    """`"n=20,100 crypto=bfv-add,bfv-mul length=4,8"` → {n:[..], crypto:[..], length:[..]}."""
    axes: dict[str, list[str]] = {}
    if not spec:
        return axes
    for token in _AXIS_SPLIT.split(spec.strip()):
        token = token.strip().strip(",")
        if not token or "=" not in token:
            continue
        key, _, raw = token.partition("=")
        key = _AXIS_ALIASES.get(key.strip().lower(), key.strip().lower())
        values = [v.strip() for v in raw.split(",") if v.strip() != ""]
        if values:
            axes[key] = values
    return axes


def _ints(values) -> list[int]:
    return [int(v) for v in values]


def expand_cells(axes: dict, base: dict) -> list[dict]:
    """Full cross-product of the four axes (a grid, not a 1:1 zip). Iteration
    order is N → L → crypto → security so the CSV is stable + reviewer-diffable."""
    n_values = _ints(axes.get("n", base["n"]))
    length_values = _ints(axes.get("length", base["length"]))
    crypto_values = list(axes.get("crypto", base["crypto"]))
    security_values = _ints(axes.get("security", base["security"]))
    cells = []
    for n in n_values:
        for length in length_values:
            for crypto in crypto_values:
                for security in security_values:
                    cells.append({"n": n, "length": length,
                                  "crypto": crypto, "security": security})
    return cells


# ---------------------------------------------------------------------------
# The sweep engine
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkMatrix:
    application: str
    cells: list[BenchmarkCell]
    axes: dict
    config: dict
    coordinate_hash: str
    sim_hash: str = ""
    directory: Path | None = None

    @property
    def passed(self) -> bool:
        return all(c.exact for c in self.cells)

    @property
    def max_observed_error(self) -> float:
        errs = [c.max_error for c in self.cells if c.max_error is not None]
        return max(errs) if errs else 0.0

    def as_dict(self) -> dict:
        return {
            "object": "simulation_run",
            "authoritative": False,
            "mode": "sweep",
            "sim_run_hash": self.sim_hash,
            "application": self.application,
            "coordinate_hash": self.coordinate_hash,
            "axes": self.axes,
            "cells": [c.as_dict() for c in self.cells],
            "equivalence": {"passed": self.passed,
                            "max_observed_error": self.max_observed_error},
            "directory": str(self.directory) if self.directory else None,
        }


def run_cell(bundle: Bundle, cell: dict, base_spec: CohortSpec,
             computation: str) -> BenchmarkCell:
    """Run one grid cell: seeded cohort → cleartext oracle + measured encrypted
    engine → exactness + cost. A crypto-layer failure (BFV ``t`` overflow /
    noise-budget exhaustion, or any stage raising) is recorded as an
    ``infeasible-at-params`` cell — a first-class publishable result — not a crash."""
    spec = CohortSpec(
        n=cell["n"], length=cell["length"], seed=base_spec.seed,
        maf_dist=base_spec.maf_dist, missingness=base_spec.missingness,
        security=cell["security"], crypto=cell["crypto"],
        coordinates=base_spec.coordinates, phenotype=base_spec.phenotype,
        bucketing=base_spec.bucketing,
    )
    cohort = generate_cohort(spec)
    adapter = application_io_for(bundle)
    oracle = adapter.compute_oracle(cohort, computation)
    try:
        engine = measure_encrypted_engine(bundle, cohort, adapter=adapter,
                                          security=int(cell["security"]))
        eq = assert_equivalence(oracle, engine.result, bundle.manifest.tolerance)
        m = engine.metrics
        cost = cost_model(m.cpu_seconds, cell["crypto"], cell["n"],
                          cell["length"], cell["security"])
        return BenchmarkCell(
            application=bundle.application_id, crypto=_norm_crypto(cell["crypto"]),
            n=cell["n"], length=cell["length"], security=cell["security"],
            encode_ms=round(m.encode_ms, 3), encrypt_ms=round(m.encrypt_ms, 3),
            compute_ms=round(m.compute_ms, 3), decrypt_ms=round(m.decrypt_ms, 3),
            runtime_ms=round(m.total_ms, 3),
            ct_bytes_per_contribution=round(m.ct_bytes_per_contribution, 2),
            ct_bytes_total=m.ct_bytes_total, peak_rss_bytes=m.peak_rss_bytes,
            cpu_seconds=round(m.cpu_seconds, 6),
            raw_cost_cents=round(cost.raw_cost_cents, 4),
            marked_up_cost_cents=cost.marked_up_cost_cents,
            max_error=eq.max_error, exact=eq.passed,
            feasibility="ok" if eq.passed else "infeasible-at-params",
        )
    except Exception:
        # No measurement possible; project the cost so the cell still prices out.
        cost = cost_model(None, cell["crypto"], cell["n"], cell["length"], cell["security"])
        return BenchmarkCell(
            application=bundle.application_id, crypto=_norm_crypto(cell["crypto"]),
            n=cell["n"], length=cell["length"], security=cell["security"],
            encode_ms=0.0, encrypt_ms=0.0, compute_ms=0.0, decrypt_ms=0.0,
            runtime_ms=0.0, ct_bytes_per_contribution=0.0, ct_bytes_total=0,
            peak_rss_bytes=0, cpu_seconds=round(cost.cpu_seconds, 6),
            raw_cost_cents=round(cost.raw_cost_cents, 4),
            marked_up_cost_cents=cost.marked_up_cost_cents,
            max_error=None, exact=False, feasibility="infeasible-at-params",
        )


def run_sweep(bundle: Bundle, base_spec: CohortSpec, axes: dict, base_axes: dict,
              *, on_cell=None) -> BenchmarkMatrix:
    """Expand the grid and run every cell. ``on_cell(index, total, cell)`` is an
    optional progress callback (the rich.progress grid bar / NDJSON stream)."""
    computation = bundle.manifest.computation or "additive_bfv"
    cell_specs = expand_cells(axes, base_axes)
    cells: list[BenchmarkCell] = []
    total = len(cell_specs)
    for i, cs in enumerate(cell_specs):
        cell = run_cell(bundle, cs, base_spec, computation)
        cells.append(cell)
        if on_cell is not None:
            on_cell(i + 1, total, cell)

    config = {
        "application": bundle.application_id,
        "computation": computation,
        "seed": base_spec.seed,
        "maf_dist": base_spec.maf_dist,
        "missingness": base_spec.missingness,
        "coordinates": base_spec.coordinates,
        "axes": {"n": _ints(axes.get("n", base_axes["n"])),
                 "length": _ints(axes.get("length", base_axes["length"])),
                 "crypto": [_norm_crypto(c) for c in axes.get("crypto", base_axes["crypto"])],
                 "security": _ints(axes.get("security", base_axes["security"]))},
    }
    sim_hash = "simrun_" + sha256_hex(canonical_json(config))[:16]
    return BenchmarkMatrix(
        application=bundle.application_id, cells=cells, axes=config["axes"],
        config=config, coordinate_hash=_coordinate_hash(bundle), sim_hash=sim_hash,
    )


# ---------------------------------------------------------------------------
# Emitters — benchmark.{csv,md,tex}, plots/, methods/threat_model, provenance
# ---------------------------------------------------------------------------


def write_benchmark_csv(path: Path, cells: list[BenchmarkCell]) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(CSV_COLUMNS)
        for c in cells:
            w.writerow(c.row())


def write_benchmark_md(path: Path, cells: list[BenchmarkCell]) -> None:
    lines = ["| " + " | ".join(CSV_COLUMNS) + " |",
             "| " + " | ".join("---" for _ in CSV_COLUMNS) + " |"]
    for c in cells:
        lines.append("| " + " | ".join(c.row()) + " |")
    path.write_text("\n".join(lines) + "\n")


def _tex_escape(text: str) -> str:
    return text.replace("_", r"\_")


def write_benchmark_tex(path: Path, cells: list[BenchmarkCell]) -> None:
    # booktabs table, drop-in for the paper (docs/simulation_mode.md §3).
    align = "".join("r" if col not in ("application", "crypto", "feasibility") else "l"
                    for col in CSV_COLUMNS)
    out = [
        "% Generated by `blind bench` — do not edit by hand.",
        r"\begin{tabular}{" + align + "}",
        r"\toprule",
        " & ".join(_tex_escape(c) for c in CSV_COLUMNS) + r" \\",
        r"\midrule",
    ]
    for c in cells:
        out.append(" & ".join(_tex_escape(v) for v in c.row()) + r" \\")
    out += [r"\bottomrule", r"\end{tabular}"]
    path.write_text("\n".join(out) + "\n")


# --- plots (matplotlib is a lazy, optional dependency) --------------------

# Each plot ships beside its source CSV slice + the plotting script
# (docs/simulation_mode.md §3). (title, filename-stem, x-column, y-column).
_PLOT_SPECS = [
    ("Runtime vs cohort size N", "runtime_vs_n", "n", "runtime_ms"),
    ("Ciphertext size vs coordinate length L", "ct_size_vs_length",
     "length", "ct_bytes_per_contribution"),
    ("Marked-up cost vs cohort size N", "cost_vs_n", "n", "marked_up_cost_cents"),
    ("Max exactness error vs cohort size N", "exactness_vs_n", "n", "max_error"),
]

_PLOT_SCRIPT = '''\
#!/usr/bin/env python3
"""Regenerate the feasibility plots from their CSV slices (needs matplotlib).

    python plots/plot.py        # writes <stem>.svg beside each <stem>.csv

Shipped alongside the plots so a reviewer reproduces the figures from the data.
"""
import csv, sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib not installed. `pip install matplotlib` (or the `plots` extra).")

here = Path(__file__).resolve().parent
for slice_csv in sorted(here.glob("*.csv")):
    rows = list(csv.DictReader(slice_csv.open()))
    if not rows:
        continue
    cols = rows[0].keys()
    xcol, ycol = list(cols)[0], list(cols)[1]
    series = {}
    for r in rows:
        series.setdefault(r.get("series", "all"), []).append(
            (float(r[xcol]), float(r[ycol] or "nan")))
    fig, ax = plt.subplots()
    for label, pts in series.items():
        pts.sort()
        ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=str(label))
    ax.set_xlabel(xcol); ax.set_ylabel(ycol)
    ax.set_title(slice_csv.stem.replace("_", " "))
    if len(series) > 1:
        ax.legend()
    fig.tight_layout()
    fig.savefig(here / f"{slice_csv.stem}.svg")
    plt.close(fig)
'''


def _load_pyplot():
    """Lazy matplotlib loader — returns pyplot or None if the optional dep is
    absent (kept out of the trust-critical core deps). Patchable in tests."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except Exception:
        return None


def _plot_slice_rows(cells: list[BenchmarkCell], xcol: str, ycol: str) -> list[dict]:
    """Group cells into series keyed by (crypto, security) so a curve is drawn per
    approach; each row is {xcol, ycol, series}."""
    rows = []
    for c in cells:
        y = getattr(c, ycol)
        rows.append({xcol: _fmt(getattr(c, xcol)),
                     ycol: _fmt(y if y is not None else ""),
                     "series": f"{c.crypto}@{c.security}"})
    return rows


def write_plots(plots_dir: Path, cells: list[BenchmarkCell]) -> dict:
    """Write the plotting script + one CSV slice per figure (always), then render
    SVGs when matplotlib is available. Returns a summary describing what landed."""
    plots_dir.mkdir(parents=True, exist_ok=True)
    (plots_dir / "plot.py").write_text(_PLOT_SCRIPT)
    written_csv: list[str] = []
    for _title, stem, xcol, ycol in _PLOT_SPECS:
        slice_rows = _plot_slice_rows(cells, xcol, ycol)
        slice_path = plots_dir / f"{stem}.csv"
        with open(slice_path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow([xcol, ycol, "series"])
            for r in slice_rows:
                w.writerow([r[xcol], r[ycol], r["series"]])
        written_csv.append(f"{stem}.csv")

    plt = _load_pyplot()
    if plt is None:
        (plots_dir / "README.md").write_text(
            "# plots\n\nmatplotlib is not installed, so only the CSV slices and "
            "`plot.py` were written. Install the optional plotting dependency and "
            "re-render:\n\n    pip install 'blindmachine[plots]'\n    python plot.py\n")
        return {"rendered": False, "reason": "matplotlib-unavailable",
                "csv_slices": written_csv, "script": "plot.py"}

    rendered: list[str] = []
    for title, stem, xcol, ycol in _PLOT_SPECS:
        series: dict[str, list[tuple[float, float]]] = {}
        for c in cells:
            y = getattr(c, ycol)
            if y is None:
                continue
            series.setdefault(f"{c.crypto}@{c.security}", []).append(
                (float(getattr(c, xcol)), float(y)))
        if not any(series.values()):
            continue
        fig, ax = plt.subplots()
        for label, pts in series.items():
            pts.sort()
            ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=label)
        ax.set_xlabel(xcol)
        ax.set_ylabel(ycol)
        ax.set_title(title)
        if len(series) > 1:
            ax.legend()
        fig.tight_layout()
        fig.savefig(plots_dir / f"{stem}.svg")
        plt.close(fig)
        rendered.append(f"{stem}.svg")
    return {"rendered": True, "svgs": rendered, "csv_slices": written_csv, "script": "plot.py"}


def _methods_md(matrix: BenchmarkMatrix, bundle: Bundle) -> str:
    m = bundle.manifest
    axes = matrix.axes
    ok = [c for c in matrix.cells if c.feasibility == "ok"]
    max_runtime = max((c.runtime_ms for c in ok), default=0.0)
    max_ct = max((c.ct_bytes_per_contribution for c in ok), default=0.0)
    return (
        f"## Methods (generated)\n\n"
        f"We benchmark `{bundle.application_id}` (crypto hint `{m.crypto}`, computation "
        f"`{m.computation}`) with the encrypted-on-synthetic engine, sweeping the grid "
        f"N ∈ {axes['n']} × L ∈ {axes['length']} × crypto ∈ {axes['crypto']} × security "
        f"∈ {axes['security']} ({len(matrix.cells)} cells). Synthetic cohorts are drawn "
        f"under Hardy-Weinberg equilibrium (MAF spectrum `{matrix.config['maf_dist']}`, "
        f"missingness {matrix.config['missingness']}, seed {matrix.config['seed']}), "
        f"byte-shaped over the application's published coordinate definition. Per cell we "
        f"measure runtime (split encode/encrypt/compute/decrypt), ciphertext size "
        f"(bytes/contribution and total), peak worker RSS (RUSAGE_CHILDREN — a coarse "
        f"cumulative-max proxy under a shared process), and CPU-seconds, and assert "
        f"bit-exact agreement with the cleartext oracle within tolerance {m.tolerance} "
        f"(max observed error {matrix.max_observed_error}). Cost is priced through a "
        f"model mirroring the platform's per-CPU-second metering "
        f"(base {base_cents_per_cpu_second()}¢, markup ×{markup_multiplier()}): we "
        f"report both the raw compute cost (CPU-seconds × base, un-marked-up) and the "
        f"customer-facing marked-up cost. Peak measured runtime was {max_runtime:.1f} ms; "
        f"peak per-contribution ciphertext {max_ct:.0f} bytes.\n"
    )


# HomomorphicEncryption.org coeff-modulus caps: max Σ coeff_mod_bit_sizes at ring
# degree N for each classical-security level. achieved(N, Σ) = strictest level L
# whose cap Σ clears. Duplicated verbatim from the bundles' 00_keygen.py (SEAL only
# validates at tc128, so achieved security is NEVER read back from SEAL — this
# table is the single source of truth, mirrored in every keygen + its tests).
_HE_COEFF_MOD_CAPS = {
    8192: {256: 118, 192: 152, 128: 218},
    16384: {256: 237, 192: 305, 128: 438},
    32768: {256: 476, 192: 611, 128: 881},
}


def achieved_security(poly_modulus_degree: int, coeff_mod_bit_sizes) -> int | None:
    """Strictest HE security level the chain's Σbits certifies at this ring, or
    None if it overflows even the 128-bit ceiling / the ring is unknown."""
    caps = _HE_COEFF_MOD_CAPS.get(int(poly_modulus_degree))
    if not caps:
        return None
    total = sum(coeff_mod_bit_sizes)
    for level in (256, 192, 128):
        if total <= caps[level]:
            return level
    return None


def _security_params(bundle: Bundle, security_levels) -> dict | None:
    """Read literal SEAL constants from signed source without executing it."""
    candidates = [
        bundle.root / "local_project_owner.py",
        bundle.stage_file("keygen"),
    ]
    for source in candidates:
        if not source.is_file() or source.stat().st_size > 1024 * 1024:
            continue
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            values: dict[str, object] = {}
            for node in tree.body:
                name = None
                value = None
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    name = node.targets[0].id if isinstance(node.targets[0], ast.Name) else None
                    value = node.value
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    name = node.target.id
                    value = node.value
                if name in {"SECURITY", "DEFAULT_POLY_MODULUS_DEGREE", "DEFAULT_PLAIN_MODULUS"}:
                    values[name] = ast.literal_eval(value)
            table = values.get("SECURITY")
            poly = values.get("DEFAULT_POLY_MODULUS_DEGREE")
            plain = values.get("DEFAULT_PLAIN_MODULUS")
            if not isinstance(table, dict) or not isinstance(poly, int):
                continue
            out: dict = {}
            for level in sorted({int(item) for item in security_levels}):
                chain = table.get(level)
                if not isinstance(chain, (list, tuple)) or not all(
                    isinstance(bit, int) for bit in chain
                ):
                    continue
                out[str(level)] = {
                    "poly_modulus_degree": poly,
                    "plain_modulus": plain,
                    "coeff_mod_bit_sizes": list(chain),
                    "coeff_mod_bits_total": sum(chain),
                    "achieved_security": achieved_security(poly, chain),
                }
            return out or None
        except (OSError, SyntaxError, TypeError, ValueError):
            continue
    return None


def write_matrix_dir(matrix: BenchmarkMatrix, out_root: Path, bundle: Bundle,
                     base_spec: CohortSpec, emit: list[str]) -> Path:
    """Write ONE aggregated non-authoritative SimulationRun directory for the sweep
    (docs/simulation_mode.md §6): config, equivalence, the benchmark table in all
    three formats (always), plots (if requested), methods/threat_model (if
    requested), and a provenance header binding git commit + every artifact hash."""
    from blind.simulate import _threat_model_md

    d = out_root / matrix.sim_hash
    d.mkdir(parents=True, exist_ok=True)
    matrix.directory = d

    (d / "config.yml").write_text(yaml.safe_dump(matrix.config, sort_keys=True))
    (d / "equivalence.json").write_text(_dumps({
        "passed": matrix.passed,
        "max_observed_error": matrix.max_observed_error,
        "cells": [{"n": c.n, "length": c.length, "crypto": c.crypto,
                   "security": c.security, "max_observed_error": c.max_error,
                   "exact": c.exact, "feasibility": c.feasibility}
                  for c in matrix.cells],
    }))

    emitted = ["config.yml", "equivalence.json"]
    # The aggregated benchmark table is the whole point of a sweep — always emit.
    write_benchmark_csv(d / "benchmark.csv", matrix.cells)
    write_benchmark_md(d / "benchmark.md", matrix.cells)
    write_benchmark_tex(d / "benchmark.tex", matrix.cells)
    emitted += ["benchmark.csv", "benchmark.md", "benchmark.tex"]

    plots_summary = None
    if "plots" in emit:
        plots_summary = write_plots(d / "plots", matrix.cells)
    if "methods" in emit:
        (d / "methods.md").write_text(_methods_md(matrix, bundle))
        emitted.append("methods.md")
    if "threat_model" in emit:
        (d / "threat_model.md").write_text(_threat_model_md())
        emitted.append("threat_model.md")

    provenance = {
        "application": bundle.application_id,
        "coordinate_hash": matrix.coordinate_hash,
        "seed": base_spec.seed,
        "cli_version": __version__,
        "git_commit": git_commit(),
        "axes": matrix.axes,
        "cell_count": len(matrix.cells),
        "equivalence_passed": matrix.passed,
        "cost_model": {"base_cents_per_cpu_second": base_cents_per_cpu_second(),
                       "markup_multiplier": markup_multiplier(),
                       "estimated_cpu_seconds_per_contribution":
                           estimated_cpu_seconds_per_contribution()},
    }
    # Machine + build identity so a dev-laptop run is distinguishable from a
    # pinned-VM run by the stamped metadata alone (CPU/RAM/OS/tenseal/git/date).
    env = machine_environment(bundle_dir=bundle.root, git_cwd=str(bundle.root))
    env["seed"] = base_spec.seed
    provenance["environment"] = env
    # The resolved SEAL params per swept security level (retires the "192/256 not
    # re-parametrized" caveat — the security axis is now genuinely honored).
    sec_params = _security_params(bundle, matrix.axes.get("security", []))
    if sec_params:
        provenance["security_params"] = sec_params
    # Bind every artifact's SHA-256 (plot slices included) so the paper cites hashes.
    plot_names = []
    if plots_summary is not None:
        plot_names = [f"plots/{n}" for n in plots_summary.get("csv_slices", [])]
        plot_names += [f"plots/{n}" for n in plots_summary.get("svgs", [])]
    provenance["artifacts"] = artifact_hashes(d, emitted + plot_names)
    if plots_summary is not None:
        provenance["plots"] = plots_summary
    (d / "provenance.json").write_text(_dumps(provenance))
    return d


def _dumps(obj) -> str:
    import json

    return json.dumps(obj, indent=2, default=str)


# ---------------------------------------------------------------------------
# Base axes from the top-level flags (merged with, and overridden by, --sweep)
# ---------------------------------------------------------------------------


def replay(sim_dir: Path, bundle: Bundle, emit: list[str], *, out_root: Path) -> dict:
    """Reproduce a cited simulation from its stored ``config.yml`` (`--replay
    <sim-run-hash>`, docs/simulation_mode.md §3). Re-runs the exact grid and
    asserts the recomputed sim-run hash matches — a bit-exact reproduction of the
    deterministic outputs (BFV integer results + equivalence verdicts). Hardware-
    dependent performance numbers reproduce within a variance band, not byte-for-byte."""
    from blind.simulate import CohortSpec, simulate

    sim_dir = Path(sim_dir)
    cfg_path = sim_dir / "config.yml"
    if not cfg_path.exists():
        raise UsageError(f"No simulation run to replay at {sim_dir}")
    cfg = yaml.safe_load(cfg_path.read_text()) or {}
    original_hash = sim_dir.name

    if "axes" in cfg:  # a sweep
        base_spec = CohortSpec(
            n=0, length=REFERENCE_LENGTH, seed=int(cfg.get("seed", 42)),
            maf_dist=cfg.get("maf_dist", "beta"),
            missingness=float(cfg.get("missingness", 0.0)),
            coordinates=cfg.get("coordinates"),
        )
        axes = {k: [str(x) for x in v] for k, v in cfg["axes"].items()}
        matrix = run_sweep(bundle, base_spec, axes, axes)
        matrix.directory = write_matrix_dir(matrix, out_root, bundle, base_spec, emit)
        return {
            "object": "simulation_run", "authoritative": False, "mode": "replay",
            "replayed": original_hash, "sim_run_hash": matrix.sim_hash,
            "reproduced": matrix.sim_hash == original_hash,
            "equivalence": {"passed": matrix.passed,
                            "max_observed_error": matrix.max_observed_error},
            "directory": str(matrix.directory),
        }

    cohort = cfg.get("cohort", {})
    spec = CohortSpec(
        n=int(cohort.get("n", 20)), length=int(cohort.get("length", REFERENCE_LENGTH)),
        seed=int(cohort.get("seed", 42)), maf_dist=cohort.get("maf_dist", "beta"),
        missingness=float(cohort.get("missingness", 0.0)),
        security=int(cohort.get("security", 128)), crypto=cohort.get("crypto"),
        coordinates=cohort.get("coordinates"),
    )
    run = simulate(bundle, spec, encrypted="encrypted" in (cfg.get("engines") or []),
                   emit=emit, out_root=out_root)
    return {
        "object": "simulation_run", "authoritative": False, "mode": "replay",
        "replayed": original_hash, "sim_run_hash": run.sim_hash,
        "reproduced": run.sim_hash == original_hash,
        "equivalence": run.equivalence.as_dict(),
        "directory": str(run.directory) if run.directory else None,
    }


def default_crypto_for(bundle: Bundle) -> str:
    """The application's declared crypto approach (COMMANDS.md `--crypto` default):
    a multiplication-supporting computation defaults to `bfv-mul`, else `bfv-add`."""
    computation = (bundle.manifest.computation or "").lower()
    return "bfv-mul" if computation.startswith("multiplicative") else "bfv-add"


def base_axes_from_flags(*, n: str, length: int, crypto: str,
                         security: str) -> dict:
    return {
        "n": [x for x in str(n).split(",") if x.strip()],
        "length": [length],
        "crypto": [crypto],
        "security": [x for x in str(security).split(",") if x.strip()] or ["128"],
    }
