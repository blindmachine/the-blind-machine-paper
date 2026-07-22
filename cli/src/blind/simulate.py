"""Simulation mode — the non-authoritative twin of the encrypted trust loop.

Implements the shared-evaluator harness from docs/simulation_mode.md:

  * a ``PlaintextEvaluator`` implementing the same ``zero/add/scalar_mul/mul``
    interface the real crypto evaluators expose, so the compute logic is written
    once and only the evaluator is swapped (the oracle can't drift);
  * a seeded, coordinate-driven synthetic-cohort generator (Hardy-Weinberg
    sampler) — a reviewer regenerates the exact cohort from ``(seed, params)``;
  * two engines: the **cleartext oracle** (implemented here, keyless) and the
    **encrypted-on-synthetic** engine (invokes the SAME bundle stages a real job
    runs), asserted equal within the application's published tolerance.

Every run is written under ``~/.blind/simulations/<sim-run-hash>/`` as a
``SimulationRun`` — NEVER a ``ComputationCertificate``: no cohort commitment,
no min-N gate, nothing uploaded.
"""

from __future__ import annotations

import json
import random
import resource
import shutil
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from blind.errors import UsageError
from blind.hashing import canonical_json, sha256_hex
from blind.runtime.bundle import Bundle
from blind.version import __version__

# ---------------------------------------------------------------------------
# The shared evaluator interface (compute written once, evaluator swapped)
# ---------------------------------------------------------------------------


class Evaluator:
    """The abstract op interface an application's compute() is written against."""

    def zero(self, length: int):
        raise NotImplementedError

    def add(self, a, b):
        raise NotImplementedError

    def scalar_mul(self, a, k):
        raise NotImplementedError

    def mul(self, a, b):
        raise NotImplementedError


class PlaintextEvaluator(Evaluator):
    """Cleartext oracle evaluator — operates on plain integer vectors."""

    def zero(self, length: int):
        return [0] * length

    def add(self, a, b):
        return [x + y for x, y in zip(a, b)]

    def scalar_mul(self, a, k):
        return [x * k for x in a]

    def mul(self, a, b):
        return [x * y for x, y in zip(a, b)]


def compute(inputs: list[list[int]], E: Evaluator, computation: str = "additive_bfv"):
    """The reference computation, written once against the evaluator interface.

    This mirrors the shape of the bundle's ``30_compute_encrypted.py`` so the
    cleartext oracle and the encrypted engine run the *same* algorithm. Additive
    applications coordinate-wise sum; the multiplicative arm squares first.
    """
    if not inputs:
        return []
    length = len(inputs[0])
    acc = E.zero(length)
    for vec in inputs:
        term = E.mul(vec, vec) if computation.startswith("multiplicative") else vec
        acc = E.add(acc, term)
    return acc


# ---------------------------------------------------------------------------
# Seeded synthetic-cohort generator (Hardy-Weinberg)
# ---------------------------------------------------------------------------


@dataclass
class CohortSpec:
    n: int
    length: int
    seed: int = 42
    maf_dist: str = "beta"
    missingness: float = 0.0
    # Extra knobs — recorded in provenance and folded into the RNG so the exact
    # cohort is reproducible from (seed, params). `security` is the crypto
    # security-level axis (128/192/256); `crypto` selects the crypto approach for
    # the cost model; `coordinates`/`phenotype`/`bucketing` are generator knobs
    # (docs/simulation_mode.md §2). None-valued extras are omitted from as_dict()
    # so a plain (n, length, seed) run keeps its legacy config hash.
    security: int = 128
    crypto: str | None = None
    coordinates: str | None = None
    phenotype: str | None = None
    bucketing: str | None = None

    def as_dict(self) -> dict:
        d = {
            "n": self.n,
            "length": self.length,
            "seed": self.seed,
            "maf_dist": self.maf_dist,
            "missingness": self.missingness,
        }
        if self.security != 128:
            d["security"] = self.security
        for key in ("crypto", "coordinates", "phenotype", "bucketing"):
            val = getattr(self, key)
            if val is not None:
                d[key] = val
        return d


def _coordinate_salt(spec: CohortSpec) -> str:
    """A deterministic salt folded into the RNG so the generator is *coordinate-
    driven* (docs/simulation_mode.md §2): a different coordinate definition /
    phenotype / bucketing yields a different — but reproducible — cohort, while
    (seed, params) alone still regenerates the exact vectors."""
    parts = [str(spec.coordinates or ""), str(spec.phenotype or ""), str(spec.bucketing or "")]
    salt = "|".join(parts)
    return "" if salt == "||" else salt


def generate_cohort(spec: CohortSpec) -> list[list[int]]:
    """Draw ``n`` genotype vectors of length ``length`` from HWE proportions.

    For coordinate j with alt-allele frequency p_j:
      P(g=0)=(1-p)^2  P(g=1)=2p(1-p)  P(g=2)=p^2
    Fully reproducible from ``(seed, params)``.
    """
    salt = _coordinate_salt(spec)
    seed = spec.seed if not salt else spec.seed ^ (int(sha256_hex(salt.encode()), 16) & 0xFFFFFFFF)
    # Reproducibility is required here; these values are synthetic, not secrets.
    rng = random.Random(seed)  # nosec B311
    # Per-coordinate allele frequencies (Beta-ish spectrum → both common + rare).
    if spec.maf_dist == "beta":
        freqs = [rng.betavariate(0.5, 2.0) for _ in range(spec.length)]
    else:
        freqs = [rng.uniform(0.01, 0.5) for _ in range(spec.length)]

    cohort: list[list[int]] = []
    for _ in range(spec.n):
        vec: list[int] = []
        for p in freqs:
            if spec.missingness and rng.random() < spec.missingness:
                vec.append(0)  # no-call encodes as 0 (stresses the encode-as-0 path)
                continue
            r = rng.random()
            p0, p1 = (1 - p) ** 2, 2 * p * (1 - p)
            g = 0 if r < p0 else (1 if r < p0 + p1 else 2)
            vec.append(g)
        cohort.append(vec)
    return cohort


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------


@dataclass
class Equivalence:
    passed: bool
    max_error: float
    tolerance: float
    oracle_result: list
    encrypted_result: list | None = None

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "max_observed_error": self.max_error,
            "tolerance": self.tolerance,
            "oracle_result": self.oracle_result,
            "encrypted_result": self.encrypted_result,
        }


def run_cleartext_oracle(cohort: list[list[int]], computation: str) -> list[int]:
    """The keyless correctness oracle — encode is identity for synthetic integer
    vectors; compute uses the PlaintextEvaluator; decode is identity."""
    return compute(cohort, PlaintextEvaluator(), computation)


@dataclass
class EngineMetrics:
    """The feasibility numbers the encrypted-on-synthetic engine measures per run
    (docs/simulation_mode.md §2 "Measured per cell"). Runtime is split by stage;
    ciphertext size is bytes/contribution + total; CPU-seconds and peak RSS come
    from ``RUSAGE_CHILDREN`` over the stage subprocesses (the same numbered stage
    scripts a real job runs)."""

    n: int
    length: int
    keygen_ms: float = 0.0
    encode_ms: float = 0.0
    encrypt_ms: float = 0.0
    compute_ms: float = 0.0
    decrypt_ms: float = 0.0
    decode_ms: float = 0.0
    total_ms: float = 0.0
    ct_bytes_total: int = 0
    ct_bytes_per_contribution: float = 0.0
    peak_rss_bytes: int = 0
    cpu_seconds: float = 0.0

    def runtime_split(self) -> dict:
        return {"encode": self.encode_ms, "encrypt": self.encrypt_ms,
                "compute": self.compute_ms, "decrypt": self.decrypt_ms}

    def as_dict(self) -> dict:
        return {
            "n": self.n, "length": self.length,
            "runtime_ms": {"keygen": self.keygen_ms, "encode": self.encode_ms,
                           "encrypt": self.encrypt_ms, "compute": self.compute_ms,
                           "decrypt": self.decrypt_ms, "decode": self.decode_ms,
                           "total": self.total_ms},
            "ct_bytes_total": self.ct_bytes_total,
            "ct_bytes_per_contribution": self.ct_bytes_per_contribution,
            "peak_rss_bytes": self.peak_rss_bytes,
            "cpu_seconds": self.cpu_seconds,
        }


@dataclass
class EngineRun:
    result: list
    metrics: EngineMetrics


def _rusage_children() -> tuple[float, int]:
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime, r.ru_maxrss


def _maxrss_bytes(maxrss: int) -> int:
    # Linux reports ru_maxrss in KiB; macOS/BSD in bytes.
    return int(maxrss) * 1024 if sys.platform.startswith("linux") else int(maxrss)


def measure_encrypted_engine(bundle: Bundle, cohort: list[list[int]],
                             *, adapter=None, security: int = 128) -> EngineRun:
    """Run the SAME numbered bundle stages a real job runs (keygen → encode →
    encrypt → compute → decrypt → decode) on ephemeral keys thrown away with the
    run, while measuring split runtime, ciphertext size, CPU-seconds, and peak RSS.
    Returns the decoded aggregate plus its ``EngineMetrics``.

    ``security`` (128/192/256) is threaded verbatim into stage 00 — each bundle's
    ``00_keygen.py`` accepts ``--security`` and selects the real SEAL
    coefficient-modulus chain for that HE level (its ``SECURITY`` table). This is
    what makes the benchmark's ``security`` column truthful instead of decorative:
    a 192/256 cell is measured on a genuinely re-parametrized context, not the
    128-bit one (retires blocker B1).

    Each stage is invoked through its argparse CLI — the identical interface the
    shipped bundles expose and the hosted worker drives for stage 30 (compute) —
    so ``blind bench`` measures the REAL crypto pipeline. The per-application
    ``adapter`` (blind.runtime.application_io) shapes each contributor's raw file,
    selects single- vs two-ciphertext encryption, gates the compute input sort
    (order-significant applications pass ``sort=False``), and names the decode key to
    read the comparable aggregate from."""
    import tempfile

    from blind.runtime.compute import (
        run_compute_stage,
        run_decode_stage,
        run_decrypt_stage,
        run_encode_stage,
        run_encrypt_stage,
        run_keygen_stage,
    )
    from blind.runtime.application_io import application_io_for

    adapter = adapter or application_io_for(bundle)
    work = Path(tempfile.mkdtemp(prefix="blind-sim-"))
    length = len(cohort[0]) if cohort else 0
    m = EngineMetrics(n=len(cohort), length=length)
    cpu0, _ = _rusage_children()
    t_run0 = time.perf_counter()

    def _timed(fn):
        t0 = time.perf_counter()
        out = fn()
        return out, (time.perf_counter() - t0) * 1000.0

    (public_ctx, secret_ctx), m.keygen_ms = _timed(
        lambda: run_keygen_stage(bundle, work / "keys",
                                 extra_argv=("--security", str(int(security)))))

    ciphertexts: list[Path] = []
    for i, vec in enumerate(cohort):
        raw = work / f"raw_{i}.json"
        raw.write_text(json.dumps(adapter.raw_for(vec)))
        enc_path = work / f"enc_{i}.json"
        _, enc_ms = _timed(lambda raw=raw, enc_path=enc_path: run_encode_stage(
            bundle, raw, length, enc_path, extra_argv=adapter.encode_argv))
        m.encode_ms += enc_ms
        if adapter.encrypt_outputs == 2:
            out_paths: list[Path] = [work / f"ct_{i}_g.bin", work / f"ct_{i}_y.bin"]
        else:
            out_paths = [work / f"ct_{i}.bin"]
        cts, ct_ms = _timed(lambda enc_path=enc_path, out_paths=out_paths:
                            run_encrypt_stage(bundle, public_ctx, enc_path, out_paths))
        m.encrypt_ms += ct_ms
        for p in cts:
            if p.exists():
                m.ct_bytes_total += p.stat().st_size
            ciphertexts.append(p)

    comp, m.compute_ms = _timed(lambda: run_compute_stage(
        bundle, public_ctx, ciphertexts, work / "result.bin",
        sort=adapter.compute_sorted))
    plain, m.decrypt_ms = _timed(lambda: run_decrypt_stage(
        bundle, secret_ctx, comp.artifact, work / "result.plain"))
    decoded, m.decode_ms = _timed(lambda: run_decode_stage(
        bundle, plain, length, work / "result.json"))

    m.total_ms = (time.perf_counter() - t_run0) * 1000.0
    cpu1, rss1 = _rusage_children()
    m.cpu_seconds = max(cpu1 - cpu0, 0.0)
    m.peak_rss_bytes = _maxrss_bytes(rss1)
    if m.n:
        m.ct_bytes_per_contribution = m.ct_bytes_total / m.n

    data = json.loads(Path(decoded).read_text())
    return EngineRun(result=adapter.extract_result(data), metrics=m)


def run_encrypted_engine(bundle: Bundle, cohort: list[list[int]]) -> list[int]:
    """The encrypted-on-synthetic engine — runs the SAME numbered bundle stages a
    real job runs (keygen → encode → encrypt → compute → decrypt → decode), on
    ephemeral keys thrown away with the run. Returns the decoded aggregate."""
    return measure_encrypted_engine(bundle, cohort).result


def assert_equivalence(
    oracle: list, encrypted: list | None, tolerance: float
) -> Equivalence:
    if encrypted is None:
        return Equivalence(True, 0.0, tolerance, oracle, None)
    max_err = 0.0
    for a, b in zip(oracle, encrypted):
        max_err = max(max_err, abs(a - b))
    passed = max_err <= tolerance
    return Equivalence(passed, max_err, tolerance, oracle, encrypted)


# ---------------------------------------------------------------------------
# Top-level run → a SimulationRun directory
# ---------------------------------------------------------------------------


@dataclass
class SimulationRun:
    sim_hash: str
    application_id: str
    config: dict
    equivalence: Equivalence
    provenance: dict
    directory: Path = field(default=None)  # type: ignore

    def as_dict(self) -> dict:
        return {
            "object": "simulation_run",
            "authoritative": False,
            "sim_run_hash": self.sim_hash,
            "application": self.application_id,
            "config": self.config,
            "equivalence": self.equivalence.as_dict(),
            "provenance": self.provenance,
            "directory": str(self.directory) if self.directory else None,
        }


def simulate(
    bundle: Bundle,
    spec: CohortSpec,
    *,
    encrypted: bool = False,
    emit: list[str] | None = None,
    out_root: Path | None = None,
) -> SimulationRun:
    """Run the oracle (always) and, when requested, the encrypted engine; assert
    equivalence; write the non-authoritative SimulationRun directory."""
    computation = bundle.manifest.computation or "additive_bfv"
    cohort = generate_cohort(spec)

    oracle = run_cleartext_oracle(cohort, computation)
    encrypted_result = run_encrypted_engine(bundle, cohort) if encrypted else None
    equivalence = assert_equivalence(oracle, encrypted_result, bundle.manifest.tolerance)

    config = {
        "application": bundle.application_id,
        "computation": computation,
        "cohort": spec.as_dict(),
        "engines": ["oracle"] + (["encrypted"] if encrypted else []),
    }
    sim_hash = "simrun_" + sha256_hex(canonical_json(config))[:16]

    provenance = {
        "application": bundle.application_id,
        "coordinate_hash": _coordinate_hash(bundle),
        "seed": spec.seed,
        "cli_version": __version__,
        "git_commit": git_commit(),
        "cohort_params": spec.as_dict(),
        "equivalence_passed": equivalence.passed,
    }

    run = SimulationRun(
        sim_hash=sim_hash,
        application_id=bundle.application_id,
        config=config,
        equivalence=equivalence,
        provenance=provenance,
    )

    if out_root is not None:
        run.directory = _write_run_dir(run, out_root, bundle, spec, emit or [])
    return run


def _coordinate_hash(bundle: Bundle) -> str:
    return "sha256:" + sha256_hex(canonical_json(bundle.manifest.coordinates or {}))


def git_commit() -> str | None:
    """The simulator's git commit for the provenance header (docs/simulation_mode.md
    §3). Read-only; degrades to None outside a git checkout."""
    git = shutil.which("git")
    if not git:
        return None
    try:
        out = subprocess.run(  # nosec B603
            [git, "rev-parse", "HEAD"],
            cwd=str(Path(__file__).resolve().parent),
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def artifact_hashes(directory: Path, names: list[str]) -> dict:
    """`sha256:<hex>` of each emitted artifact that exists — the provenance binding
    a paper cites (docs/simulation_mode.md §3 "SHA-256 of the produced table/plot data")."""
    out: dict = {}
    for name in names:
        p = directory / name
        if p.is_file():
            out[name] = "sha256:" + sha256_hex(p.read_bytes())
    return out


def _write_run_dir(
    run: SimulationRun, out_root: Path, bundle: Bundle, spec: CohortSpec, emit: list[str]
) -> Path:
    d = out_root / run.sim_hash
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.yml").write_text(yaml.safe_dump(run.config, sort_keys=True))
    (d / "equivalence.json").write_text(json.dumps(run.equivalence.as_dict(), indent=2))
    emitted = ["config.yml", "equivalence.json"]
    if "methods" in emit:
        (d / "methods.md").write_text(_methods_md(bundle, spec, run))
        emitted.append("methods.md")
    if "threat_model" in emit:
        (d / "threat_model.md").write_text(_threat_model_md())
        emitted.append("threat_model.md")
    # Provenance is written last so it can bind the SHA-256 of every emitted file.
    run.provenance["artifacts"] = artifact_hashes(d, emitted)
    (d / "provenance.json").write_text(json.dumps(run.provenance, indent=2))
    return d


def _methods_md(bundle: Bundle, spec: CohortSpec, run: SimulationRun) -> str:
    m = bundle.manifest
    return (
        f"## Methods (generated)\n\n"
        f"We evaluate `{bundle.application_id}` (crypto hint `{m.crypto}`, "
        f"computation `{m.computation}`). Synthetic cohorts of N={spec.n} "
        f"contributors over L={spec.length} coordinates were drawn under "
        f"Hardy-Weinberg equilibrium (MAF spectrum `{spec.maf_dist}`, "
        f"missingness {spec.missingness}, seed {spec.seed}). The cleartext oracle "
        f"(`encode → compute(PlaintextEvaluator) → decode`) and the encrypted "
        f"engine run the identical compute over swapped evaluators; agreement is "
        f"asserted within tolerance {m.tolerance} "
        f"(max observed error {run.equivalence.max_error}).\n"
    )


def _threat_model_md() -> str:
    return (
        "## Threat model / limitations (generated)\n\n"
        "FHE hides contributor inputs from the server. It does NOT hide the "
        "released aggregate, metadata, or protect against a malicious keyholder. "
        "The append-1 sentinel is an integrity check, not a MAC. "
        "Cohort freeze + min-N + run-cap mitigate but do not fully close K-vs-K+1 "
        "differencing; overlapping/Sybil differencing across separately frozen "
        "cohorts needs DP + cross-job query budgets (v2).\n"
    )


# ---------------------------------------------------------------------------
# Accepted-but-previously-unimplemented flags (COMMANDS.md §simulations)
# ---------------------------------------------------------------------------


def load_local_vectors(raw_dir: Path) -> list[list[int]]:
    """Read the researcher's own LOCAL raw vectors (`--from <dir>`): one JSON file
    per contribution, each ``{"vector": [...]}`` (or a bare list). Never uploaded."""
    raw_dir = Path(raw_dir)
    if not raw_dir.is_dir():
        raise UsageError(f"--from directory not found: {raw_dir}")
    vectors: list[list[int]] = []
    for path in sorted(raw_dir.glob("*.json")):
        data = json.loads(path.read_text())
        vec = data.get("vector", data) if isinstance(data, dict) else data
        vectors.append([int(x) for x in vec])
    if not vectors:
        raise UsageError(f"--from directory has no *.json vectors: {raw_dir}")
    return vectors


def run_local_oracle(bundle: Bundle, raw_dir: Path, *, encrypted: bool = False) -> dict:
    """Run the oracle (and optionally the encrypted engine) on LOCAL raw vectors,
    never synthetic and never uploaded (COMMANDS.md `--from`)."""
    computation = bundle.manifest.computation or "additive_bfv"
    cohort = load_local_vectors(raw_dir)
    oracle = run_cleartext_oracle(cohort, computation)
    encrypted_result = run_encrypted_engine(bundle, cohort) if encrypted else None
    eq = assert_equivalence(oracle, encrypted_result, bundle.manifest.tolerance)
    return {
        "object": "simulation_run", "authoritative": False, "mode": "from-local",
        "application": bundle.application_id, "source": str(raw_dir), "n": len(cohort),
        "oracle_result": oracle,
        "equivalence": eq.as_dict(),
    }


def assert_against_result(bundle: Bundle, raw_dir: Path, result_path: Path) -> dict:
    """`--from <dir> --against-result <file>`: assert the cleartext oracle over the
    LOCAL raw vectors agrees with an already-produced (decoded) encrypted result.
    A bare result-hash with no local file cannot be resolved offline."""
    result_path = Path(result_path)
    if not result_path.is_file():
        raise UsageError(
            f"--against-result must point at a local decoded result file "
            f"(offline); got {result_path!r}")
    computation = bundle.manifest.computation or "additive_bfv"
    cohort = load_local_vectors(raw_dir)
    oracle = run_cleartext_oracle(cohort, computation)
    data = json.loads(result_path.read_text())
    produced = data.get("vector", data.get("result", data)) if isinstance(data, dict) else data
    eq = assert_equivalence(oracle, [int(x) for x in produced], bundle.manifest.tolerance)
    return {
        "object": "simulation_run", "authoritative": False, "mode": "against-result",
        "application": bundle.application_id, "source": str(raw_dir),
        "against_result": str(result_path), "equivalence": eq.as_dict(),
    }


def differencing_demo(bundle: Bundle, *, n: int = 50, seed: int = 7, length: int = 16) -> dict:
    """The K-vs-K+1 differencing attack (`--attack differencing`,
    docs/simulation_mode.md §5): on an *unfrozen* cohort, A_{K+1} − A_K exactly
    recovers one target's genotype vector. Shows the leak, then names the fix
    (cohort freeze + min-N + run-cap) and — honestly — what it does NOT close.

    This is a property of the *statistic*, so the keyless oracle is enough."""
    computation = bundle.manifest.computation or "additive_bfv"
    full = generate_cohort(CohortSpec(n=n + 1, length=length, seed=seed))
    cohort_k = full[:n]
    target = full[n]
    a_k = run_cleartext_oracle(cohort_k, computation)
    a_k1 = run_cleartext_oracle(full, computation)
    recovered = [b - a for a, b in zip(a_k, a_k1)]
    exact = recovered == (target if not computation.startswith("multiplicative")
                          else [x * x for x in target])
    return {
        "object": "attack_demo", "authoritative": False, "attack": "differencing",
        "application": bundle.application_id, "k": n,
        "target_vector": target, "recovered_vector": recovered,
        "recovered_exactly": exact,
        "leak": "A_{K+1} - A_K recovers one contributor's exact vector on an "
                "unfrozen cohort.",
        "fix": ["cohort freeze pins membership → K and K+1 are different committed "
                "cohorts, not two runs of one project",
                "min-N refuses runs below the floor (cannot shrink toward N=1)",
                "run-cap blocks the run-twice-with-a-one-person-delta pattern"],
        "not_closed": "overlapping / Sybil differencing across separately frozen "
                      "cohorts (needs DP + cross-job query budgets, v2).",
    }
