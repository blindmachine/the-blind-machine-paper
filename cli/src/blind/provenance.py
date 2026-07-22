"""Machine + build provenance for reproducible benchmark runs.

The benchmark harness stamps *what produced a number* so a paper reviewer can
tell a dev-laptop run from a pinned-VM run at a glance: CPU model, physical /
logical core count, total RAM, OS, the CLI's Python version, the crypto library
(TenSEAL) version actually governing the ciphertexts, the seed, and the git
commit (+ dirty flag).

Two rules shape this module:

  * **Fail-open.** Every probe is best-effort and returns ``None`` on any error
    (missing ``sysctl``, no ``/proc``, no git checkout). Stamping provenance must
    never break a benchmark run.
  * **No wall-clock reads in the harness.** The runtime forbids ``Date.now``-style
    reads for determinism, so ``run_date`` is the ONE field that cannot be
    self-generated: it is PASSED IN via the ``BLIND_BENCH_RUN_DATE`` env var
    (ISO-8601). The standalone runner (``docs/paper/artifacts/run_benchmarks.py``)
    sets it once from ``datetime`` before invoking the harness; the harness only
    ever *reads* it here.

``tenseal_version`` is deliberately queried from the **sealed bundle env**
(``uv --project env run --frozen``), not the CLI interpreter — the trust-critical
CLI venv has no TenSEAL, so importing it here would always be ``None``. The number
that governs the crypto lives in each bundle's ``env/``.
"""

from __future__ import annotations

import os
import platform
import subprocess  # nosec B404
from pathlib import Path

RUN_DATE_ENV = "BLIND_BENCH_RUN_DATE"


def _run(cmd: list[str], *, cwd: str | None = None, timeout: int = 10) -> str | None:
    try:
        # argv comes only from the fixed, read-only provenance probes below.
        out = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    value = out.stdout.strip()
    return value or None


def cpu_model() -> str | None:
    """Human-readable CPU model. ``platform.processor()`` alone returns only
    ``"arm"`` on Apple silicon, so we prefer the OS-native probe."""
    if os.sys.platform == "darwin":
        model = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if model:
            return model
    elif os.sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            return platform.processor() or platform.machine() or None
    return platform.processor() or platform.machine() or None


def logical_cores() -> int | None:
    return os.cpu_count()


def physical_cores() -> int | None:
    if os.sys.platform == "darwin":
        value = _run(["sysctl", "-n", "hw.physicalcpu"])
    elif os.sys.platform.startswith("linux"):
        value = _run(["nproc", "--all"])
    else:
        value = None
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def ram_bytes() -> int | None:
    if os.sys.platform == "darwin":
        value = _run(["sysctl", "-n", "hw.memsize"])
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None
    try:  # POSIX (Linux and most Unixes)
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return None


def git_commit(cwd: str | None = None) -> str | None:
    return _run(["git", "rev-parse", "HEAD"], cwd=cwd, timeout=5)


def git_dirty(cwd: str | None = None) -> bool | None:
    out = _run(["git", "status", "--porcelain"], cwd=cwd, timeout=5)
    if out is None:
        # Distinguish "clean" (empty string, which _run coerces to None) from
        # "not a git checkout" by re-probing the top-level.
        top = _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=cwd, timeout=5)
        if top is None:
            return None
        return False
    return bool(out.strip())


def run_date() -> str | None:
    """The externally supplied ISO-8601 run date (``BLIND_BENCH_RUN_DATE``).

    Returns ``None`` when unset — the harness never invents a timestamp."""
    value = os.environ.get(RUN_DATE_ENV)
    return value.strip() if value and value.strip() else None


def sealed_tenseal_version(bundle_dir: str | Path | None, *, timeout: int = 60) -> str | None:
    """TenSEAL version from a bundle's SEALED env (``uv --project env run
    --frozen``), not the CLI interpreter. Best-effort: ``None`` if uv/the venv is
    absent (the same fall-through ``blind bench`` uses for the stage runner)."""
    if bundle_dir is None:
        return None
    bundle_dir = Path(bundle_dir)
    if not (bundle_dir / "env" / ".venv").exists():
        return None
    return _run(
        ["uv", "--project", "env", "run", "--frozen", "--no-sync", "python", "-c",
         "import tenseal, sys; sys.stdout.write(tenseal.__version__)"],
        cwd=str(bundle_dir), timeout=timeout,
    )


def machine_environment(
    *, bundle_dir: str | Path | None = None, git_cwd: str | None = None,
    include_tenseal: bool = True,
) -> dict:
    """The reproducibility block stamped into ``provenance.json`` and the aggregate
    benchmark JSON. Every field is best-effort; ``run_date`` is read from the
    environment (passed in — never generated here)."""
    env = {
        "cpu_model": cpu_model(),
        "cpu_cores_physical": physical_cores(),
        "cpu_cores_logical": logical_cores(),
        "ram_bytes": ram_bytes(),
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "tenseal_version": (
            sealed_tenseal_version(bundle_dir) if include_tenseal else None
        ),
        "seed": None,  # filled in by the caller from the sweep's seed
        "git_commit": git_commit(cwd=git_cwd),
        "git_dirty": git_dirty(cwd=git_cwd),
        "run_date": run_date(),
    }
    return env
