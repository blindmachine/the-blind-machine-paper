"""Run the SERVER compute stage (``30_compute_encrypted.py``) locally.

THE SERVER COMPUTE CONVENTION (argparse — what the hosted worker drives):

    uv --project env run --frozen --no-sync \
      python 30_compute_encrypted.py \
        --context <public_context> --inputs <ct...> --out <result>

This module is the exact local mirror of that invocation, so the CLI's local
simulate/compute path recomputes the same bytes the server produced:

  * inputs are sorted ascending by their ``sha256:`` digest — the identical
    canonical order the server stages ciphertexts in (the same sort the cohort
    commitment uses), so deterministic applications reproduce bit-identically;
  * the stage runs inside the digest-pinned, network-disabled container sandbox;
    there is no implicit host-interpreter fallback;
  * the produced artifact is returned with its ``sha256:``-prefixed digest —
    the number compared against the server's ``result_digest``. NOTE: the
    platform stores/serves result digests as bare 64-hex (its certificate
    DIGEST_PATTERN forbids the prefix), so comparisons go through
    ``blind.hashing.digests_match``, which normalizes both encodings.

The workdir/input.json convention in stages.py is the LOCAL runner for the
other numbered stages; the server never uses it (see stages.py docstring).
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path

from blind.errors import UsageError, VerificationError
from blind.hashing import sha256_file
from blind.runtime.bundle import Bundle
from blind.runtime.sandbox import (
    ContainerSandbox,
    limits_for,
    scrubbed_direct_env,
    unsafe_direct_enabled,
)
from blind.runtime.shims import execution_stage_file


@dataclass
class ComputeResult:
    artifact: Path
    sha256: str  # sha256:<hex> of the artifact bytes (the recomputed result digest)
    inputs: list[Path]  # the ciphertexts, in canonical (digest-sorted) order
    stdout: str
    stderr: str


def sort_inputs_by_digest(paths: list[str | Path]) -> list[Path]:
    """The server's canonical input order: ascending by ciphertext sha256 digest
    (the identical sort the cohort commitment uses)."""
    return [p for _, p in sorted((sha256_file(p), Path(p)) for p in paths)]


def _direct_run(
    bundle: Bundle,
    stage_file: Path,
    args: list[str],
    *,
    timeout: int,
    private_input: tuple[str, bytes] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Explicitly unsafe test/development seam; never selected implicitly."""
    if private_input is None:
        return subprocess.run(  # nosec B603
            [sys.executable, str(stage_file), *args],
            cwd=str(bundle.root),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
            env=scrubbed_direct_env(bundle.root),
        )

    marker, payload = private_input
    if os.name == "nt":
        raise VerificationError("Pipe-only private inputs require the container sandbox on Windows")
    if not marker or marker.startswith("-") or args.count(marker) != 1 or not payload:
        raise VerificationError("Invalid pipe-only private stage input")
    rewritten = ["/dev/stdin" if value == marker else value for value in args]
    result = subprocess.run(  # nosec B603
        [sys.executable, str(stage_file), *rewritten],
        cwd=str(bundle.root),
        capture_output=True,
        input=payload,
        timeout=timeout,
        env=scrubbed_direct_env(bundle.root),
    )
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        result.stdout.decode("utf-8", errors="replace"),
        result.stderr.decode("utf-8", errors="replace"),
    )


def run_compute_stage(
    bundle: Bundle,
    context_path: str | Path,
    input_paths: list[str | Path],
    out_path: str | Path,
    *,
    timeout: int = 3600,
    sort: bool = True,
) -> ComputeResult:
    """Invoke the compute stage exactly as the server does (argparse convention).

    ``sort`` controls input ordering. The default (``True``) sorts ciphertexts
    ascending by their ``sha256:`` digest — the server's canonical order, which
    is correct for the order-invariant additive fold and what the local
    simulate/compute path needs to reproduce the server's bytes. Order-
    significant applications (e.g. ``genotype_phenotype_covariance``, whose stage 30
    expects INTERLEAVED ``g0,y0,g1,y1,…`` inputs) pass ``sort=False`` so the
    caller's explicit order is preserved verbatim.
    """
    stage_file, shim_dir = execution_stage_file(bundle.root, "30_compute_encrypted.py")
    if not stage_file.exists():
        raise UsageError(f"Bundle {bundle.name} has no compute stage file")
    context_path = Path(context_path)
    if not context_path.exists():
        raise UsageError(f"Public context not found: {context_path}")
    if not input_paths:
        raise UsageError("No ciphertext inputs to compute over.")
    for p in input_paths:
        if not Path(p).exists():
            raise UsageError(f"Ciphertext input not found: {p}")

    inputs = sort_inputs_by_digest(input_paths) if sort else [Path(p) for p in input_paths]
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    args = [
        "--context", str(context_path),
        "--inputs", *[str(p) for p in inputs],
        "--out", str(out_path),
    ]
    try:
        if unsafe_direct_enabled():
            proc = _direct_run(bundle, stage_file, args, timeout=timeout)
        else:
            proc = ContainerSandbox().run_stage(
                bundle_root=bundle.root,
                shim_dir=shim_dir,
                stage_name=stage_file.name,
                args=args,
                input_paths=[context_path, *inputs],
                output_paths=[out_path],
                output_dir_argument=None,
                limits=limits_for(bundle.manifest.raw, timeout),
            )
    except FileNotFoundError as exc:
        raise UsageError(f"Compute stage runner not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise UsageError(f"Compute stage timed out after {timeout}s") from exc

    if proc.returncode != 0:
        raise UsageError(
            f"Compute stage ({stage_file.name}) exited {proc.returncode}; "
            "application output was suppressed to protect private inputs"
        )
    if not out_path.exists():
        raise UsageError(f"Compute stage exited 0 but wrote no artifact at {out_path}")

    return ComputeResult(
        artifact=out_path,
        sha256=sha256_file(out_path),
        inputs=inputs,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


# ---------------------------------------------------------------------------
# The LOCAL argparse stage invokers (the OTHER five numbered stages)
# ---------------------------------------------------------------------------
#
# These mirror ``run_compute_stage``'s runner-selection + subprocess pattern for
# the five non-server stages, speaking the SAME argparse CLI the shipped bundles
# expose (``--out-dir`` / ``--raw`` / ``--context`` / ``--result`` / ``--plain``).
# ``blind bench`` drives the real 00/10/20/30/40/50 stages through these — the
# encrypted-on-synthetic engine now measures the identical invocation a real job
# (and the hosted worker, for stage 30) runs, instead of the stub-only
# workdir/input.json convention in ``stages.py`` (which stays intact for
# ``workspace.py`` and any input.json bundle).


def _run_stage_argv(
    bundle: Bundle,
    stage: str,
    args: list[str],
    input_paths: list[Path],
    out_paths: list[Path],
    *,
    timeout: int,
    output_dir_argument: Path | None = None,
    private_input: tuple[str, bytes] | None = None,
) -> subprocess.CompletedProcess:
    """Invoke one numbered stage through its argparse CLI, asserting the declared
    output artifacts landed. Shared body for the five local-stage invokers."""
    stage_name = {
        "keygen": "00_keygen.py",
        "encode": "10_encode.py",
        "encrypt": "20_encrypt.py",
        "decrypt": "40_decrypt.py",
        "decode": "50_decode.py",
    }[stage]
    stage_file, shim_dir = execution_stage_file(bundle.root, stage_name)
    if not stage_file.exists():
        raise UsageError(f"Bundle {bundle.name} has no {stage} stage file")
    try:
        if unsafe_direct_enabled():
            proc = _direct_run(
                bundle, stage_file, args, timeout=timeout, private_input=private_input
            )
        else:
            proc = ContainerSandbox().run_stage(
                bundle_root=bundle.root,
                shim_dir=shim_dir,
                stage_name=stage_file.name,
                args=args,
                input_paths=input_paths,
                output_paths=out_paths,
                output_dir_argument=output_dir_argument,
                limits=limits_for(bundle.manifest.raw, timeout),
                private_input=private_input,
            )
    except FileNotFoundError as exc:
        raise UsageError(f"{stage} stage runner not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise UsageError(f"{stage} stage timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise UsageError(
            f"{stage} stage ({stage_file.name}) exited {proc.returncode}; "
            "application output was suppressed to protect private inputs"
        )
    for p in out_paths:
        if not Path(p).exists():
            raise UsageError(f"{stage} stage exited 0 but wrote no artifact at {p}")
    return proc


def run_keygen_stage(
    bundle: Bundle, out_dir: str | Path, *, extra_argv: tuple[str, ...] = (),
    timeout: int = 600,
) -> tuple[Path, Path]:
    """``00_keygen.py --out-dir DIR`` → ``(public_context, secret_context)``.

    Writes the fixed filenames standardized across the shipped bundles
    (``public_context.tenseal`` / ``secret_context.tenseal``)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    public = out_dir / "public_context.tenseal"
    secret = out_dir / "secret_context.tenseal"
    _run_stage_argv(
        bundle, "keygen", ["--out-dir", str(out_dir), *extra_argv], [], [public, secret],
        timeout=timeout, output_dir_argument=out_dir,
    )
    return public, secret


def run_encode_stage(
    bundle: Bundle, raw_path: str | Path, length: int, out_path: str | Path,
    *, extra_argv: tuple[str, ...] = (), timeout: int = 600,
) -> Path:
    """``10_encode.py --raw RAW --length L --out OUT`` (+ optional extra flags,
    e.g. ``--phenotype-domain``)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _run_stage_argv(
        bundle, "encode",
        ["--raw", str(raw_path), "--length", str(length), "--out", str(out_path),
         *extra_argv],
        [Path(raw_path)], [out_path], timeout=timeout)
    return out_path


def run_encrypt_stage(
    bundle: Bundle, context: str | Path, encoded: str | Path,
    out_paths: list[str | Path], *, timeout: int = 600,
) -> list[Path]:
    """``20_encrypt.py --context CTX --encoded ENC ...``.

    Single-output applications pass one path (``--out``); multi-output applications
    (two ciphertexts per contributor) pass two (``--out-g`` / ``--out-y``)."""
    outs = [Path(p) for p in out_paths]
    for p in outs:
        p.parent.mkdir(parents=True, exist_ok=True)
    base = ["--context", str(context), "--encoded", str(encoded)]
    if len(outs) == 1:
        args = base + ["--out", str(outs[0])]
    elif len(outs) == 2:
        args = base + ["--out-g", str(outs[0]), "--out-y", str(outs[1])]
    else:
        raise UsageError(f"encrypt stage supports 1 or 2 outputs, got {len(outs)}")
    _run_stage_argv(
        bundle, "encrypt", args, [Path(context), Path(encoded)], outs, timeout=timeout
    )
    return outs


def run_decrypt_stage(
    bundle: Bundle, context: str | Path, result: str | Path, out_path: str | Path,
    *, timeout: int = 600,
) -> Path:
    """``40_decrypt.py --context SECRET --result RESULT --out PLAIN``."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _run_stage_argv(
        bundle, "decrypt",
        ["--context", str(context), "--result", str(result), "--out", str(out_path)],
        [Path(context), Path(result)], [out_path], timeout=timeout)
    return out_path


def run_decrypt_stage_from_bytes(
    bundle: Bundle, context: bytes, result: str | Path, out_path: str | Path,
    *, timeout: int = 600,
) -> Path:
    """Decrypt with a secret context delivered over stdin, never a host file."""
    marker = "__blind_private_context__"
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _run_stage_argv(
        bundle,
        "decrypt",
        ["--context", marker, "--result", str(result), "--out", str(out_path)],
        [Path(result)],
        [out_path],
        timeout=timeout,
        private_input=(marker, context),
    )
    return out_path


def run_decode_stage(
    bundle: Bundle, plain: str | Path, length: int, out_path: str | Path,
    *, timeout: int = 600,
) -> Path:
    """``50_decode.py --plain PLAIN --length L --out RESULT``."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _run_stage_argv(
        bundle, "decode",
        ["--plain", str(plain), "--length", str(length), "--out", str(out_path)],
        [Path(plain)], [out_path], timeout=timeout)
    return out_path
