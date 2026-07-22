"""Execute a numbered application stage inside the bundle's sealed env.

THE STAGE I/O CONVENTION (the contract fixtures and real bundles both honor):

A stage is invoked with one positional argument — a *work directory* — that the
CLI has populated with ``input.json``. The stage reads ``input.json``, does its
work, writes any artifact bytes to the path named in ``input.json["out"]``, and
writes ``output.json`` describing what it produced. Nothing is read from stdin;
stdout/stderr are for logs only.

``input.json`` (CLI → stage)::

    {
      "stage": "keygen|encode|encrypt|compute|decrypt|decode",
      "params": { ... },              # relevant manifest params (coordinates, length, ...)
      "input": "<abs path>",          # single input artifact (encode/encrypt/decrypt/decode)
      "inputs": ["<abs path>", ...],  # multiple ciphertext inputs (compute)
      "public_context": "<abs path>", # encrypt: the project public context
      "secret_key": "<abs path>",     # decrypt: the local secret; keygen WRITES it
      "out": "<abs path>",            # where to write the primary output artifact
      "out_public": "<abs path>",     # keygen only
      "out_secret": "<abs path>"      # keygen only
    }

``output.json`` (stage → CLI)::

    { "artifact": "<abs path>", "sha256": "sha256:...", "meta": { ... } }

This legacy workdir adapter is retained only for explicit development fixtures.
Production commands use the argparse adapters in ``runtime.compute``, which run
inside the fail-closed container sandbox. There is no implicit host fallback.

NOTE — the server does NOT use this workdir/input.json convention. The hosted
worker invokes ``30_compute_encrypted.py`` via its argparse interface
(``--context <public_context> --inputs <ct...> --out <result>``) inside a
``--network none`` sealed sandbox. The local mirror of that server invocation
lives in ``blind/runtime/compute.py`` (used by the simulate/compute path);
this module is the LOCAL runner for the other numbered stages and for stub
bundles that honor the input.json convention.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from blind.errors import UsageError
from blind.hashing import sha256_file
from blind.runtime.bundle import Bundle
from blind.runtime.sandbox import scrubbed_direct_env, unsafe_direct_enabled


@dataclass
class StageResult:
    artifact: Path | None
    sha256: str | None
    meta: dict
    stdout: str
    stderr: str


def _runner_cmd(bundle: Bundle, stage_file: Path, workdir: Path) -> list[str]:
    if unsafe_direct_enabled():
        return [sys.executable, str(stage_file), str(workdir)]
    raise UsageError(
        "The legacy workdir stage adapter is disabled outside explicit tests; "
        "use the sandboxed argparse stage interface"
    )


def run_stage(
    bundle: Bundle,
    stage: str,
    payload: dict,
    *,
    workdir: Path | None = None,
    timeout: int = 600,
) -> StageResult:
    """Run one numbered stage under the documented I/O convention."""
    stage_file = bundle.stage_file(stage)
    if not stage_file.exists():
        raise UsageError(f"Bundle {bundle.name} has no stage file for {stage!r}")

    tmp_created = workdir is None
    workdir = workdir or Path(tempfile.mkdtemp(prefix="blind-stage-"))
    payload = {"stage": stage, **payload}
    (workdir / "input.json").write_text(json.dumps(payload))

    cmd = _runner_cmd(bundle, stage_file, workdir)
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            cwd=str(bundle.root),
            capture_output=True,
            timeout=timeout,
            text=True,
            env=scrubbed_direct_env(bundle.root),
        )
    except FileNotFoundError as exc:
        raise UsageError(f"Stage runner not found: {exc}") from exc

    stdout, stderr = proc.stdout, proc.stderr
    if proc.returncode != 0:
        raise UsageError(
            f"Stage {stage} ({stage_file.name}) exited {proc.returncode}; "
            "application output was suppressed to protect private inputs"
        )

    out_json = workdir / "output.json"
    meta: dict = {}
    artifact: Path | None = None
    sha: str | None = None
    if out_json.exists():
        data = json.loads(out_json.read_text())
        meta = data.get("meta", {})
        if data.get("artifact"):
            artifact = Path(data["artifact"])
            sha = data.get("sha256") or (sha256_file(artifact) if artifact.exists() else None)
        # keygen returns public/secret paths in meta
        for k in ("public", "secret", "artifact", "sha256"):
            if k in data and k not in meta:
                meta[k] = data[k]
    elif payload.get("out") and Path(payload["out"]).exists():
        artifact = Path(payload["out"])
        sha = sha256_file(artifact)

    result = StageResult(artifact=artifact, sha256=sha, meta=meta, stdout=stdout, stderr=stderr)
    if tmp_created:
        result.meta.setdefault("_workdir", str(workdir))
    return result
