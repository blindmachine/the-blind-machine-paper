"""`blind results` — download / decrypt / verify (decrypt is LOCAL)."""

from __future__ import annotations

from pathlib import Path

import typer

from blind import console
from blind.context import Context, emit
from blind.errors import VerificationError
from blind.hashing import digests_match, sha256_prefixed, short
from blind.workspace import resolve_project_bundle, run_decrypt_decode

app = typer.Typer(help="Download / decrypt / verify results.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def _download_result(ctx: Context, job: str) -> tuple[dict, str, str]:
    data = ctx.client().retrieve_result(job)
    ct = data.get("ciphertext_bytes", b"")
    if isinstance(ct, str):
        ct = ct.encode()
    ct = bytes(ct)
    server_digest = data.get("result_digest", "")
    local_digest = sha256_prefixed(ct)
    return data, server_digest, local_digest, ct


@app.command("retrieve")
def retrieve(c: typer.Context, job: str, out: str = typer.Option(None, "--out")):
    ctx = _ctx(c)
    data, server_digest, local_digest, ct_bytes = _download_result(ctx, job)
    verified = digests_match(server_digest, local_digest)
    if not verified and server_digest:
        raise VerificationError(f"Result digest mismatch: {local_digest} != {server_digest}")
    dest = Path(out) if out else ctx.store.home / "results" / job
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "result.ct").write_bytes(ct_bytes)
    view = {"object": "result", "job": job, "result_digest": server_digest,
            "verified": verified, "path": str(dest / "result.ct")}

    def render():
        console.status_line(verified, "result digest", short(server_digest),
                            "matches server")

    emit(ctx, view, render)


@app.command("decrypt")
def decrypt(c: typer.Context, job: str, project: str = typer.Option(None, "--project"),
            out: str = typer.Option(None, "--out"),
            show: bool = typer.Option(False, "--show"),
            display: str = typer.Option(None, "--display")):
    ctx = _ctx(c)
    data, server_digest, local_digest, ct_bytes = _download_result(ctx, job)
    if server_digest and not digests_match(server_digest, local_digest):
        raise VerificationError(f"Result digest mismatch: {local_digest} != {server_digest}")

    project = project or data.get("project_id")
    if not project:
        from blind.errors import UsageError
        raise UsageError("Pass --project so the local secret key can be found.")
    bundle = resolve_project_bundle(ctx.store, project)

    result_dir = ctx.store.result_dir(project, job)
    result_dir.mkdir(parents=True, exist_ok=True)
    ct_path = result_dir / "result.ct"
    ct_path.write_bytes(ct_bytes)

    aggregate = run_decrypt_decode(ctx.store, project, bundle, ct_path, result_dir)
    # Real decode → {n_contributors, allele_counts, allele_frequencies}; stub →
    # {vector, sentinel_n}. Accept both so the view is application-agnostic.
    sentinel_n = (aggregate.get("n_contributors") or aggregate.get("sentinel_n")
                  or aggregate.get("n"))
    counts = (aggregate.get("allele_counts") or aggregate.get("vector")
              or aggregate.get("result"))
    frequencies = aggregate.get("allele_frequencies")
    view = {
        "object": "decrypted_result",
        "job": job,
        "project": project,
        "result_digest": server_digest or local_digest,
        "result": counts,
        "frequencies": frequencies,
        "sentinel_n": sentinel_n,
        "aggregate": aggregate,
        "min_contributors_satisfied": data.get("min_contributors_satisfied"),
        "trust": {"result_plain": "local_only"},
    }

    def render():
        console.line("verify", "application", "digest verified", trust=None)
        console.status_line(True, "result (cipher)", short(server_digest or local_digest),
                            "matches server result digest")
        console.line("decrypt", "aggregate", f"sentinel N = {sentinel_n}", trust="raw")
        want = (display or "").lower()
        payload = frequencies if (want in ("maf", "freq", "frequencies") and frequencies
                                  is not None) else counts
        if (show or want) and payload is not None:
            console.console.print(payload)

    emit(ctx, view, render)


@app.command("verify")
def verify(c: typer.Context, job: str,
           local: bool = typer.Option(
               False, "--local",
               help="Re-execute the pinned compute stage HERE over --inputs. For "
                    "synthetic/self-owned cohorts: real cohort ciphertexts are never "
                    "served, so you must already hold the input files."),
           inputs: str = typer.Option(
               None, "--inputs",
               help="Directory of ciphertext files to recompute over (required with --local)."),
           context: str = typer.Option(
               None, "--context",
               help="Public context file (default: the project's cached public.context)."),
           bundle: str = typer.Option(
               None, "--bundle",
               help="Application bundle directory (default: the project's pinned installed bundle)."),
           project: str = typer.Option(None, "--project"),
           timeout: int = typer.Option(
               300, "--timeout",
               help="Server mode: seconds to wait for the re-execution to reach "
                    "a verdict before giving up (never a false verdict)."),
           interval: float = typer.Option(
               2.0, "--interval",
               help="Server mode: poll interval in seconds.")):
    ctx = _ctx(c)
    if local:
        view, render = _verify_local(ctx, job, inputs=inputs, context=context,
                                     bundle_dir=bundle, project=project)
    else:
        view, render = _verify_server(ctx, job, timeout=timeout, interval=interval)

    emit(ctx, view, render)
    if not view["identical"]:
        raise typer.Exit(code=VerificationError.code)


def _verify_server(ctx: Context, job: str, *, timeout: int = 300, interval: float = 2.0):
    """Server path: POST /jobs/:id/reexecute spawns a QUEUED, non-billable
    re-execution run — the 201 body is that fresh run (result_digest and
    matches are null), NOT a verdict. Poll the run to a terminal state, then
    compare its recomputed result_digest against the ORIGINAL job's
    result_digest (cli/COMMANDS.md: "the CLI compares digests"). A server
    `matches` verdict, when present, is respected. Surfaces failure_reason when
    the re-execution failed; a timeout raises PreconditionError rather than
    inventing a verdict either way."""
    import time

    from blind.errors import PreconditionError

    client = ctx.client()
    run = client.reexecute_job(job)
    run_id = run.get("id")

    deadline = time.monotonic() + timeout
    while run.get("matches") is None and run.get("state") in ("queued", "running"):
        if not run_id or time.monotonic() >= deadline:
            raise PreconditionError(
                f"Re-execution {run_id or '(unknown id)'} is still "
                f"'{run.get('state', 'pending')}' after {timeout}s — no verdict yet. "
                f"Re-run `blind results verify {job}` later (or raise --timeout).")
        time.sleep(interval)
        run = client.retrieve_job(run_id)

    recomputed = run.get("result_digest") or ""
    failure_reason = run.get("failure_reason")
    failed = run.get("state") == "failed" or bool(failure_reason)

    # The original job's digest is the number being reproduced.
    original = client.retrieve_job(job)
    server_digest = original.get("result_digest") or ""

    if failed:
        identical = False
    elif run.get("matches") is not None:
        identical = bool(run["matches"])
    else:
        identical = digests_match(server_digest, recomputed)

    view = {"object": "result_verification", "job": job, "mode": "server",
            "reexecution_id": run_id,
            "server_result_digest": server_digest, "recomputed_result_digest": recomputed,
            "identical": identical,
            # The comparison was done BY the server, so this is a governance record,
            # not an independent verification. Never label it "verified by
            # re-execution": that phrase is reserved for the local path (V3.1).
            "independent": False}
    if failure_reason:
        view["failure_reason"] = failure_reason

    def render():
        console.line("compute", "server re-executed the pinned application on the SAME ciphertexts")
        if failure_reason:
            console.status_line(False, "re-execution", failure_reason, "failed server-side")
        console.status_line(identical, "result digest",
                            short(recomputed),
                            "server reports identical" if identical else "MISMATCH")
        console.panel(
            "Server re-execution — governance record",
            "The HOSTED SERVER re-ran the pinned application and reports a "
            + ("matching" if identical else "MISMATCHING") + " result digest.\n"
            "This is a governance record, NOT an independent verification — the "
            "comparison was performed by the server.\n"
            "Run `blind results verify " + str(job) + " --local --inputs DIR` to "
            "verify independently (synthetic / self-owned cohorts).",
            kind="trust")

    return view, render


def _verify_local(ctx: Context, job: str, *, inputs: str | None, context: str | None,
                  bundle_dir: str | None, project: str | None):
    """Honest local re-execution: run the pinned 30_compute_encrypted.py HERE
    (server argparse convention, digest-sorted inputs) over user-supplied
    ciphertext files, then compare the recomputed digest to the server's."""
    from blind.errors import PreconditionError, UsageError
    from blind.runtime.bundle import load_bundle
    from blind.runtime.compute import run_compute_stage
    from blind.workspace import resolve_project_bundle

    if not inputs:
        raise UsageError(
            "--local requires --inputs DIR (a directory of ciphertext files). "
            "Real cohort ciphertexts are never served; --local is for "
            "synthetic/self-owned cohorts.")
    input_dir = Path(inputs)
    if not input_dir.is_dir():
        raise UsageError(f"--inputs is not a directory: {inputs}")
    ciphertexts = sorted(p for p in input_dir.iterdir()
                         if p.is_file() and not p.name.startswith("."))
    if not ciphertexts:
        raise UsageError(f"No ciphertext files found in {inputs}")

    data = ctx.client().retrieve_job(job)
    server_digest = data.get("result_digest") or ""
    if not server_digest:
        raise PreconditionError(
            f"Job {job} has no result digest yet (state: {data.get('state', 'unknown')}).")
    project = project or data.get("project_id")
    if not project and not (bundle_dir and context):
        raise UsageError("Pass --project (or both --bundle and --context) so the "
                         "pinned bundle and public context can be resolved.")

    b = load_bundle(bundle_dir) if bundle_dir else resolve_project_bundle(ctx.store, project)

    context_path = Path(context) if context else ctx.store.key_dir(project) / "public.context"
    if not context_path.exists():
        raise UsageError(
            f"No public context at {context_path}. Pass --context PATH.")

    out_dir = ctx.store.result_dir(project, job) if project else input_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    result = run_compute_stage(b, context_path, ciphertexts, out_dir / "recomputed.bin")
    recomputed = result.sha256
    # The platform serves bare 64-hex digests; the CLI's canonical form is
    # `sha256:<hex>`. Same value, two encodings — compare normalized.
    identical = digests_match(server_digest, recomputed)

    view = {"object": "result_verification", "job": job, "mode": "local",
            "server_result_digest": server_digest, "recomputed_result_digest": recomputed,
            "identical": identical, "ciphertext_count": len(result.inputs),
            "recomputed_path": str(result.artifact),
            # This IS the independent path: we recomputed the digest HERE, on the
            # client, from the ciphertexts — no server verdict was trusted (V3.1).
            "independent": True}

    def render():
        console.line("compute",
                     f"re-executing {b.application_id.split('@')[0]} locally "
                     f"({len(result.inputs)} ciphertexts, digest-sorted)")
        console.status_line(True, "server digest", short(server_digest))
        console.status_line(identical, "recomputed", short(recomputed),
                            "identical" if identical else "MISMATCH")
        console.panel("Verified by local re-execution (independent)" if identical
                      else "Local re-execution MISMATCH",
                      "Same ciphertexts in → same result digest out, recomputed HERE.\n"
                      "This proves DETERMINISTIC recomputation independently of the "
                      "server, but is not zero-knowledge.",
                      kind="done" if identical else "trust")

    return view, render
