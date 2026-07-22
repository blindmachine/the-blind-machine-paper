"""`blind results` — download / decrypt (decrypt is LOCAL)."""

from __future__ import annotations

from pathlib import Path

import typer

from blind import console
from blind.context import Context, emit
from blind.hashing import require_result_digest, sha256_prefixed, short
from blind.workspace import resolve_project_bundle, run_decrypt_decode

app = typer.Typer(help="Download / decrypt results.", no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


def _download_result(ctx: Context, job: str) -> tuple[dict, str, str, bytes]:
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
    # Fail closed: absent OR mismatched digest refuses the bytes (a hostile
    # server can strip the header as easily as it can tamper with the payload).
    require_result_digest(server_digest, ct_bytes)
    verified = True
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
    # Fail closed BEFORE decrypting: never feed unverified ciphertext to the
    # local secret key. Absent digest == verification failure, not a pass.
    require_result_digest(server_digest, ct_bytes)

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
