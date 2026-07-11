"""`blind data` — LOCAL encode/encrypt primitives (power / dev). Nothing uploaded."""

from __future__ import annotations

from pathlib import Path

import typer

from blind import console
from blind.context import Context, emit
from blind.errors import UsageError
from blind.hashing import sha256_file, short
from blind.workspace import resolve_project_bundle, run_encode, run_encrypt

app = typer.Typer(help="Local encode/encrypt primitives (nothing is uploaded).",
                  no_args_is_help=True)


def _ctx(c: typer.Context) -> Context:
    return c.obj


@app.command("encode")
def encode(c: typer.Context, project: str = typer.Option(..., "--project"),
           input: str = typer.Option(..., "--input"),
           out: str = typer.Option(None, "--out")):
    ctx = _ctx(c)
    raw = Path(input)
    if not raw.exists():
        raise UsageError(f"Input not found: {raw}")
    bundle = resolve_project_bundle(ctx.store, project)
    dest = Path(out) if out else ctx.store.home / "cache" / "encoded" / f"{raw.stem}.enc-in"
    artifact, sha = run_encode(bundle, raw, dest)
    view = {"object": "encoded", "project": project, "path": str(artifact),
            "sha256": sha, "coordinate_hash": bundle.digest,
            "trust": {"raw": "local_only", "encoded": "local_only"}}

    def render():
        console.line("read", str(raw), trust="raw")
        console.line("encode", short(sha), str(artifact), trust="encoded")

    emit(ctx, view, render)


@app.command("encrypt")
def encrypt(c: typer.Context, project: str = typer.Option(..., "--project"),
            input: str = typer.Option(..., "--input"),
            append_sentinel: bool = typer.Option(True, "--append-sentinel/--no-append-sentinel"),
            out: str = typer.Option(None, "--out")):
    ctx = _ctx(c)
    src = Path(input)
    if not src.exists():
        raise UsageError(f"Input not found: {src}")
    bundle = resolve_project_bundle(ctx.store, project)

    # Auto-encode if the input looks like Raw (not already an encoded artifact).
    if src.suffix != ".enc-in":
        enc_out = ctx.store.home / "cache" / "encoded" / f"{src.stem}.enc-in"
        src, _ = run_encode(bundle, src, enc_out)
        src = Path(src)

    public_ctx = ctx.store.key_dir(project) / "public.context"
    if not public_ctx.exists():
        data = ctx.client().get_public_context(project)
        public_ctx.parent.mkdir(parents=True, exist_ok=True)
        public_ctx.write_text(data.get("public_context", ""))

    dest = Path(out) if out else ctx.store.home / "cache" / "encrypted" / f"{src.stem}.ct"
    artifact, sha = run_encrypt(bundle, src, public_ctx, dest)
    pub_sha = sha256_file(public_ctx)
    view = {"object": "encrypted", "project": project, "path": str(artifact),
            "ciphertext_sha256": sha, "public_context_sha256": pub_sha,
            "trust": {"encrypted": "uploadable"}}

    def render():
        console.line("encrypt", short(sha), str(artifact), trust="encrypted")
        if append_sentinel:
            console.line("append", "sentinel +1", "integrity, not a MAC", trust="encrypted")
        console.console.print(console.Text(
            "Nothing uploaded. Run `blind contributions create` to upload.", style="meta"))

    emit(ctx, view, render)
