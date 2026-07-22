"""Materialize the kit-owned stage shims into a bundle dir at run time.

A signed application bundle ships ONLY the author's files (`server.py` +
`local_project_owner.py` / `local_data_owner.py`). The six numbered stage shims
(`00_keygen.py … 50_decode.py`) are framework boilerplate — written here just
before the CLI runs a stage, so `python NN_*.py` can import the author functions.
These templates are byte-identical to the worker's (BlindWorker::ShimScaffold), so
the CLI's local simulate/compute reproduces the server's bytes.

Gated on `server.py`: a legacy self-contained bundle is left untouched.
"""

from __future__ import annotations

import shutil
from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent / "stage_shims"
SERVER_FILE = "server.py"
SHIM_NAMES = (
    "00_keygen.py", "10_encode.py", "20_encrypt.py",
    "30_compute_encrypted.py", "40_decrypt.py", "50_decode.py",
)


def is_new_contract(bundle_root: str | Path) -> bool:
    """True iff the bundle ships server.py (the RFC-0002 named-function contract)."""
    return (Path(bundle_root) / SERVER_FILE).is_file()


def execution_stage_file(bundle_root: str | Path, stage_name: str) -> tuple[Path, Path | None]:
    """Return the trusted stage file and optional shim mount directory.

    New-contract bundles never receive generated files at execution time. Their
    kit-owned shim runs from this installed CLI package with the signed bundle on
    ``PYTHONPATH``. Legacy bundles continue to execute their signed numbered file.
    """
    root = Path(bundle_root)
    if stage_name not in SHIM_NAMES:
        raise ValueError(f"Unknown stage shim: {stage_name}")
    if is_new_contract(root):
        return TEMPLATE_DIR / stage_name, TEMPLATE_DIR
    return root / stage_name, None


def materialize(bundle_root: str | Path) -> bool:
    """Write the six kit shims into ``bundle_root`` (no-op for a legacy bundle).

    Idempotent — overwrites any same-named file, so an author-supplied stage file
    can never shadow the canonical shim.
    """
    root = Path(bundle_root)
    if not is_new_contract(root):
        return False
    for name in SHIM_NAMES:
        shutil.copyfile(TEMPLATE_DIR / name, root / name)
    return True
