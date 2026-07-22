"""`application_io` adapter ↔ real stage-CLI contract (regression for B0).

The stub bundles in ``conftest`` are single-output and value-preserving, so a
mismatch between an ``application_io`` adapter and a *real* bundle's stage CLI never
shows up in the stub suite. B0 was exactly such a mismatch: the covariance
adapter declared ``encrypt_outputs=2`` (→ ``run_encrypt_stage`` invokes
``20_encrypt.py --out-g … --out-y …``) after the bundle had been changed to emit
ONE packed ``(g, y)`` blob via a single ``--out``. ``blind bench`` then recorded
the 6th application ``infeasible-at-params`` while the whole suite stayed green.

These tests use a self-contained signed covariance-shaped bundle and assert the
adapter's declared output count is exactly what the trusted stage shim requires,
so this divergence cannot regress or disappear from standalone CI.
"""

from __future__ import annotations

import ast
import shutil

from blind.runtime.compute import run_encrypt_stage
from blind.runtime.application_io import application_io_for
from blind.runtime.bundle import load_bundle
from blind.runtime.shims import materialize


def _encrypt_stage_option_strings(bundle) -> set[str]:
    """Return the set of CLI option strings the bundle's ``20_encrypt.py``
    declares without importing application-controlled Python into the host."""
    stage_path = bundle.stage_file("encrypt")
    tree = ast.parse(stage_path.read_text(encoding="utf-8"), filename=str(stage_path))
    options: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "add_argument":
            continue
        for argument in node.args:
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                if argument.value.startswith("-"):
                    options.add(argument.value)
    return options


def _materialized_copy(bundle, tmp_path):
    package_root = bundle.package_root or bundle.root
    copied_root = tmp_path / "bundle-copy"
    shutil.copytree(package_root, copied_root)
    copied = load_bundle(copied_root)
    materialize(copied.root)
    return copied


def test_covariance_adapter_declares_single_packed_output(covariance_bundle):
    """The covariance contribution is ONE packed (g, y) blob → encrypt_outputs 1."""
    io = application_io_for(covariance_bundle)
    assert io.encrypt_outputs == 1, (
        "covariance emits one co-packed (g,y) BMCT1 blob per contributor; "
        "encrypt_outputs must be 1 so run_encrypt_stage invokes `--out`, not "
        "`--out-g`/`--out-y`."
    )


def test_covariance_adapter_matches_encrypt_stage_cli(covariance_bundle, tmp_path):
    """The adapter's output count must match what ``20_encrypt.py`` actually asks
    for. This is the exact seam that made B0 record `infeasible-at-params`."""
    bundle = _materialized_copy(covariance_bundle, tmp_path)
    io = application_io_for(bundle)
    opts = _encrypt_stage_option_strings(bundle)

    if io.encrypt_outputs == 1:
        assert "--out" in opts
        assert "--out-g" not in opts and "--out-y" not in opts, (
            "adapter declares one output but the encrypt CLI expects a split "
            "`--out-g`/`--out-y` — run_encrypt_stage would pass the wrong flags."
        )
    elif io.encrypt_outputs == 2:
        assert "--out-g" in opts and "--out-y" in opts
        assert "--out" not in opts
    else:  # pragma: no cover - run_encrypt_stage only supports 1 or 2
        raise AssertionError(f"unexpected encrypt_outputs={io.encrypt_outputs}")


def test_run_encrypt_stage_argv_uses_stage_flags(covariance_bundle, tmp_path):
    """End-to-end on the argv seam (no crypto): the flags ``run_encrypt_stage``
    builds for the adapter's output count are the flags the real stage accepts.

    We stop at argparse — the stage exits 2 with "arguments are required" when
    the flags don't match (the observed B0 failure), and only reaches the (here
    absent) TenSEAL body when they DO. So "not an argparse usage error" proves
    the contract holds without needing the sealed crypto env."""
    bundle = _materialized_copy(covariance_bundle, tmp_path)
    io = application_io_for(bundle)
    out_paths = [tmp_path / f"ct_{i}.bin" for i in range(io.encrypt_outputs)]
    ctx = tmp_path / "public_context.tenseal"
    ctx.write_bytes(b"not-a-real-context")
    encoded = tmp_path / "encoded.json"
    encoded.write_text('{"g": [0], "y": [0]}')

    from blind.errors import UsageError

    try:
        run_encrypt_stage(bundle, ctx, encoded, out_paths)
    except UsageError as exc:
        # A crypto-layer failure (bad context bytes) is fine; an argparse arg
        # mismatch is the B0 regression and must NOT happen.
        assert "arguments are required" not in str(exc), (
            "encrypt stage rejected the flags run_encrypt_stage built for "
            f"encrypt_outputs={io.encrypt_outputs}: {exc}"
        )
        assert "exited 2" not in str(exc), f"argparse usage error from encrypt stage: {exc}"
