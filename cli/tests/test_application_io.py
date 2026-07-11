"""`application_io` adapter ↔ real stage-CLI contract (regression for B0).

The stub bundles in ``conftest`` are single-output and value-preserving, so a
mismatch between an ``application_io`` adapter and a *real* bundle's stage CLI never
shows up in the stub suite. B0 was exactly such a mismatch: the covariance
adapter declared ``encrypt_outputs=2`` (→ ``run_encrypt_stage`` invokes
``20_encrypt.py --out-g … --out-y …``) after the bundle had been changed to emit
ONE packed ``(g, y)`` blob via a single ``--out``. ``blind bench`` then recorded
the 6th application ``infeasible-at-params`` while the whole suite stayed green.

These tests load the REAL bundle and assert the adapter's declared output count
is exactly what the shipped ``20_encrypt.py`` CLI requires — so this specific
divergence can never regress silently again.
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import sys

from blind.runtime.compute import run_encrypt_stage
from blind.runtime.application_io import application_io_for
from blind.runtime.bundle import load_bundle
from blind.runtime.shims import materialize


class _ParserGrabbed(Exception):
    pass


def _encrypt_stage_option_strings(bundle) -> set[str]:
    """Return the set of CLI option strings the bundle's ``20_encrypt.py``
    declares — introspected from its actual ``argparse`` parser (robust to
    argument renames), not scraped from source."""
    stage_path = bundle.stage_file("encrypt")
    spec = importlib.util.spec_from_file_location("cov_encrypt_stage", stage_path)
    module = importlib.util.module_from_spec(spec)

    # The stage file is a thin kit shim that imports its pure function from a
    # sibling author module (local_data_owner.py). Loading it IN-PROCESS therefore
    # needs the bundle root on sys.path — exactly what `python 20_encrypt.py` from
    # the bundle root (how the worker/CLI actually run it) gets for free.
    bundle_root = str(stage_path.parent)
    sys.path.insert(0, bundle_root)
    try:
        spec.loader.exec_module(module)
    finally:
        if bundle_root in sys.path:
            sys.path.remove(bundle_root)
        sys.modules.pop("local_data_owner", None)

    captured: dict[str, argparse.ArgumentParser] = {}
    original = argparse.ArgumentParser.parse_args

    def _grab(self, *args, **kwargs):  # noqa: ANN001
        captured["parser"] = self
        raise _ParserGrabbed

    argparse.ArgumentParser.parse_args = _grab  # type: ignore[assignment]
    try:
        module.main([])
    except _ParserGrabbed:
        pass
    finally:
        argparse.ArgumentParser.parse_args = original  # type: ignore[assignment]

    parser = captured["parser"]
    options: set[str] = set()
    for action in parser._actions:  # noqa: SLF001 — introspection is the point
        options.update(action.option_strings)
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
