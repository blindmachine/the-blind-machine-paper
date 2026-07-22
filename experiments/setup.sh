#!/usr/bin/env bash
# One-time setup: materialize each application's sealed environment and install the
# six bundles into the experiment-local, offline store. Idempotent.
#
# No registry / hosted server is involved: each bundle is a self-contained,
# content-addressed directory under applications/, and we install it locally by
# copying it into the CLI's experiment-local application cache path
# ($BLIND_STATE_DIR/applications/<name>@local). `blind bench` recomputes the bundle
# digest from its contents and runs the real stages against the sealed env —
# exactly what the hosted worker does for stage 30, but on synthetic data here.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

echo "[setup] materializing sealed per-application environments (uv sync --frozen)…"
# Seal the six signed bundles AND the E8 draft bundle; the sealed envs also provide
# the TenSEAL runtime the E5-E8 real-DNA studies re-exec into. A bundle that isn't
# present (e.g. a package that omitted the draft) is skipped, and its study SKIPs.
for p in "${ALL_APPLICATIONS[@]}"; do
  if [ ! -d "$APPS_DIR/$p/signed" ]; then
    echo "  · $p  not present — skipping"
  elif [ -d "$APPS_DIR/$p/signed/env/.venv" ]; then
    echo "  · $p  env already sealed"
  else
    echo "  · $p  sealing env…"
    ( cd "$APPS_DIR/$p/signed" && uv --project env sync --frozen )
  fi
done

echo "[setup] installing bundles into the offline application cache ($BLIND_STATE_DIR/applications)…"
rm -rf "$BLIND_STATE_DIR/applications"
mkdir -p "$BLIND_STATE_DIR/applications"
for p in "${APPLICATIONS[@]}"; do
  dest="$BLIND_STATE_DIR/applications/${p}@local"
  cp -R "$APPS_DIR/$p" "$dest"
  # A dev checkout can carry stray __pycache__/*.pyc from having imported the role
  # files locally. `blind applications install` never sees these (it unpacks a clean
  # signed tar), and the CLI's verify_installed_structure fails closed on any unsigned
  # bytecode OUTSIDE the one sealed venv. Strip them from the offline copy so the
  # cp-based install matches the registry tar — but NEVER touch the sealed
  # signed/env/.venv (its bytecode is part of the pinned environment).
  find "$dest" -path '*/.venv' -prune -o \( -name '__pycache__' -type d -print \) 2>/dev/null | xargs -r rm -rf
  find "$dest" -path '*/.venv' -prune -o \( -name '*.pyc' -type f -print \) 2>/dev/null | xargs -r rm -f
done

# `blind applications install` records an env_lock (a sha256 over the bundle's own
# uv.lock + .python-version) via seal_env, and the CLI re-verifies it at run time.
# The offline harness installs by copy instead of fetching from the registry, so we
# write the same self-computed env_lock here — the local equivalent of that seal.
# This is a byte-for-byte integrity record over the bundle's OWN env, so it keeps the
# CLI's verify_env_lock check meaningful rather than weakening it.
echo "[setup] recording per-bundle env_lock (offline equivalent of install-time seal)…"
( cd "$CLI_DIR" && HOME="$BLIND_PAPER_HOME" uv run python - "$BLIND_STATE_DIR/applications" <<'PY'
import sys
from pathlib import Path
from blind.runtime.bundle import load_bundle
root = Path(sys.argv[1])
for d in sorted(root.iterdir()):
    if not d.name.endswith("@local") or not d.is_dir():
        continue
    bundle = load_bundle(d)
    (bundle.root / "env_lock").write_text(bundle.compute_env_lock() + "\n")
    print(f"  · {d.name}  env_lock recorded")
PY
)

echo "[setup] done. Six bundles installed offline; run: bash run_all.sh"
