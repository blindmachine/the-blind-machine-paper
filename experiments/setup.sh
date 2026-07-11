#!/usr/bin/env bash
# One-time setup: materialize each application's sealed environment and install the
# six bundles into the experiment-local, offline store. Idempotent.
#
# No registry / hosted server is involved: each bundle is a self-contained,
# content-addressed directory under applications/, and we install it locally by
# copying it into the CLI's experiment-local application cache path
# ($BLIND_HOME/applications/<name>@local). `blind bench` recomputes the bundle
# digest from its contents and runs the real stages against the sealed env —
# exactly what the hosted worker does for stage 30, but on synthetic data here.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

echo "[setup] materializing sealed per-application environments (uv sync --frozen)…"
for p in "${APPLICATIONS[@]}"; do
  if [ -d "$APPS_DIR/$p/signed/env/.venv" ]; then
    echo "  · $p  env already sealed"
  else
    echo "  · $p  sealing env…"
    ( cd "$APPS_DIR/$p/signed" && uv --project env sync --frozen )
  fi
done

echo "[setup] installing bundles into the offline application cache ($BLIND_HOME/applications)…"
rm -rf "$BLIND_HOME/applications"
mkdir -p "$BLIND_HOME/applications"
for p in "${APPLICATIONS[@]}"; do
  cp -R "$APPS_DIR/$p" "$BLIND_HOME/applications/${p}@local"
done

echo "[setup] done. Six bundles installed offline; run: bash run_all.sh"
