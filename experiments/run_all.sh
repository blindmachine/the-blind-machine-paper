#!/usr/bin/env bash
# run_all.sh — the E1-E4 synthetic-core harness only (the offline, deterministic
# BFV claims). This is NOT the full-paper entrypoint: for the whole paper (E1-E10,
# including the public-genome studies E5-E8 and the published-study reproductions
# E9-E10) run the canonical `replicate_all.sh`, which drives this script as its
# first stage. Use this script directly only when you want the fast synthetic core.
#
# One command to reproduce the paper's core empirical claims — entirely locally,
# no hosted server, no network, no real data.
#
#   bash run_all.sh          # fast profile: E1 (taxonomy) + E4 (differencing)  ~2-4 min
#   bash run_all.sh full     # + E2 (security matrix) + E3 (feasibility sweep)  ~15-25 min
#
# On success it prints "RESULT: PASS" and writes paper-facing CSV tables to
# results/. On any bit-exactness / taxonomy / premium / differencing regression it
# prints "RESULT: FAIL" and exits non-zero.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
MODE="${1:-fast}"

# Start from a clean raw-results state. A previous interrupted run can leave a
# zero-byte or partial JSON in results/raw/; without this, verify.py would read
# that stale file. Each experiment below regenerates the raw files it owns, and
# verify.py cleanly skips whichever experiments this profile did not run.
rm -f "$RAW"/*.json

bash "$EXP_DIR/setup.sh"
bash "$EXP_DIR/e1_exactness_taxonomy.sh"
bash "$EXP_DIR/e4_differencing.sh"
if [ "$MODE" = "full" ]; then
  bash "$EXP_DIR/e2_security_matrix.sh"
  bash "$EXP_DIR/e3_feasibility.sh"
fi

python3 "$EXP_DIR/verify.py"
