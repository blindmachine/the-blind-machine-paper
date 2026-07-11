#!/usr/bin/env bash
# replicate_all.sh — ONE command to run EVERY paper experiment (E1-E8) and print a
# single PASS / SKIP / FAIL table. This is the artifact an independent reviewer or
# AI agent runs to reproduce the whole paper from a clean clone.
#
#   bash replicate_all.sh          # full: E1-E4 synthetic (incl. the E2/E3 sweeps) + E5-E8
#   bash replicate_all.sh fast     # E1+E4 synthetic core + E5-E8 (skips the longer E2/E3 sweeps)
#
#   E1-E4  synthetic BFV taxonomy / security matrix / feasibility / differencing —
#          offline, deterministic; these MUST PASS.
#   E5-E8  public-genome studies — need bcftools + network; they SKIP cleanly
#          (not FAIL) when a prerequisite is missing.
#
# Exit status is non-zero ONLY if a deterministic experiment produced a WRONG result.
# SKIPs (no bcftools, no network, an unsealed env, an absent draft bundle) are not
# failures — a prerequisite you could not provide is not a broken paper.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
MODE="${1:-full}"

NAMES=(); STATUS=()
record() { NAMES+=("$1"); STATUS+=("$2"); }

echo "======================================================================"
echo " The Blind Machine — full paper replication (E1-E8), mode: $MODE"
echo " apps: $APPS_DIR"
echo " cli : $CLI_DIR"
echo "======================================================================"

# --- E1-E4 synthetic harness (setup + experiments + verify.py invariants) ---------
echo
echo ">>> E1-E4  synthetic BFV harness (offline, deterministic)"
if bash "$EXP_DIR/run_all.sh" "$MODE"; then
  record "E1-E4 synthetic (verify.py invariants)" "PASS"
else
  record "E1-E4 synthetic (verify.py invariants)" "FAIL"
fi

# --- fetch bounded public genome slices (best effort) -----------------------------
echo
echo ">>> fetching bounded public 1000 Genomes slices (best effort)"
if bash "$EXP_DIR/fetch_public_data.sh"; then
  echo "    public data staged."
else
  echo "    fetch unavailable (no bcftools/network/mirror) — E5-E8 will SKIP."
fi

# --- E5-E8 real-DNA studies (exit 0 = PASS, 3 = SKIP, anything else = FAIL) --------
run_study() {  # $1 = label, $2 = wrapper script
  echo
  echo ">>> $1"
  set +e
  bash "$EXP_DIR/$2"
  local rc=$?
  set -e
  case "$rc" in
    0) record "$1" "PASS" ;;
    3) record "$1" "SKIP" ;;
    *) record "$1" "FAIL (rc=$rc)" ;;
  esac
}
run_study "E5 real human DNA (IGSR)"     "e5_real_human_dna_igsr.sh"
run_study "E6 public AF / FST panel"     "e6_public_af_fst_panel.sh"
run_study "E7 beacon release policy"     "e7_beacon_release_policy.sh"
run_study "E8 public LD window (draft)"  "e8_public_ld_window.sh"

# (Regenerate the appendix tables/figures afterwards with:
#   python3 summarize_public_real_dna.py )

# --- summary table + overall verdict ----------------------------------------------
echo
echo "==================== REPLICATION SUMMARY ===================="
any_fail=0
for i in "${!NAMES[@]}"; do
  printf "  %-40s %s\n" "${NAMES[$i]}" "${STATUS[$i]}"
  case "${STATUS[$i]}" in FAIL*) any_fail=1 ;; esac
done
echo "============================================================"
echo "  PASS = reproduced   SKIP = missing prerequisite (not a failure)   FAIL = wrong result"
if [ "$any_fail" -ne 0 ]; then
  echo "RESULT: FAIL — a deterministic experiment produced a wrong result."
  exit 1
fi
echo "RESULT: PASS — every experiment that could run reproduced; any SKIPs are missing prerequisites only."
