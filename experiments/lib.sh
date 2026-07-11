#!/usr/bin/env bash
# Shared configuration for The Blind Machine paper experiments.
#
# Every experiment runs ENTIRELY LOCALLY — no hosted server, no network, no real
# data. This is "simulation mode": `blind bench` and `blind simulate` drive the
# real signed application bundles end-to-end (00_keygen … 50_decode) under real
# TenSEAL on seeded synthetic cohorts, in a sandbox on this machine. The hosted
# blindmachine.org service is never contacted. A reviewer reproduces every table
# with `bash run_all.sh` and nothing else.
set -euo pipefail

EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$EXP_DIR/../../.." && pwd)"
APPS_DIR="$REPO_ROOT/applications"
CLI_DIR="$REPO_ROOT/cli"

# A self-contained, experiment-local ~/.blind so a run never touches the
# reviewer's real CLI state and is trivially discarded (rm -rf .blind-home).
export BLIND_HOME="$EXP_DIR/.blind-home"

# The one seed the whole paper is reproducible from. Synthetic cohorts are drawn
# under Hardy-Weinberg equilibrium and are bit-for-bit determined by (seed, N, L).
export SEED="${SEED:-42}"

RESULTS="$EXP_DIR/results"
RAW="$RESULTS/raw"
mkdir -p "$RAW"

# The six curated BFV applications. First four are minimal-params additive BFV;
# last two are multiplication-supporting BFV (depth-1). This split is the paper's
# empirical spine (draft §5, Table 4).
APPLICATIONS=(
  allele_frequency_count
  carrier_count
  cohort_histogram
  polygenic_score_aggregate
  allele_frequency_with_variance
  genotype_phenotype_covariance
)
ADDITIVE=(allele_frequency_count carrier_count cohort_histogram polygenic_score_aggregate)
MULTIPLICATIVE=(allele_frequency_with_variance genotype_phenotype_covariance)

# Run the offline `blind` CLI from its own uv environment, pointed at the
# experiment-local store. Stdout stays clean JSON under `--json`.
blind() { ( cd "$CLI_DIR" && BLIND_HOME="$BLIND_HOME" uv run blind "$@" ); }

# Run one benchmark cell and save the full JSON under results/raw/<tag>.json.
# Usage: bench_cell <tag> <application> [extra blind bench args...]
bench_cell() {
  local tag="$1" application="$2"; shift 2
  echo "  · $tag  ($application  $*)"
  blind --json bench "${application}@local" --seed "$SEED" "$@" > "$RAW/${tag}.json"
}
