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

# Locate applications/ and cli/ by walking UP from experiments/. This works in BOTH
# layouts without editing: the monorepo (docs/paper/experiments + <repo>/applications
# + <repo>/cli, several levels up) and the published paper package (experiments/ with
# sibling applications/ and a vendored cli/). The old hardcoded "$EXP_DIR/../../.."
# pointed ABOVE a standalone clone, which is exactly why an outside reviewer's
# `run_all.sh` could not find the bundles. Override with BLIND_PAPER_APPS_DIR /
# BLIND_CLI_DIR.
_blind_find_up() {  # $1 = directory name to find; prints abs path, returns non-zero if none
  local name="$1" d="$EXP_DIR"
  while :; do
    if [ -d "$d/$name" ]; then ( cd "$d/$name" && pwd ); return 0; fi
    [ "$d" = "/" ] && return 1
    d="$(dirname "$d")"
  done
}

APPS_DIR="${BLIND_PAPER_APPS_DIR:-$(_blind_find_up applications || true)}"
CLI_DIR="${BLIND_CLI_DIR:-$(_blind_find_up cli || true)}"
REPO_ROOT="${APPS_DIR%/applications}"

if [ -z "$APPS_DIR" ] || [ ! -d "$APPS_DIR" ]; then
  echo "lib.sh: could not locate an 'applications/' directory above $EXP_DIR." >&2
  echo "        Set BLIND_PAPER_APPS_DIR to the directory holding the signed bundles." >&2
  exit 1
fi
if [ -z "$CLI_DIR" ] || [ ! -d "$CLI_DIR" ]; then
  echo "lib.sh: could not locate a 'cli/' Blind CLI checkout above $EXP_DIR." >&2
  echo "        The published paper package vendors it at ./cli; the monorepo has <repo>/cli." >&2
  echo "        Set BLIND_CLI_DIR to a github.com/blindmachine/blind checkout to override." >&2
  exit 1
fi

# A self-contained HOME keeps the CLI's fixed ~/.blind store away from the
# reviewer's real state and is trivially discarded (rm -rf .blind-home).
export BLIND_PAPER_HOME="$EXP_DIR/.blind-home"
export BLIND_STATE_DIR="$BLIND_PAPER_HOME/.blind"

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

# The E8 appendix bundle. It is a DRAFT (unsigned, not in the public registry), kept
# separate from the six signed paper bundles. setup.sh seals its env too so E8 can run
# locally under real BFV; if it is absent, E8 SKIPs. Keep in sync with
# public_genomics_common.py::_SEALED_ENV_APPS.
DRAFT_APPLICATIONS=(genotype_pair_ld)
ALL_APPLICATIONS=("${APPLICATIONS[@]}" "${DRAFT_APPLICATIONS[@]}")

# Run the offline `blind` CLI from its own uv environment, pointed at the
# experiment-local store. Stdout stays clean JSON under `--json`.
blind() { ( cd "$CLI_DIR" && HOME="$BLIND_PAPER_HOME" uv run blind "$@" ); }

# Run one benchmark cell and save the full JSON under results/raw/<tag>.json.
# Usage: bench_cell <tag> <application> [extra blind bench args...]
bench_cell() {
  local tag="$1" application="$2"; shift 2
  echo "  · $tag  ($application  $*)"
  blind --json bench "${application}@local" --seed "$SEED" "$@" > "$RAW/${tag}.json"
}
