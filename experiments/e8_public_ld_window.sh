#!/usr/bin/env bash
# Optional public-real-DNA LD/covariance experiment.
set -euo pipefail

EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$EXP_DIR/public_ld_window_2026_07_09/run_study.py"
