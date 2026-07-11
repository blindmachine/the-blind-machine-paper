#!/usr/bin/env bash
# Optional public-real-DNA Beacon/release-policy experiment.
set -euo pipefail

EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$EXP_DIR/beacon_release_policy_2026_07_09/run_study.py"
