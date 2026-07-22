#!/usr/bin/env bash
# E9 — Reproduce a published FHE-PRS study (HEPRS, Knight et al. 2026) on The Blind
# Machine's `polygenic_score_inference` application. Runs on the HEPRS PUBLIC
# example (vendored, synthetic HAPGEN2) + a small synthetic scaling check, and
# asserts bit-exactness + reproduction of HEPRS's published predictions. SKIPs
# cleanly if the bundle or TenSEAL runtime is absent (see run_study.py).
set -euo pipefail

EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$EXP_DIR/heprs_prs_reproduction_2026_07_17/run_study.py"
