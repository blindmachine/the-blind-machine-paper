#!/usr/bin/env bash
# Optional real-human-DNA study.
#
# This is intentionally NOT part of run_all.sh: the core paper harness is
# no-network/no-real-data, while this study downloads public IGSR/1000 Genomes
# VCF slices and writes aggregate-only results.
set -euo pipefail

EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$EXP_DIR/real_human_dna_igsr_2026_07_09/run_study.py"
