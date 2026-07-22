#!/usr/bin/env bash
# E10 — Reproduce Duality's Chi-Square GWAS (Blatt et al., PNAS 2020) on The Blind
# Machine's `gwas_chi_square` application. Runs the full trust loop on a seeded
# synthetic case/control cohort (default N=200 x M=16,384 — the shape of Duality's
# public data/random_sample.csv) and asserts the decrypted allelic chi-square GWAS
# is BIT-IDENTICAL to the cleartext GWAS (the paper reports R^2=1.00; here it is
# bit-exact). Point it at Duality's own CSV with BLIND_GWAS_CSV=/path/random_sample.csv.
# SKIPs (exit 3) if the bundle or TenSEAL runtime is absent (see run_study.py).
set -euo pipefail

EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$EXP_DIR/gwas_chi_square_pnas2020_2026_07_17/run_study.py"
