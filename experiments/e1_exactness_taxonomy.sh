#!/usr/bin/env bash
# E1 — the two-tier BFV exactness taxonomy (draft §5, Table 4) and payload-premium
# source data for Table 5. Runs all six curated applications end-to-end under real TenSEAL
# on a seeded N=20, L=10 synthetic cohort at 128-bit security, and records whether
# each decrypted aggregate is bit-identical to the cleartext oracle (max_error=0).
#
# Expected: 4 additive-BFV-exact + 2 multiplication-supporting-BFV-exact, all
# bit-exact. This is the paper's "additive suffices for 4 of 6" headline.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

echo "[E1] two-tier BFV exactness taxonomy — six applications, N=20 L=10, 128-bit, seed $SEED"
for p in "${APPLICATIONS[@]}"; do
  bench_cell "e1__$p" "$p" --n 20 --length 10 --security 128
done
echo "[E1] done → results/raw/e1__*.json"
