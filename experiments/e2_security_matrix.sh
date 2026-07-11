#!/usr/bin/env bash
# E2 — the security-level matrix (draft §5, Table 6). Each application is
# benchmarked at all three HomomorphicEncryption.org security levels at one cohort
# point (N=20, L=10). Every cell must stay bit-exact; the counterintuitive result
# the paper reports is that at a FIXED ring degree a HIGHER security level yields a
# SMALLER ciphertext (only the coefficient-modulus band shrinks).
#
# Slower than E1 (18 cells). Part of the `full` profile.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

echo "[E2] security-level matrix — six applications × {128,192,256}, N=20 L=10, seed $SEED"
for p in "${APPLICATIONS[@]}"; do
  bench_cell "e2__$p" "$p" --sweep "security=128,192,256 n=20 length=10"
done
echo "[E2] done → results/raw/e2__*.json"
