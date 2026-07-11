#!/usr/bin/env bash
# E3 — feasibility support for the flagship additive application and camera-ready
# feasibility curves: allele_frequency_count swept over cohort size N and coordinate length L.
# The paper's claims this validates: server-compute scales ~linearly in N and is
# ~flat in L (BFV packs L<=8191 coordinates into one ciphertext), and ciphertext
# size is set by the ring, not by L.
#
# The DEFAULT grid is deliberately small (N<=100) so the harness finishes quickly.
# Set FULL_GRID=1 for the paper's full N∈{20,100,1000} sweep (minutes: each
# contributor's encrypt is a fresh TenSEAL-importing subprocess — a harness cost,
# not a crypto one; the isolated server-compute stays ~1 ms/contributor).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "${FULL_GRID:-0}" = "1" ]; then
  GRID="n=20,100,1000 length=10,100"
else
  GRID="n=20,100 length=10,100"
fi

echo "[E3] feasibility sweep — allele_frequency_count, $GRID, 128-bit, seed $SEED"
bench_cell "e3__afc" allele_frequency_count --sweep "$GRID"
echo "[E3] done → results/raw/e3__afc.json"
