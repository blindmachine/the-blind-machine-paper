#!/usr/bin/env bash
# E4 — the differencing demonstration (draft Figure 2). Runs the K-vs-K+1
# differencing attack in simulation mode: on an UNFROZEN cohort, the difference of
# the aggregate over K+1 contributors and the aggregate over K contributors
# recovers one individual's exact contribution. This is the concrete evidence
# behind the paper's honest "differencing is MITIGATED, not solved" claim — and
# the fix it names (cohort freeze + min-N + run-cap) is emitted alongside.
#
# Cleartext-oracle based (no TenSEAL), so it is fast and needs no sealed env.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

echo "[E4] differencing demonstration — allele_frequency_count, N=50, seed 7 (attack seed)"
blind --json simulate allele_frequency_count@local --attack differencing --n 50 --seed 7 \
  > "$RAW/e4__differencing.json"
echo "[E4] done → results/raw/e4__differencing.json"
