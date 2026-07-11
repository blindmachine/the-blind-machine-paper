# Reproducible experiments — The Blind Machine bioRxiv paper

**Everything (E1-E8) in one command, with a single PASS / SKIP / FAIL table:**

```bash
bash replicate_all.sh          # E1-E4 synthetic (offline, deterministic) + E5-E8 real-DNA
bash replicate_all.sh fast     # skip the longer E2/E3 sweeps
```

`replicate_all.sh` runs the synthetic harness, fetches the bounded public genome
slices, runs the four real-DNA studies, and prints one summary table. It exits
non-zero **only** if a deterministic experiment produced a wrong result; the E5-E8
studies **SKIP cleanly** (not FAIL) when a prerequisite is missing (no
`bcftools`/`tabix`, no network, an unsealed env, or the absent draft E8 bundle). The
studies auto-run under a TenSEAL-capable interpreter — if the launching `python3`
lacks TenSEAL they transparently re-exec into a sealed application env.

**Just the synthetic core — no server, no real data, ~90 seconds:**

```bash
bash run_all.sh            # fast: E1 (exactness taxonomy) + E4 (differencing)
bash run_all.sh full       # + E2 (security matrix) + E3 (feasibility sweep)
```

On success it prints `RESULT: PASS` and writes paper-facing CSV tables to
`results/`. On any regression in bit-exactness, the two-tier taxonomy, the payload
premium, or the differencing recovery it prints `RESULT: FAIL` and exits non-zero.

Everything here runs **entirely in the tool, in simulation mode**: `blind bench`
and `blind simulate` drive the real, signed application bundles end-to-end (the six
numbered stages `00_keygen … 50_decode`) under **real TenSEAL BFV** on **seeded
synthetic cohorts**, in a local sandbox. The hosted `blindmachine.org` service is
**never contacted**, no network is used at run time, and **no real genomic or
medical data exists** — so a reviewer reproduces every table with zero IRB,
zero data-use agreement, and zero access to the hosted service.

## Why this is reproducible

- **Deterministic synthetic data.** Cohorts are drawn under Hardy–Weinberg
  equilibrium and are bit-for-bit determined by `(seed, N, L)`. The seed is fixed
  at **42** (the differencing attack uses seed 7, as in the paper).
- **Content-addressed, sealed bundles.** Each application brings its own pinned
  environment (`env/uv.lock`, `.python-version`) sealed with `uv`; `setup.sh`
  materializes it once. The crypto is TenSEAL 0.3.16 over Microsoft SEAL.
- **Machine-independent invariants are asserted; hardware-dependent numbers are
  only reported.** `verify.py` asserts exactness (`max_error == 0`), the taxonomy,
  the payload-premium direction, the differencing recovery, and — as INV-6 —
  equality of the deterministic columns against the committed
  `results/expected/*.json` reference values (the 128-bit ciphertext sizes and
  feasibility sizes), so those reference files are asserted invariants, not
  silently-drifting documentation. Only the 128-bit ciphertext sizes are
  byte-stable; the 192/256-bit sizes vary by tens of bytes across TenSEAL builds,
  so they are reported, not asserted. Wall-clock, RAM, and cost are recorded but
  **not** asserted (they vary by hardware; the paper reports them with that caveat).

## What each experiment proves (→ which paper artifact)

| Script | Proves | Paper artifact |
|---|---|---|
| `e1_exactness_taxonomy.sh` | All six applications are bit-exact against the cleartext oracle; 4 additive-BFV + 2 multiplication-supporting-BFV; the additive/variance/covariance **payload premium** | Draft Table 4; payload source data for Table 5 |
| `e2_security_matrix.sh` | Every application stays bit-exact at 128/192/256-bit; stronger security → smaller ciphertext at fixed ring degree | Draft Table 6 |
| `e3_feasibility.sh` | `allele_frequency_count` server-compute scales ~linearly in N and is ~flat in L; ciphertext size is ring-set, not L-set | Camera-ready feasibility-curve source |
| `e4_differencing.sh` | K-vs-K+1 differencing recovers one contributor **exactly** on an *unfrozen* cohort — the honest "mitigated, not solved" evidence, with the freeze + min-N + run-cap fix | Draft Figure 2 |

## Optional real-human-DNA study

`e5_real_human_dna_igsr.sh` is an explicit opt-in study using public
IGSR/1000 Genomes Phase 3 VCF data:

```bash
bash e5_real_human_dna_igsr.sh
```

It is not part of `run_all.sh` because it has different assumptions: it uses the
network, queries public human genotype rows, and writes individual-level
intermediates under an ignored `work/` directory. Its committed outputs live
under `real_human_dna_igsr_2026_07_09/results/` and are aggregate-only.

## Optional public-real-DNA experiment appendices

The following opt-in experiments extend E5 into three paper-facing
public-genomics demonstrations. They are not part of `run_all.sh` because they
use the network and real public human genotype rows. Each keeps individual-level
material under an ignored `work/` directory and commits aggregate-only outputs.

| Script | Demonstrates | Result directory | Paper evidence page |
|---|---|---|---|
| `e6_public_af_fst_panel.sh` | 50-sample public 1000 Genomes AF, variance, group suppression, and FST-like summaries using existing allele apps | `public_af_fst_2026_07_09/results/` | `https://blindmachine.org/verify/paper/public-genomics-e6-af-fst` |
| `e7_beacon_release_policy.sh` | Beacon-style adjacent-release risk and why min-N/freeze/query budgets matter after encrypted computation | `beacon_release_policy_2026_07_09/results/` | `https://blindmachine.org/verify/paper/public-genomics-e7-beacon-policy` |
| `e8_public_ld_window.sh` | Draft `genotype_pair_ld` encrypted-product application over adjacent public genotype pairs | `public_ld_window_2026_07_09/results/` | `https://blindmachine.org/verify/paper/public-genomics-e8-ld-window` |

Regenerate the appendix tables and SVG figure sources with:

```bash
python3 summarize_public_real_dna.py
```

This writes `public_real_dna_summary_2026_07_09/appendix.md` plus CSV/SVG
artifacts under `public_real_dna_summary_2026_07_09/results/`.

## Reference results (this machine: Apple-silicon, macOS arm64, TenSEAL 0.3.16)

At N=20, L=10, 128-bit, seed 42 — the **machine-independent** columns (committed at
`results/expected/table_b_reference.json`):

| Application | Tier | Crypto | ct / contribution | Exact? |
|---|---|---|---:|:--:|
| `allele_frequency_count` | additive-BFV-exact | bfv-add | 262,282 B (≈262 KB) | ✔ |
| `carrier_count` | additive-BFV-exact | bfv-add | 262,282 B | ✔ |
| `cohort_histogram` | additive-BFV-exact | bfv-add | 262,282 B | ✔ |
| `polygenic_score_aggregate` | additive-BFV-exact | bfv-add | 262,282 B | ✔ |
| `allele_frequency_with_variance` | mult-supporting-BFV-exact | bfv-mul | 1,310,882 B (≈1.31 MB, **5×**) | ✔ |
| `genotype_phenotype_covariance` | mult-supporting-BFV-exact | bfv-mul | 2,621,791 B (≈2.62 MB, **10×**) | ✔ |

Ciphertext sizes are **deterministic** (a reviewer reproduces these exact byte
counts); the **payload premium** of one multiplicative level is therefore **5×**
(variance) and **10×** (covariance) over the additive fold at 128-bit. The
*compute* premium (isolated server-compute CPU) is larger (≈10–19×) and is measured
by the in-process cross-check driver `../artifacts/measure_real_bench.py`, because
`blind bench`'s `cpu_seconds` bills the whole subprocess pipeline (dominated by
per-contributor TenSEAL re-import startup), not the isolated hosted stage.

## Files

- `setup.sh` — seal the six envs (`uv sync --frozen`) + install bundles into an
  offline, experiment-local `$BLIND_HOME` (`.blind-home/`, git-ignored).
- `e1..e4_*.sh` — the four experiments (above).
- `verify.py` — consolidate `results/raw/*.json` into `results/*.csv` and ASSERT
  the invariants; exit non-zero on any failure.
- `run_all.sh` — setup + synthetic experiments + verify, one command.
- `replicate_all.sh` — the full E1-E8 driver: run_all + fetch + E5-E8 + PASS/SKIP/FAIL table.
- `fetch_public_data.sh` — download the bounded public 1000 Genomes slices E5-E8 read
  (into a git-ignored `data/` cache); `DATA_SOURCES.md` pins the exact URLs/windows.
- `e5_real_human_dna_igsr.sh` … `e8_public_ld_window.sh` — the optional public-real-DNA
  studies (network + `bcftools`), separate from the no-network/no-real-data core.
- `public_genomics_common.py` — shared helpers for E5-E8 (layout-agnostic root,
  TenSEAL re-exec + clean SKIP, bounded VCF fetch).
- `lib.sh` — shared config (offline `blind` wrapper, seed, application lists,
  layout-agnostic `applications/` + `cli/` resolution).
- `results/expected/` — committed machine-independent reference values.

## Requirements

- [`uv`](https://docs.astral.sh/uv/) (the Python toolchain the bundles seal with)
  and Python 3.11+. No other setup — the sealed envs bring TenSEAL themselves.
- First run seals six envs (downloads TenSEAL once); subsequent runs reuse them.

## Cleaning up

```bash
rm -rf .blind-home results/raw results/*.csv   # everything generated; harness stays
```
