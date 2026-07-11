# Beacon Release-Policy Experiment

- Source: IGSR/1000 Genomes Phase 3 `20130502`
- Region: `22:16050000-17250000`
- Cohorts compared: N=25 versus adjacent N=24
- Variants: 40 complete-call biallelic SNPs
- Paper evidence URL: <https://blindmachine.org/verify/paper/public-genomics-e7-beacon-policy>

## Main Result

| Policy | Adjacent releases? | Query budget | Recovery rate | Nonzero recovery |
|---|---:|---:|---:|---:|
| no_policy_exact_adjacent_counts | True | 40 | 1.000 | 1.000 |
| min_n_20_only | True | 40 | 1.000 | 1.000 |
| min_n_25_blocks_adjacent_base | False | 0 | 0.000 | 0.000 |
| cohort_freeze_single_release | False | 0 | 0.000 | 0.000 |
| query_budget_5 | True | 5 | 0.125 | 0.167 |
| rounded_counts_to_nearest_5 | True | 40 | 0.850 | 0.000 |

Exact adjacent aggregate counts recover the held-out public sample's dosage vector by subtraction. A minimum-N floor only helps if it blocks adjacent releases; min-N alone does not protect against two comparable cohorts above the floor. Cohort freeze and query budgets are therefore release-governance controls, not crypto features.

## Validation

- `allele_frequency_count` matched cleartext counts for both adjacent cohorts.
- The exact-count difference matched the held-out target vector.
- Per-sample target traces were written only under ignored `work/`.

## Interpretation Boundary

This is a public-data release-policy demonstration. It does not identify a private person and does not publish the target sample's genotype trace.
