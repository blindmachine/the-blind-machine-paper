# Appendix: Public-Real-DNA Experiments

These optional experiments use public IGSR/1000 Genomes Phase 3 data. They are not part of the no-real-data synthetic reproducibility harness; they demonstrate that the same application-governed workflow can be run on public human genotype data while committing only aggregate outputs.

## Summary Table

| Experiment | Samples | Variants/queries | Application | Primary result | Evidence page |
|---|---:|---:|---|---|---|
| E5 AF panel | 10 | 12 | allele_frequency_count; allele_frequency_with_variance | exact first/second moments; mean abs AF delta vs IGSR global 0.0609 | (local run; artifacts under real_human_dna_igsr_2026_07_09/results) |
| E6 AF/FST panel | 50 | 24 | allele_frequency_count; allele_frequency_with_variance | max FST-like=0.1363; suppressed rows=624 | https://blindmachine.org/verify/paper/public-genomics-e6-af-fst |
| E7 Beacon policy | 25 | 40 | allele_frequency_count plus release-policy harness | adjacent N=25 vs 24 release-risk comparison | https://blindmachine.org/verify/paper/public-genomics-e7-beacon-policy |
| E8 LD window | 25 | 11 | genotype_pair_ld draft application | max r2=1.0000; exact moments match oracle | https://blindmachine.org/verify/paper/public-genomics-e8-ld-window |

## Figures

- `results/figure_e5_af_concordance.svg` plots the E5 encrypted panel allele frequency against the IGSR global frequency (concordance vs a y=x line).
- `results/figure_beacon_policy_recovery.svg` shows the fraction of the 40 dosage positions recovered exactly under each release policy.
- `results/figure_ld_top_r2.svg` shows the strongest adjacent-pair LD `r2` values, with small-count artifacts flagged.

## Boundaries

- Individual VCF slices, sample lists, raw vectors, and attack traces remain in ignored `work/` directories.
- The public evidence URLs under `/verify/paper/...` are paper evidence packages, not hosted private-cohort computation certificates.
- The hosted `/verify/:certificate_hash` status is `not_published` for all three local runs.
- These small public panels are workflow demonstrations, not clinical results or population estimates.
