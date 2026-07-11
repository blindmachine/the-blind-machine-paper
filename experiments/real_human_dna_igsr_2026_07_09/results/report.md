# Real Human DNA Allele-Frequency Study

- Source: IGSR/1000 Genomes Phase 3 release `20130502`
- Region: `22:16050000-17000000`
- Samples: 10 public sample IDs
- Variants: 12 biallelic SNPs polymorphic in the toy cohort
- Existing BlindMachine applications: `allele_frequency_count, allele_frequency_with_variance`

## Aggregate Frequencies

| # | Coordinate | Alt count | AF | IGSR global AF | Abs delta |
|---:|---|---:|---:|---:|---:|
| 1 | `22:16051249:T:C` | 4 | 0.2000 | 0.1124 | 0.0876 |
| 2 | `22:16052080:G:A` | 3 | 0.1500 | 0.1412 | 0.0088 |
| 3 | `22:16052962:C:T` | 3 | 0.1500 | 0.0938 | 0.0562 |
| 4 | `22:16052986:C:A` | 1 | 0.0500 | 0.0741 | 0.0241 |
| 5 | `22:16053444:A:T` | 1 | 0.0500 | 0.0719 | 0.0219 |
| 6 | `22:16053659:A:C` | 15 | 0.7500 | 0.8576 | 0.1076 |
| 7 | `22:16053791:C:A` | 5 | 0.2500 | 0.1659 | 0.0841 |
| 8 | `22:16053862:C:T` | 4 | 0.2000 | 0.1146 | 0.0854 |
| 9 | `22:16053863:G:A` | 3 | 0.1500 | 0.1404 | 0.0096 |
| 10 | `22:16054454:C:T` | 4 | 0.2000 | 0.1158 | 0.0842 |
| 11 | `22:16054740:A:G` | 7 | 0.3500 | 0.4956 | 0.1456 |
| 12 | `22:16055070:G:A` | 3 | 0.1500 | 0.1348 | 0.0152 |

## Additional Analyses

- `group_frequencies.csv` reports toy subgroup rows by 1000 Genomes super-population and reported sex, with allele counts suppressed when `n < 5`.
- `genotype_distribution.csv` reports homozygous-reference, heterozygous, homozygous-alt, and missing-call counts.
- `blindmachine_results.json` records the exact first moment from `allele_frequency_count` and the exact first/second moments from `allele_frequency_with_variance`.

Summary statistics:

- Mean absolute delta vs IGSR global AF: 0.0609
- Mean heterozygote rate across selected variants: 0.3083
- Mean dosage variance across selected variants: 0.2542

## Validation

- Cleartext aggregate matched `allele_frequency_count` output exactly.
- `allele_frequency_with_variance` produced the same first moment and exact second moments.
- Per-sample genotype vectors were written only under ignored `work/`.

## Interpretation Boundary

These are toy workflow frequencies over ten public samples. They are not medical claims and not population estimates.
