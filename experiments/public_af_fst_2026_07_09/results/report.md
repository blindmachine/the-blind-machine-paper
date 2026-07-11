# Public IGSR Cross-Population AF/FST-ish Panel

- Source: IGSR/1000 Genomes Phase 3 release `20130502` (GRCh37)
- Region: `22:16050000-17000000`
- Samples: 50 public samples selected by deterministic rule
- Variants: 24 biallelic SNPs selected for source super-population AF range >= 0.15
- Reporting floor: suppress group count/frequency fields when `n < 10`
- Existing BlindMachine applications used locally: `allele_frequency_count`, `allele_frequency_with_variance`

## Outputs

- `allele_panel.csv`: aggregate panel frequencies, source AF deltas, dosage variance, and per-variant FST-ish summaries.
- `group_frequencies.csv`: super-population rows plus suppressed population-level small cells.
- `fst_summary.csv`: per-variant equal-weight `(H_T - mean(H_S)) / H_T` across super-populations.
- `blindmachine_results.json`: decoded local BlindMachine application outputs plus signed pure-function equivalence checks.
- `verification.json`: local verification command and honest hosted publication status.

## Highest FST-ish Variants

| # | Coordinate | Panel AF | Max delta | Min group | Max group | FST-ish | IGSR FST-ish |
|---:|---|---:|---:|---|---|---:|---:|
| 19 | `22:16067208:C:G` | 0.6500 | 0.4500 | AMR 0.4500 | EAS 0.9000 | 0.1363 | 0.0604 |
| 2 | `22:16052080:G:A` | 0.1600 | 0.3000 | AFR 0.0500 | EAS 0.3500 | 0.1071 | 0.0440 |
| 8 | `22:16055070:G:A` | 0.1500 | 0.3000 | AFR 0.0500 | EAS 0.3500 | 0.1020 | 0.0475 |
| 4 | `22:16053659:A:C` | 0.8000 | 0.3000 | EUR 0.6500 | AFR 0.9500 | 0.1000 | 0.0371 |
| 22 | `22:16069141:C:G` | 0.6600 | 0.4000 | AMR 0.5000 | EAS 0.9000 | 0.0998 | 0.0640 |
| 17 | `22:16063369:C:T` | 0.1100 | 0.2500 | EUR 0.0000 | SAS 0.2500 | 0.0960 | 0.0712 |
| 1 | `22:16051249:T:C` | 0.1200 | 0.2500 | AFR 0.0000 | SAS 0.2500 | 0.0814 | 0.0766 |
| 20 | `22:16067411:T:C` | 0.1300 | 0.2500 | AFR 0.0000 | EAS 0.2500 | 0.0760 | 0.0874 |

## Summary

- Mean absolute delta vs IGSR global AF: 0.0311
- Mean panel FST-ish value: 0.0611
- Max panel FST-ish value: 0.1363
- Suppressed small-cell group rows: 624

## Validation

- Local encrypted `allele_frequency_count` output matched cleartext alternate-allele counts exactly.
- Local encrypted `allele_frequency_with_variance` output matched cleartext first and second moments exactly.
- Signed pure server aggregate functions were also imported and checked for each reported super-population group.
- Per-sample genotype vectors, the selected sample list, and the subset VCF were written only under ignored `work/`.

## Hosted Verification

`blindmachine.org` publication status is `not_published`: this local run did not have hosted verification credentials or a server-side publication target. Reproduce locally with:

```bash
bash docs/paper/experiments/e6_public_af_fst_panel.sh && python3 -m json.tool docs/paper/experiments/public_af_fst_2026_07_09/results/provenance.json >/dev/null && python3 -m json.tool docs/paper/experiments/public_af_fst_2026_07_09/results/blindmachine_results.json >/dev/null && python3 -m json.tool docs/paper/experiments/public_af_fst_2026_07_09/results/verification.json >/dev/null
```

## Interpretation Boundary

This is a deterministic public-data workflow panel, not a clinical result and not a population-genetics estimate. The FST-ish statistic is an equal-weight heterozygosity contrast over a small selected sample panel.
