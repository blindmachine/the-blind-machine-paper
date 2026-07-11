# Real Human DNA Allele-Frequency Study - IGSR/1000 Genomes Phase 3

This optional study uses public human genotype data from the International Genome
Sample Resource (IGSR) / 1000 Genomes Project Phase 3 release `20130502`.

It is deliberately separate from `run_all.sh`. The main paper experiments remain
offline, synthetic, and no-real-data. This study is a demonstration workflow for
real, public-consented human DNA data with aggregate-only outputs.

## Source

- Release directory: <https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502/>
- VCF: `ALL.chr22.phase3_shapeit2_mvncall_integrated_v5b.20130502.genotypes.vcf.gz`
- Sample panel: `integrated_call_samples_v3.20130502.ALL.panel`
- IGSR data notes: <https://www.internationalgenome.org/data/>
- IGSR reuse/disclaimer: <https://www.internationalgenome.org/IGSR_disclaimer/>

The runner selects two samples from each 1000 Genomes super-population, then
queries a small chr22 interval and keeps the first biallelic SNPs that are
polymorphic in the selected ten-sample toy cohort.

## Run

From the repo root:

```bash
bash docs/paper/experiments/e5_real_human_dna_igsr.sh
```

Requirements:

- `bcftools`
- network access to the IGSR FTP/HTTP endpoint
- Python 3.11+
- TenSEAL available in the local Python environment, or the existing app envs
  already materialized as they are in this checkout

## Outputs

Tracked aggregate outputs are written under `results/`:

- `allele_frequencies.csv` - overall ten-sample aggregate allele frequencies.
- `group_frequencies.csv` - toy subgroup allele frequencies by super-population
  and reported sex, with small cells suppressed.
- `genotype_distribution.csv` - per-variant genotype counts.
- `blindmachine_results.json` - aggregate-only results from the existing
  `allele_frequency_count` and `allele_frequency_with_variance` applications.
- `provenance.json` - source URLs, region, selected sample IDs, tool versions,
  hashes, and ethical boundary notes.
- `report.md` - concise study report.

Per-sample genotype vectors and the subset VCF are written only to `work/`, which
is ignored. Do not commit `work/`; it contains public but individual-level human
genotype rows.

Subgroup allele counts are suppressed when `n < 5`, because two-person subgroup
aggregates can reconstruct individual genotypes even when the underlying data is
publicly available.

## Boundary

This is not a population-genetics finding and not a medical interpretation. With
only ten public samples, the estimates are toy workflow outputs. The useful claim
is that the BlindMachine allele-frequency applications can run over real
human-genotype dosage vectors while keeping the committed paper artifact
aggregate-only.
