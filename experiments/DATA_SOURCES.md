# Public genome data — sources & policy (E5–E8)

The optional real-human-DNA studies (E5–E8) do **not** ship human genotypes. They
ship the analysis scripts, exact **pointers** to the authoritative public source,
and **aggregate** expected results. Reviewers fetch the data themselves from the
original source — automated by `fetch_public_data.sh`.

## Authoritative source (pinned)

| | |
|---|---|
| Project | IGSR / 1000 Genomes Project, **phase 3** |
| Genome build | **GRCh37** |
| Base URL | `https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502` |
| Sample panel | `…/integrated_call_samples_v3.20130502.ALL.panel` |
| Genotypes (chr22) | `…/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5b.20130502.genotypes.vcf.gz` |
| Access date | 2026-07-09 |

These constants are mirrored in `public_genomics_common.py`; keep the two in sync.

## What each study reads

Every study takes a bounded **chr22** window and keeps the first *N* complete-call
biallelic SNPs inside a global-AF band, choosing samples in fixed super-population
order (EUR, EAS, AMR, AFR, SAS):

| Study | Script | Region | Global-AF band | Samples/super-pop | Variants |
|-------|--------|--------|----------------|-------------------|----------|
| E5 real human DNA (IGSR) | `e5_real_human_dna_igsr.sh` | `22:16050000-17000000` | 0.05–0.95 | 2 (10) | 12 |
| E6 AF / FST panel | `e6_public_af_fst_panel.sh` | `22:16050000-17000000` | 0.05–0.95 | 10 (50) | 24 |
| E7 Beacon / release policy | `e7_beacon_release_policy.sh` | `22:16050000-17250000` | 0.02–0.60 | 5 (25) | 40 |
| E8 LD window | `e8_public_ld_window.sh` | `22:16050000-16900000` | 0.05–0.95 | 5 (25) | 12 |

The union of all windows is **`22:16050000-17250000`** — that is exactly what the
prefetch mirrors by default.

## Fetching the data

```bash
bash docs/paper/experiments/fetch_public_data.sh          # panel + union-region slice (a few MB)
bash docs/paper/experiments/fetch_public_data.sh --full   # or the whole chr22 VCF (~205 MB)
```

Requirements: `curl`, `bcftools`, `tabix`. The download lands under the git-ignored
`data/1000genomes/` cache and is checksummed into `DATA_MANIFEST.json`. The
union-region slice is a faithful **superset**: re-querying it locally with a
study's sample list + AF filter returns the identical variants the remote query
would, so results are unchanged.

### Optional: run offline against the mirror

After a fetch, export the printed variable and the shared-helper studies (E7, E8)
read bytes locally with no network:

```bash
export BLIND_1000G_VCF="…/data/1000genomes/1000g_phase3_chr22_16050000_17250000.snps.vcf.gz"
bash docs/paper/experiments/e7_beacon_release_policy.sh
```

Provenance still records the canonical remote URL; only the byte source changes.
(E5/E6 currently fetch their bounded slice directly at runtime — wiring them to the
same `BLIND_1000G_*` variables is a one-line follow-up.)

## Human-data policy (enforced)

- **Committed:** scripts, source pointers (this file), aggregate results
  (per-variant/panel summary stats, provenance), and the public sample-ID lists.
- **Never committed:** individual genotypes — no genotype VCFs, no per-sample
  dosage vectors, no subset alignments. Study `work/` directories and the
  `data/1000genomes/` cache are git-ignored.

Pointing at the authoritative source (rather than redistributing genomes) is
better on both counts: reviewers get the authentic, checksummed bytes from IGSR,
and no human genetic data ever lives in our repository.

## E9 — HEPRS reproduction (vendored public example)

E9 is different from E5–E8: it reproduces a **published FHE-PRS study** (Knight et
al. 2026, HEPRS) rather than querying IGSR. Its data is the HEPRS repository's own
**public example** — **synthetic** genotypes generated with HAPGEN2, MIT-licensed —
which we vendor **unmodified** under
`heprs_prs_reproduction_2026_07_17/example_data/` (with HEPRS's `HEPRS_LICENSE`
alongside). Because it is synthetic and openly licensed, it is safe to commit and
E9 runs fully offline. Provenance and the exact reproduction claim are in
[`heprs_prs_reproduction_2026_07_17/PROVENANCE.md`](heprs_prs_reproduction_2026_07_17/PROVENANCE.md).

HEPRS's headline **real** result (110,258-SNP schizophrenia model on 1,146
PsychENCODE individuals) uses **controlled-access** genotypes that are **not**
redistributed. E9 reproduces the public example exactly, runs a synthetic
HAPGEN2-style scaling sweep at matched sizes, and **cites** HEPRS's real-data
accuracy — the same human-data policy as E5–E8: no controlled data in the repo.
