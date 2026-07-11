# The Blind Machine — paper replication materials

Everything needed to independently reproduce the empirical claims in
*The Blind Machine* paper. This repository is the **canonical, tagged, and
Zenodo-archived** replication package: `git clone`, `git checkout` the paper's
tag, and run one command.

The design thesis of the paper is *verify, don't trust us* — so these materials
survive independent of our server. The synthetic experiments (E1–E4) run with
**zero** dependency on any hosted service; the real-human-DNA studies (E5–E8)
fetch authentic bytes straight from the authoritative public source.

- **Tool** (open CLI): https://github.com/blindmachine/blind
- **This repo** (replication): https://github.com/blindmachine/the-blind-machine-paper
- **Paper text**: https://blindmachine.org/papers/the-blind-machine

Snapshot assembled: 2026-07-11T06:44:49Z

---

## Two tiers of replication

| Tier | What it proves | Needs |
|------|----------------|-------|
| **Tier 1 — smoke** | the open CLI installs a signed application, seals an env, simulates a run, verifies by re-execution | just the `blind` CLI (the tool repo above) |
| **Tier 2 — full E1–E8** | the paper's tables, end to end | this repo + `uv` + `python3` (the `blind` CLI is **vendored** at `./cli` — no separate clone); E5–E8 additionally need `curl`, `bcftools`, `tabix` |

Tier 2 is what this package delivers, and it is **self-contained**: the six signed
bundles and the `blind` CLI are vendored, so E1–E4 clone-and-run with **zero**
dependency on any hosted service. E1–E4 are fully deterministic (synthetic cohorts,
seeded, no network). E5–E8 are **aggregate-reproducible** from public IGSR 1000
Genomes data via `fetch_public_data.sh` — no human genotypes are shipped here — and
**SKIP cleanly** when `bcftools`/network is unavailable.

---

## One-command replication

```bash
# 1. Clone and pin to the paper's tag (replace <tag> with the release tag)
git clone https://github.com/blindmachine/the-blind-machine-paper
cd the-blind-machine-paper
git checkout <tag>

# 2. Run EVERY experiment (E1–E8) and print one PASS / SKIP / FAIL table
bash experiments/replicate_all.sh          # full E1–E8
bash experiments/replicate_all.sh fast     # skip the longer E2/E3 sweeps
```

`replicate_all.sh` seals the app envs, runs the synthetic harness (E1–E4), fetches
the bounded public genome slices, runs the real-DNA studies (E5–E8), and prints one
summary table. It exits non-zero **only** if a deterministic experiment produced a
wrong result. The E5–E8 studies **SKIP cleanly** (not FAIL) when a prerequisite is
missing (no `bcftools`/`tabix`, no network, or the draft E8 bundle). The studies run
under whichever interpreter has TenSEAL — if the launching `python3` lacks it, they
transparently re-exec into a sealed application env, so no manual venv step is needed.

### Running the pieces individually

```bash
# Synthetic core only (E1 + E4; add `full` for E2 + E3), then verify:
bash experiments/run_all.sh          # fast profile   ~2-4 min
bash experiments/run_all.sh full     # full  profile  ~15-25 min
python3 experiments/verify.py        # prints RESULT: PASS on success

# Real-human-DNA studies (E5–E8): fetch a bounded chr22 window (no genotypes shipped)
bash experiments/fetch_public_data.sh          # panel + union-region slice (a few MB)
bash experiments/fetch_public_data.sh --full   # or the whole chr22 VCF (~205 MB)
bash experiments/e5_real_human_dna_igsr.sh
bash experiments/e6_public_af_fst_panel.sh
bash experiments/e7_beacon_release_policy.sh
bash experiments/e8_public_ld_window.sh        # uses the draft `genotype_pair_ld` bundle
```

Requirements for E5–E8: `curl`, `bcftools`, `tabix`. The download lands under the
git-ignored `experiments/data/1000genomes/` cache and is checksummed. See
`experiments/DATA_SOURCES.md` for the exact pinned source, region windows, and
sample panels.

---

## What's in here

```
the-blind-machine-paper/
  README.md            # this file
  LICENSE              # MIT
  cli/                 # the vendored open `blind` CLI (so run_all/replicate_all are self-contained)
  applications/        # the 6 signed bundles (Ed25519, content-addressed) + the draft genotype_pair_ld (E8)
  experiments/         # e1..e8, run_all.sh, replicate_all.sh, verify.py, lib.sh, fetch_public_data.sh, DATA_SOURCES.md
  MANIFEST.sha256      # sha256 of every file in this snapshot
```

### Applications

The 6 curated BFV applications the experiments run against, each a
signed bundle (`.blind-signature` + `signed/`):

- `allele_frequency_count`
- `carrier_count`
- `cohort_histogram`
- `polygenic_score_aggregate`
- `allele_frequency_with_variance`
- `genotype_phenotype_covariance`

The experiments drive these bundles end-to-end (`00_keygen … 50_decode`) under
real TenSEAL on seeded synthetic cohorts, so nothing here contacts a hosted
service.

### Integrity

`MANIFEST.sha256` records a SHA-256 for every file placed in this snapshot.
Verify it with either tool:

```bash
cd the-blind-machine-paper
sha256sum   -c MANIFEST.sha256      # GNU coreutils
shasum -a 256 -c MANIFEST.sha256    # macOS / BSD
```

---

## Human-data policy

- **Committed:** analysis scripts, source pointers (`experiments/DATA_SOURCES.md`),
  aggregate results (per-variant / panel summary stats, provenance), and public
  sample-ID lists.
- **Never committed:** individual genotypes — no genotype VCFs, no per-sample
  dosage vectors, no subset alignments. Study `work/` directories and the
  `data/1000genomes/` cache are git-ignored.

Pointing at the authoritative IGSR source rather than redistributing genomes is
better on both counts: reviewers get authentic, checksummed bytes from the
original, and no human genetic data ever lives in this repository.

---

## License

MIT — see `LICENSE`. (The reference worker and the `blind` CLI tool are likewise
MIT.)
