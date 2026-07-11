#!/usr/bin/env bash
# fetch_public_data.sh — pre-stage the public genome data used by the optional
# real-human-DNA studies (E5-E8) of The Blind Machine paper.
#
# WHAT IT DOES
#   Downloads, from the authoritative public source (IGSR / 1000 Genomes Project
#   phase 3, GRCh37 — the exact source the studies use), only what E5-E8 read:
#     1. the sample panel (population labels), and
#     2. a bounded chr22 slice — the UNION of every study's window — bgzip-
#        compressed and tabix-indexed.
#   Both land under a git-ignored cache (data/1000genomes/) and are checksummed
#   into DATA_MANIFEST.json. No individual genotype is ever committed: this cache
#   is git-ignored by design (see the paper's human-data policy / DATA_SOURCES.md).
#
# WHY A SLICE, NOT THE WHOLE GENOME
#   Every E5-E8 study queries a bounded chr22 window inside
#   22:16,050,000-17,250,000. Mirroring just that union interval (a few MB) IS the
#   honest "all public genomes necessary": it is a faithful superset — re-querying
#   it locally with each study's sample list + allele-frequency filter returns the
#   identical variants the remote query would. Pass --full to mirror the entire
#   chr22 VCF (~205 MB) instead.
#
# OFFLINE RUNS (optional)
#   After a successful fetch, export the printed BLIND_1000G_VCF (slice mode) or
#   BLIND_1000G_DIR (--full mode). Studies that use the shared helper (E7, E8) then
#   read bytes locally with no network. Each study's provenance still records the
#   canonical remote URL — only where bcftools reads bytes from changes.
#
# REQUIREMENTS: curl, bcftools, tabix (htslib).
#   macOS:  brew install bcftools htslib
#   Debian: apt-get install -y bcftools tabix
set -euo pipefail

# --- pinned public sources (MUST match public_genomics_common.py) ------------
BASE_URL="https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502"
PANEL_URL="$BASE_URL/integrated_call_samples_v3.20130502.ALL.panel"
CHR22_VCF_URL="$BASE_URL/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5b.20130502.genotypes.vcf.gz"
GENOME_BUILD="GRCh37"
# Union of E5-E8 windows: E5/E6 16.05-17.00Mb, E7 16.05-17.25Mb, E8 16.05-16.90Mb.
UNION_REGION="22:16050000-17250000"

EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$EXP_DIR/data/1000genomes"
MANIFEST="$CACHE_DIR/DATA_MANIFEST.json"
PANEL="$CACHE_DIR/integrated_call_samples_v3.20130502.ALL.panel"
SLICE="$CACHE_DIR/1000g_phase3_chr${UNION_REGION//[:-]/_}.snps.vcf.gz"
FULL_VCF="$CACHE_DIR/$(basename "$CHR22_VCF_URL")"

MODE="slice"; FORCE="0"

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<EOF

Usage: bash fetch_public_data.sh [--full] [--force] [-h|--help]
  --full    mirror the entire chr22 VCF (~205 MB) instead of the union-region slice
  --force   re-download even if a cached copy already exists
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --full) MODE="full" ;;
    --force) FORCE="1" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required tool '$1' not found. $2" >&2; exit 127; }; }
sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else sha256sum "$1" | awk '{print $1}'; fi
}

echo "The Blind Machine — public genome pre-fetch ($MODE mode)"
need curl "Install curl."
need bcftools "Install bcftools (brew install bcftools / apt-get install bcftools)."
need tabix "Install htslib/tabix (brew install htslib / apt-get install tabix)."
echo "  curl:     $(curl --version | head -1)"
echo "  bcftools: $(bcftools --version | head -1)"
echo "  tabix:    $(tabix --version 2>&1 | head -1)"
mkdir -p "$CACHE_DIR"

# 1) sample panel (authoritative bytes — stable sha256) ------------------------
if [ "$FORCE" = "1" ] || [ ! -s "$PANEL" ]; then
  echo "· fetching sample panel"
  curl -L --fail --silent --show-error -o "$PANEL" "$PANEL_URL"
else
  echo "· panel already cached (use --force to refetch)"
fi

# 2) genotypes ----------------------------------------------------------------
if [ "$MODE" = "full" ]; then
  if [ "$FORCE" = "1" ] || [ ! -s "$FULL_VCF" ]; then
    echo "· fetching FULL chr22 VCF (~205 MB, resumable)"
    curl -L --fail --show-error --continue-at - -o "$FULL_VCF" "$CHR22_VCF_URL"
  else
    echo "· full chr22 VCF already cached (use --force to refetch)"
  fi
  echo "· fetching / building tabix index"
  curl -L --fail --silent --show-error --continue-at - -o "$FULL_VCF.tbi" "$CHR22_VCF_URL.tbi" \
    || tabix -f -p vcf "$FULL_VCF"
  DATA_FILE="$FULL_VCF"
  REGION_LABEL="whole-chr22"
  DATA_NOTE="authoritative bytes; sha256 is stable across environments"
else
  if [ "$FORCE" = "1" ] || [ ! -s "$SLICE" ]; then
    echo "· fetching chr22 union-region slice $UNION_REGION (remote bcftools range query)"
    # All samples, biallelic SNPs, NO allele-frequency filter → faithful superset.
    bcftools view --no-version -r "$UNION_REGION" -m2 -M2 -v snps "$CHR22_VCF_URL" -Oz -o "$SLICE"
    tabix -f -p vcf "$SLICE"
  else
    echo "· region slice already cached (use --force to refetch)"
  fi
  DATA_FILE="$SLICE"
  REGION_LABEL="$UNION_REGION"
  DATA_NOTE="derived slice; sha256 depends on the bcftools/bgzip build — informational, not a paper invariant"
fi

# 3) validate + checksum + manifest -------------------------------------------
echo "· validating with bcftools"
bcftools view -h "$DATA_FILE" >/dev/null
VARIANTS="$(bcftools view -H "$DATA_FILE" | wc -l | tr -d ' ')"
PANEL_SHA="$(sha256 "$PANEL")"
DATA_SHA="$(sha256 "$DATA_FILE")"

cat > "$MANIFEST" <<JSON
{
  "generated_by": "fetch_public_data.sh",
  "mode": "$MODE",
  "genome_build": "$GENOME_BUILD",
  "source": "IGSR / 1000 Genomes Project phase 3",
  "source_base_url": "$BASE_URL",
  "panel": {
    "url": "$PANEL_URL",
    "path": "${PANEL#"$EXP_DIR"/}",
    "sha256": "$PANEL_SHA",
    "note": "authoritative bytes; sha256 is stable across environments"
  },
  "genotypes": {
    "canonical_url": "$CHR22_VCF_URL",
    "region": "$REGION_LABEL",
    "path": "${DATA_FILE#"$EXP_DIR"/}",
    "sha256": "$DATA_SHA",
    "variant_records": $VARIANTS,
    "note": "$DATA_NOTE"
  }
}
JSON

echo
echo "Done. Cached under ${CACHE_DIR#"$EXP_DIR"/}/  (git-ignored — never committed)"
echo "  panel:     $PANEL_SHA"
echo "  genotypes: $DATA_SHA  ($VARIANTS variant records)"
echo "  manifest:  ${MANIFEST#"$EXP_DIR"/}"
echo
echo "Optional — run the shared-helper studies (E7, E8) fully offline against this mirror:"
if [ "$MODE" = "full" ]; then
  echo "  export BLIND_1000G_DIR=\"$CACHE_DIR\""
else
  echo "  export BLIND_1000G_VCF=\"$SLICE\""
fi
echo "  bash e7_beacon_release_policy.sh && bash e8_public_ld_window.sh"
