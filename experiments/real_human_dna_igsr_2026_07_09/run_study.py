#!/usr/bin/env python3
"""Run an aggregate-only allele-frequency study on public IGSR/1000G data.

The script keeps individual-level genotype material in work/ (git-ignored) and
writes only aggregate summaries to results/.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import math
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


STUDY_NAME = "real_human_dna_igsr_2026_07_09"
SUPER_POP_ORDER = ("EUR", "EAS", "AMR", "AFR", "SAS")
SAMPLES_PER_SUPER_POP = 2
VARIANT_COUNT = 12
REGION = "22:16050000-17000000"
MIN_GLOBAL_AF = 0.05
MAX_GLOBAL_AF = 0.95
MIN_REPORTABLE_GROUP_N = 5
STUDY_ACCESS_DATE = "2026-07-09"
GENOME_BUILD = "GRCh37"

BASE_URL = "https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502"
PANEL_URL = f"{BASE_URL}/integrated_call_samples_v3.20130502.ALL.panel"
VCF_URL = (
    f"{BASE_URL}/"
    "ALL.chr22.phase3_shapeit2_mvncall_integrated_v5b.20130502.genotypes.vcf.gz"
)

SCRIPT_PATH = Path(__file__).resolve()
STUDY_DIR = SCRIPT_PATH.parent
EXPERIMENTS_DIR = STUDY_DIR.parent
sys.path.insert(0, str(EXPERIMENTS_DIR))
from public_genomics_common import (  # noqa: E402
    DataUnavailable,
    ensure_bcftools,
    ensure_tenseal_runtime,
    find_repo_root,
)

REPO_ROOT = find_repo_root(STUDY_DIR)
RESULTS_DIR = STUDY_DIR / "results"
WORK_DIR = STUDY_DIR / "work"


@dataclass(frozen=True)
class Sample:
    sample_id: str
    population: str
    super_population: str
    gender: str


@dataclass(frozen=True)
class Variant:
    chrom: str
    pos: int
    variant_id: str
    ref: str
    alt: str
    info: dict[str, str]
    dosages: dict[str, int | None]

    @property
    def coordinate(self) -> str:
        return f"{self.chrom}:{self.pos}:{self.ref}:{self.alt}"

    @property
    def global_af(self) -> float | None:
        return parse_float(self.info.get("AF"))


def run(cmd: list[str], *, input_text: str | None = None, cwd: Path | None = None) -> str:
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DataUnavailable(f"required tool not found on PATH: {cmd[0]}") from exc
    if proc.returncode != 0:
        raise DataUnavailable(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr[-1200:]}"
        )
    return proc.stdout


def _mirror_dir() -> Path | None:
    directory = os.environ.get("BLIND_1000G_DIR")
    return Path(directory) if directory else None


def bcftools_source(vcf_url: str) -> str:
    """Physical byte source for bcftools: a locally staged public-data mirror when
    one is present (offline mode, staged by fetch_public_data.sh), otherwise the
    canonical remote URL. Set BLIND_1000G_VCF to a bgzipped+tabixed VCF, or
    BLIND_1000G_DIR to a directory holding <basename>. Provenance keeps recording
    the canonical remote URL — only where bytes are read from changes. With neither
    variable set, behaviour is byte-identical to a direct remote query."""
    explicit = os.environ.get("BLIND_1000G_VCF")
    if explicit and Path(explicit).is_file():
        return explicit
    directory = _mirror_dir()
    if directory is not None:
        candidate = directory / Path(vcf_url).name
        if candidate.is_file():
            return str(candidate)
    return vcf_url


def _mirror_panel_text() -> str | None:
    directory = _mirror_dir()
    if directory is None:
        return None
    candidate = directory / Path(PANEL_URL).name
    return candidate.read_text() if candidate.is_file() else None


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def parse_float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value.split(",")[0])
    except ValueError:
        return None


def parse_info(field: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for part in field.split(";"):
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
            info[key] = value
        else:
            info[part] = "true"
    return info


def parse_gt_dosage(sample_field: str, format_keys: list[str]) -> int | None:
    values = sample_field.split(":")
    fields = dict(zip(format_keys, values))
    gt = fields.get("GT", "")
    if not gt or "." in gt:
        return None
    alleles = gt.replace("|", "/").split("/")
    dosage = 0
    for allele in alleles:
        if allele == "1":
            dosage += 1
        elif allele == "0":
            continue
        else:
            return None
    return dosage


def read_panel() -> list[Sample]:
    panel_text = _mirror_panel_text()
    if panel_text is None:
        panel_text = run(["curl", "-L", "--fail", "--silent", "--show-error", PANEL_URL])
    (WORK_DIR / "integrated_call_samples_v3.20130502.ALL.panel").write_text(panel_text)
    rows: list[Sample] = []
    for line in panel_text.splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        rows.append(Sample(parts[0], parts[1], parts[2], parts[3]))
    return rows


def select_samples(panel: list[Sample]) -> list[Sample]:
    counts = {super_pop: 0 for super_pop in SUPER_POP_ORDER}
    selected: list[Sample] = []
    for sample in panel:
        if sample.super_population not in counts:
            continue
        if counts[sample.super_population] >= SAMPLES_PER_SUPER_POP:
            continue
        selected.append(sample)
        counts[sample.super_population] += 1
        if all(count == SAMPLES_PER_SUPER_POP for count in counts.values()):
            return selected
    missing = [key for key, count in counts.items() if count < SAMPLES_PER_SUPER_POP]
    raise RuntimeError(f"panel did not contain enough samples for {missing}")


def fetch_candidate_vcf(samples: list[Sample]) -> str:
    sample_file = WORK_DIR / "selected_samples.txt"
    sample_file.write_text("\n".join(sample.sample_id for sample in samples) + "\n")
    expr = f"AF>{MIN_GLOBAL_AF} && AF<{MAX_GLOBAL_AF}"
    cmd = [
        "bcftools",
        "view",
        "--no-version",
        "-S",
        str(sample_file),
        "-r",
        REGION,
        "-m2",
        "-M2",
        "-v",
        "snps",
        "-i",
        expr,
        bcftools_source(VCF_URL),
    ]
    vcf_text = run(cmd, cwd=WORK_DIR)
    (WORK_DIR / "candidate_subset.vcf").write_text(vcf_text)
    return vcf_text


def parse_vcf(vcf_text: str, selected: list[Sample]) -> tuple[list[str], list[Variant]]:
    sample_order: list[str] | None = None
    selected_ids = {sample.sample_id for sample in selected}
    variants: list[Variant] = []

    for line in vcf_text.splitlines():
        if not line:
            continue
        if line.startswith("#CHROM"):
            parts = line.split("\t")
            sample_order = parts[9:]
            unexpected = [sample for sample in sample_order if sample not in selected_ids]
            if unexpected:
                raise RuntimeError(f"VCF returned unexpected samples: {unexpected}")
            continue
        if line.startswith("#"):
            continue
        if sample_order is None:
            raise RuntimeError("VCF data arrived before #CHROM header")
        parts = line.split("\t")
        if len(parts) < 10:
            continue
        chrom, pos, variant_id, ref, alt = parts[:5]
        info = parse_info(parts[7])
        format_keys = parts[8].split(":")
        dosages = {
            sample: parse_gt_dosage(field, format_keys)
            for sample, field in zip(sample_order, parts[9:])
        }
        present = [dosage for dosage in dosages.values() if dosage is not None]
        if len(present) != len(sample_order):
            continue
        alt_count = sum(present)
        total_alleles = 2 * len(present)
        if not present or alt_count <= 0 or alt_count >= total_alleles:
            continue
        variants.append(
            Variant(
                chrom=chrom,
                pos=int(pos),
                variant_id=variant_id if variant_id != "." else f"{chrom}:{pos}:{ref}:{alt}",
                ref=ref,
                alt=alt,
                info=info,
                dosages=dosages,
            )
        )
        if len(variants) >= VARIANT_COUNT:
            break
    if sample_order is None:
        raise RuntimeError("VCF header did not include a #CHROM line")
    if len(variants) < VARIANT_COUNT:
        raise RuntimeError(
            f"only found {len(variants)} polymorphic variants in {REGION}; "
            f"need {VARIANT_COUNT}"
        )
    return sample_order, variants


def write_raw_vectors(sample_order: list[str], variants: list[Variant]) -> dict[str, list[int]]:
    raw_dir = WORK_DIR / "raw_vectors"
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    vectors: dict[str, list[int]] = {}
    for sample_id in sample_order:
        vector: list[int] = []
        for variant in variants:
            dosage = variant.dosages[sample_id]
            if dosage is None:
                raise RuntimeError(
                    f"selected variant {variant.coordinate} has a missing call for {sample_id}"
                )
            vector.append(dosage)
        vectors[sample_id] = vector
        (raw_dir / f"{sample_id}.json").write_text(json.dumps({"vector": vector}) + "\n")
    return vectors


def import_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run_application(app_name: str, vectors: dict[str, list[int]]) -> dict[str, Any]:
    signed_dir = REPO_ROOT / "applications" / app_name / "signed"
    data_owner = import_module(f"{app_name}_data_owner", signed_dir / "local_data_owner.py")
    project_owner = import_module(
        f"{app_name}_project_owner", signed_dir / "local_project_owner.py"
    )
    server = import_module(f"{app_name}_server", signed_dir / "server.py")

    timings: dict[str, float] = {}

    def timed(label: str, func):
        start = time.perf_counter()
        value = func()
        timings[label] = (time.perf_counter() - start) * 1000.0
        return value

    length = len(next(iter(vectors.values())))
    secret_context, public_context = timed("keygen_ms", project_owner.keygen)
    encoded = timed(
        "encode_ms",
        lambda: {
            sample_id: data_owner.encode(vector, length)
            for sample_id, vector in vectors.items()
        },
    )
    ciphertexts = timed(
        "encrypt_ms",
        lambda: [
            data_owner.encrypt(public_context, encoded[sample_id])
            for sample_id in vectors.keys()
        ],
    )
    result_bytes = timed(
        "compute_ms", lambda: server.compute(ciphertexts, public_context)
    )
    plain = timed(
        "decrypt_ms", lambda: project_owner.decrypt(secret_context, result_bytes)
    )
    decoded = timed("decode_ms", lambda: project_owner.decode(plain, length))

    timings["total_ms"] = sum(timings.values())
    ciphertext_sizes = [len(blob) for blob in ciphertexts]
    return {
        "application": app_name,
        "decoded": decoded,
        "timings_ms": timings,
        "crypto_artifacts": {
            "public_context_sha256": sha256_bytes(public_context),
            "result_sha256": sha256_bytes(result_bytes),
            "public_context_bytes": len(public_context),
            "result_bytes": len(result_bytes),
            "ciphertext_bytes_total": sum(ciphertext_sizes),
            "ciphertext_bytes_per_sample": sum(ciphertext_sizes) / len(ciphertext_sizes),
            "ciphertext_sha256s": [sha256_bytes(blob) for blob in ciphertexts],
        },
    }


def cleartext_counts(vectors: dict[str, list[int]]) -> tuple[list[int], list[int]]:
    length = len(next(iter(vectors.values())))
    sums = [0] * length
    sumsq = [0] * length
    for vector in vectors.values():
        for index, dosage in enumerate(vector):
            sums[index] += dosage
            sumsq[index] += dosage * dosage
    return sums, sumsq


def allele_frequency_rows(variants: list[Variant], sums: list[int], n: int) -> list[dict[str, Any]]:
    rows = []
    for index, (variant, alt_count) in enumerate(zip(variants, sums), start=1):
        selected_af = alt_count / (2 * n)
        global_af = variant.global_af
        rows.append(
            {
                "variant_index": index,
                "coordinate": variant.coordinate,
                "variant_id": variant.variant_id,
                "chrom": variant.chrom,
                "pos": variant.pos,
                "ref": variant.ref,
                "alt": variant.alt,
                "n_samples": n,
                "allele_number": 2 * n,
                "alt_count": alt_count,
                "allele_frequency": selected_af,
                "igsr_global_af": global_af,
                "abs_delta_vs_igsr_global_af": (
                    abs(selected_af - global_af) if global_af is not None else None
                ),
            }
        )
    return rows


def group_frequency_rows(
    variants: list[Variant], samples_by_id: dict[str, Sample], group_key: str
) -> list[dict[str, Any]]:
    groups: dict[str, list[Sample]] = {}
    for sample in samples_by_id.values():
        group = getattr(sample, group_key)
        groups.setdefault(group, []).append(sample)

    rows: list[dict[str, Any]] = []
    for index, variant in enumerate(variants, start=1):
        for group, members in sorted(groups.items()):
            present = [
                variant.dosages[member.sample_id]
                for member in members
                if variant.dosages[member.sample_id] is not None
            ]
            n = len(present)
            alt_count = sum(int(value) for value in present)
            if group_key == "super_population":
                source_af = parse_float(variant.info.get(f"{group}_AF"))
            else:
                source_af = None
            suppressed = n < MIN_REPORTABLE_GROUP_N
            af = alt_count / (2 * n) if n and not suppressed else None
            rows.append(
                {
                    "variant_index": index,
                    "coordinate": variant.coordinate,
                    "group_type": group_key,
                    "group": group,
                    "n_samples": n,
                    "allele_number": 2 * n,
                    "alt_count": None if suppressed else alt_count,
                    "allele_frequency": af,
                    "igsr_reference_group_af": None if suppressed else source_af,
                    "abs_delta_vs_igsr_reference_group_af": (
                        abs(af - source_af)
                        if af is not None and source_af is not None
                        else None
                    ),
                    "suppressed": suppressed,
                    "suppression_reason": (
                        f"n<{MIN_REPORTABLE_GROUP_N}; avoid small-cell genotype disclosure"
                        if suppressed
                        else None
                    ),
                }
            )
    return rows


def genotype_distribution_rows(variants: list[Variant]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, variant in enumerate(variants, start=1):
        counts = {0: 0, 1: 0, 2: 0}
        missing = 0
        for dosage in variant.dosages.values():
            if dosage is None:
                missing += 1
            else:
                counts[dosage] += 1
        n = sum(counts.values())
        rows.append(
            {
                "variant_index": index,
                "coordinate": variant.coordinate,
                "hom_ref_count": counts[0],
                "het_count": counts[1],
                "hom_alt_count": counts[2],
                "missing_count": missing,
                "heterozygote_rate": counts[1] / n if n else None,
                "hom_alt_rate": counts[2] / n if n else None,
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(rows[0].keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


def mean(values: list[float]) -> float | None:
    values = [value for value in values if value is not None and not math.isnan(value)]
    return sum(values) / len(values) if values else None


def write_report(summary: dict[str, Any], allele_rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Real Human DNA Allele-Frequency Study",
        "",
        f"- Source: IGSR/1000 Genomes Phase 3 release `20130502`",
        f"- Region: `{REGION}`",
        f"- Samples: {summary['sample_count']} public sample IDs",
        f"- Variants: {summary['variant_count']} biallelic SNPs polymorphic in the toy cohort",
        f"- Existing BlindMachine applications: `{', '.join(summary['applications'])}`",
        "",
        "## Aggregate Frequencies",
        "",
        "| # | Coordinate | Alt count | AF | IGSR global AF | Abs delta |",
        "|---:|---|---:|---:|---:|---:|",
    ]
    for row in allele_rows:
        lines.append(
            "| {variant_index} | `{coordinate}` | {alt_count} | {af:.4f} | "
            "{global_af} | {delta} |".format(
                variant_index=row["variant_index"],
                coordinate=row["coordinate"],
                alt_count=row["alt_count"],
                af=row["allele_frequency"],
                global_af=(
                    f"{row['igsr_global_af']:.4f}"
                    if row["igsr_global_af"] is not None
                    else ""
                ),
                delta=(
                    f"{row['abs_delta_vs_igsr_global_af']:.4f}"
                    if row["abs_delta_vs_igsr_global_af"] is not None
                    else ""
                ),
            )
        )
    lines.extend(
        [
            "",
            "## Additional Analyses",
            "",
            f"- `group_frequencies.csv` reports toy subgroup rows by 1000 Genomes "
            f"super-population and reported sex, with allele counts suppressed "
            f"when `n < {MIN_REPORTABLE_GROUP_N}`.",
            "- `genotype_distribution.csv` reports homozygous-reference, "
            "heterozygous, homozygous-alt, and missing-call counts.",
            "- `blindmachine_results.json` records the exact first moment from "
            "`allele_frequency_count` and the exact first/second moments from "
            "`allele_frequency_with_variance`.",
            "",
            "Summary statistics:",
            "",
            f"- Mean absolute delta vs IGSR global AF: "
            f"{summary['summary_stats']['mean_abs_delta_vs_igsr_global_af']:.4f}",
            f"- Mean heterozygote rate across selected variants: "
            f"{summary['summary_stats']['mean_heterozygote_rate']:.4f}",
            f"- Mean dosage variance across selected variants: "
            f"{summary['summary_stats']['mean_dosage_variance']:.4f}",
            "",
            "## Validation",
            "",
            "- Cleartext aggregate matched `allele_frequency_count` output exactly.",
            "- `allele_frequency_with_variance` produced the same first moment and exact second moments.",
            "- Per-sample genotype vectors were written only under ignored `work/`.",
            "",
            "## Interpretation Boundary",
            "",
            "These are toy workflow frequencies over ten public samples. They are not "
            "medical claims and not population estimates.",
            "",
        ]
    )
    (RESULTS_DIR / "report.md").write_text("\n".join(lines))


def main() -> int:
    ensure_tenseal_runtime(REPO_ROOT, SCRIPT_PATH)
    ensure_bcftools()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    panel = read_panel()
    selected = select_samples(panel)
    selected_by_id = {sample.sample_id: sample for sample in selected}
    vcf_text = fetch_candidate_vcf(selected)
    sample_order, variants = parse_vcf(vcf_text, selected)
    vectors = write_raw_vectors(sample_order, variants)

    sums, sumsq = cleartext_counts(vectors)
    n = len(vectors)

    count_result = run_application("allele_frequency_count", vectors)
    variance_result = run_application("allele_frequency_with_variance", vectors)

    count_decoded = count_result["decoded"]
    variance_decoded = variance_result["decoded"]
    if count_decoded["allele_counts"] != sums:
        raise RuntimeError("allele_frequency_count did not match cleartext sums")
    if variance_decoded["sum_g"] != sums:
        raise RuntimeError("variance app first moment did not match cleartext sums")
    if variance_decoded["sum_g2"] != sumsq:
        raise RuntimeError("variance app second moment did not match cleartext sums")

    allele_rows = allele_frequency_rows(variants, sums, n)
    group_rows = group_frequency_rows(variants, selected_by_id, "super_population")
    group_rows.extend(group_frequency_rows(variants, selected_by_id, "gender"))
    genotype_rows = genotype_distribution_rows(variants)

    write_csv(RESULTS_DIR / "allele_frequencies.csv", allele_rows)
    write_csv(RESULTS_DIR / "group_frequencies.csv", group_rows)
    write_csv(RESULTS_DIR / "genotype_distribution.csv", genotype_rows)

    summary = {
        "study": STUDY_NAME,
        "accessed_on_utc": STUDY_ACCESS_DATE,
        "source": {
            "panel_url": PANEL_URL,
            "vcf_url": VCF_URL,
            "region": REGION,
            "genome_build": GENOME_BUILD,
            "release": "1000 Genomes Project Phase 3 integrated callset, 20130502",
            "data_access_pattern": (
                "bcftools remote query of a bounded chr22 interval; the subset VCF "
                "and index cache are kept under ignored work/"
            ),
            "data_reuse_statement": (
                "IGSR/1000 Genomes data is publicly available without embargo; users "
                "must consult IGSR data reuse statements and cite associated publications."
            ),
            "global_af_filter": {
                "min": MIN_GLOBAL_AF,
                "max": MAX_GLOBAL_AF,
            },
            "sample_selection_rule": (
                "take the first two samples encountered in the 20130502 panel for each "
                "super-population in order EUR, EAS, AMR, AFR, SAS"
            ),
            "variant_selection_rule": (
                "within the chr22 interval, keep the first 12 complete-call biallelic "
                "SNPs with IGSR global AF between 0.05 and 0.95 and nonzero/nonfixed "
                "alternate-allele count in the selected ten-sample cohort"
            ),
            "bcftools_filters": [
                "-m2 -M2",
                "-v snps",
                f"-i 'AF>{MIN_GLOBAL_AF} && AF<{MAX_GLOBAL_AF}'",
            ],
        },
        "sample_count": n,
        "variant_count": len(variants),
        "selected_samples": [
            {
                "sample_id": sample.sample_id,
                "population": sample.population,
                "super_population": sample.super_population,
                "gender": sample.gender,
            }
            for sample in selected
        ],
        "applications": [
            "allele_frequency_count",
            "allele_frequency_with_variance",
        ],
        "checks": {
            "count_matches_cleartext": count_decoded["allele_counts"] == sums,
            "variance_sum_matches_cleartext": variance_decoded["sum_g"] == sums,
            "variance_sumsq_matches_cleartext": variance_decoded["sum_g2"] == sumsq,
            "n_contributors": count_decoded["n_contributors"],
            "variance_n_contributors": variance_decoded["n_contributors"],
        },
        "summary_stats": {
            "mean_abs_delta_vs_igsr_global_af": mean(
                [row["abs_delta_vs_igsr_global_af"] for row in allele_rows]
            ),
            "mean_heterozygote_rate": mean(
                [row["heterozygote_rate"] for row in genotype_rows]
            ),
            "mean_dosage_variance": mean(variance_decoded["variance"]),
        },
        "tool_versions": {
            "python": sys.version.split()[0],
            "bcftools": run(["bcftools", "--version"]).splitlines()[0],
        },
        "work_artifacts": {
            "candidate_subset_vcf_sha256": sha256_file(WORK_DIR / "candidate_subset.vcf"),
            "sample_panel_sha256": sha256_file(
                WORK_DIR / "integrated_call_samples_v3.20130502.ALL.panel"
            ),
        },
        "ethics_boundary": {
            "data_type": "publicly available human genotype VCF subset under IGSR/1000G terms",
            "committed_outputs": "aggregate-only allele-frequency and moment summaries",
            "ignored_outputs": (
                "per-sample genotype vectors, subset VCF, remote index cache, and "
                "runtime diagnostics under work/"
            ),
            "small_cell_policy": (
                f"group-level allele counts and frequencies are suppressed when "
                f"n < {MIN_REPORTABLE_GROUP_N}"
            ),
            "limitations": [
                "n=10 toy workflow, not a population estimate",
                "no medical or clinical interpretation",
                "public genomic data is not anonymous and still carries re-identification risk",
            ],
        },
    }

    blindmachine_full = {
        "allele_frequency_count": count_result,
        "allele_frequency_with_variance": variance_result,
    }
    blindmachine = {
        name: {
            "application": result["application"],
            "decoded": result["decoded"],
            "artifact_sizes": {
                "public_context_bytes": result["crypto_artifacts"]["public_context_bytes"],
                "result_bytes": result["crypto_artifacts"]["result_bytes"],
                "ciphertext_bytes_total": result["crypto_artifacts"]["ciphertext_bytes_total"],
                "ciphertext_bytes_per_sample": result["crypto_artifacts"][
                    "ciphertext_bytes_per_sample"
                ],
            },
        }
        for name, result in blindmachine_full.items()
    }

    (RESULTS_DIR / "provenance.json").write_text(json.dumps(summary, indent=2) + "\n")
    (RESULTS_DIR / "blindmachine_results.json").write_text(
        json.dumps(blindmachine, indent=2) + "\n"
    )
    (WORK_DIR / "runtime_diagnostics.json").write_text(
        json.dumps(blindmachine_full, indent=2) + "\n"
    )
    write_report(summary, allele_rows)

    print(f"RESULT: PASS {STUDY_NAME}")
    print(f"  samples: {n} ({', '.join(sample_order)})")
    print(f"  variants: {len(variants)} from {REGION}")
    print(f"  results: {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DataUnavailable as exc:
        print(f"SKIP: {exc}", flush=True)
        raise SystemExit(3)
