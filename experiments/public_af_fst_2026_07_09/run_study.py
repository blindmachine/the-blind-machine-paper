#!/usr/bin/env python3
"""Run an aggregate-only cross-population AF/FST-ish panel on IGSR/1000G data.

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
from typing import Any, Iterable


STUDY_NAME = "public_af_fst_2026_07_09"
PAPER_EVIDENCE_SLUG = "public-genomics-e6-af-fst"
STUDY_ACCESS_DATE = "2026-07-09"
GENOME_BUILD = "GRCh37"

SUPER_POP_ORDER = ("AFR", "AMR", "EAS", "EUR", "SAS")
SAMPLES_PER_SUPER_POP = 10
VARIANT_COUNT = 24
REGION = "22:16050000-17000000"
MIN_GLOBAL_AF = 0.05
MAX_GLOBAL_AF = 0.95
MIN_SOURCE_SUPERPOP_AF_RANGE = 0.15
MIN_VARIANT_SPACING_BP = 200
MIN_REPORTABLE_GROUP_N = 10

BASE_URL = "https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502"
PANEL_URL = f"{BASE_URL}/integrated_call_samples_v3.20130502.ALL.panel"
VCF_URL = (
    f"{BASE_URL}/"
    "ALL.chr22.phase3_shapeit2_mvncall_integrated_v5b.20130502.genotypes.vcf.gz"
)
IGSR_DATA_URL = "https://www.internationalgenome.org/data/"
IGSR_PERMISSION_URL = (
    "https://www.internationalgenome.org/faq/"
    "do-i-need-permission-to-use-igsr-data-in-my-own-scientific-research/"
)
IGSR_PHASE3_URL = "https://www.internationalgenome.org/data-portal/data-collection/phase3/"
IGSR_FTP_RELEASE_URL = BASE_URL + "/"

SCRIPT_PATH = Path(__file__).resolve()
STUDY_DIR = SCRIPT_PATH.parent
REPO_ROOT = STUDY_DIR.parents[3]
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

    @property
    def source_superpop_afs(self) -> dict[str, float]:
        values: dict[str, float] = {}
        for super_pop in SUPER_POP_ORDER:
            value = parse_float(self.info.get(f"{super_pop}_AF"))
            if value is not None:
                values[super_pop] = value
        return values


class PlainAddEvaluator:
    def zero(self, length: int) -> list[int]:
        return [0] * length

    def add(self, a: list[int], b: list[int]) -> list[int]:
        return [x + y for x, y in zip(a, b)]


class PlainVarianceEvaluator(PlainAddEvaluator):
    def mul(self, a: list[int], b: list[int]) -> list[int]:
        return [x * y for x, y in zip(a, b)]


def run(cmd: list[str], *, input_text: str | None = None, cwd: Path | None = None) -> str:
    proc = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr[-1600:]}"
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
    """Select samples by deterministic round-robin over populations per super-pop."""
    selected: list[Sample] = []
    for super_pop in SUPER_POP_ORDER:
        by_population: dict[str, list[Sample]] = {}
        for sample in panel:
            if sample.super_population == super_pop:
                by_population.setdefault(sample.population, []).append(sample)
        if not by_population:
            raise RuntimeError(f"panel has no samples for {super_pop}")

        population_order = sorted(by_population)
        group_samples: list[Sample] = []
        offsets = {population: 0 for population in population_order}
        while len(group_samples) < SAMPLES_PER_SUPER_POP:
            progressed = False
            for population in population_order:
                offset = offsets[population]
                samples = by_population[population]
                if offset >= len(samples):
                    continue
                group_samples.append(samples[offset])
                offsets[population] += 1
                progressed = True
                if len(group_samples) >= SAMPLES_PER_SUPER_POP:
                    break
            if not progressed:
                raise RuntimeError(
                    f"panel did not contain {SAMPLES_PER_SUPER_POP} samples for {super_pop}"
                )
        selected.extend(group_samples)
    return selected


def sample_counts(samples: Iterable[Sample], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sample in samples:
        value = getattr(sample, key)
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


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
    last_kept_pos: int | None = None

    for line in vcf_text.splitlines():
        if not line:
            continue
        if line.startswith("#CHROM"):
            parts = line.split("\t")
            sample_order = parts[9:]
            unexpected = [sample for sample in sample_order if sample not in selected_ids]
            missing = [sample_id for sample_id in selected_ids if sample_id not in sample_order]
            if unexpected:
                raise RuntimeError(f"VCF returned unexpected samples: {unexpected}")
            if missing:
                raise RuntimeError(f"VCF did not return selected samples: {missing}")
            continue
        if line.startswith("#"):
            continue
        if sample_order is None:
            raise RuntimeError("VCF data arrived before #CHROM header")

        parts = line.split("\t")
        if len(parts) < 10:
            continue
        chrom, pos_text, variant_id, ref, alt = parts[:5]
        pos = int(pos_text)
        if last_kept_pos is not None and pos - last_kept_pos < MIN_VARIANT_SPACING_BP:
            continue

        info = parse_info(parts[7])
        source_superpop_afs = {
            super_pop: parse_float(info.get(f"{super_pop}_AF"))
            for super_pop in SUPER_POP_ORDER
        }
        if any(value is None for value in source_superpop_afs.values()):
            continue
        source_af_values = [float(value) for value in source_superpop_afs.values()]
        source_range = max(source_af_values) - min(source_af_values)
        if source_range < MIN_SOURCE_SUPERPOP_AF_RANGE:
            continue

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
                pos=pos,
                variant_id=variant_id if variant_id != "." else f"{chrom}:{pos}:{ref}:{alt}",
                ref=ref,
                alt=alt,
                info=info,
                dosages=dosages,
            )
        )
        last_kept_pos = pos
        if len(variants) >= VARIANT_COUNT:
            break

    if sample_order is None:
        raise RuntimeError("VCF header did not include a #CHROM line")
    if len(variants) < VARIANT_COUNT:
        raise RuntimeError(
            f"only found {len(variants)} panel variants in {REGION}; need {VARIANT_COUNT}"
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


def app_modules(app_name: str):
    signed_dir = REPO_ROOT / "applications" / app_name / "signed"
    data_owner = import_module(f"e6_{app_name}_data_owner", signed_dir / "local_data_owner.py")
    project_owner = import_module(
        f"e6_{app_name}_project_owner", signed_dir / "local_project_owner.py"
    )
    server = import_module(f"e6_{app_name}_server", signed_dir / "server.py")
    return data_owner, project_owner, server


def run_application(app_name: str, vectors: dict[str, list[int]]) -> dict[str, Any]:
    data_owner, project_owner, server = app_modules(app_name)

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
    result_bytes = timed("compute_ms", lambda: server.compute(ciphertexts, public_context))
    plain = timed("decrypt_ms", lambda: project_owner.decrypt(secret_context, result_bytes))
    decoded = timed("decode_ms", lambda: project_owner.decode(plain, length))

    timings["total_ms"] = sum(timings.values())
    ciphertext_sizes = [len(blob) for blob in ciphertexts]
    return {
        "application": app_name,
        "mode": "local_encrypted_application_execution",
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


def signed_plaintext_application_result(
    app_name: str, vectors: dict[str, list[int]]
) -> dict[str, Any]:
    data_owner, project_owner, server = app_modules(app_name)
    length = len(next(iter(vectors.values())))
    encoded_with_sentinel = [
        data_owner.append_sentinel(data_owner.encode(vector, length))
        for vector in vectors.values()
    ]
    if app_name == "allele_frequency_count":
        aggregate = server.aggregate(encoded_with_sentinel, PlainAddEvaluator())
        decoded = project_owner.decode(aggregate, length)
    elif app_name == "allele_frequency_with_variance":
        sum_g, sum_g2 = server.aggregate(encoded_with_sentinel, PlainVarianceEvaluator())
        decoded = project_owner.decode({"sum": sum_g, "sumsq": sum_g2}, length)
    else:
        raise ValueError(f"unsupported application for signed plaintext check: {app_name}")
    return {
        "application": app_name,
        "mode": "signed_plaintext_server_aggregate",
        "decoded": decoded,
    }


def vector_subset(vectors: dict[str, list[int]], sample_ids: Iterable[str]) -> dict[str, list[int]]:
    return {sample_id: vectors[sample_id] for sample_id in sample_ids}


def cleartext_counts(vectors: dict[str, list[int]]) -> tuple[list[int], list[int]]:
    length = len(next(iter(vectors.values())))
    sums = [0] * length
    sumsq = [0] * length
    for vector in vectors.values():
        for index, dosage in enumerate(vector):
            sums[index] += dosage
            sumsq[index] += dosage * dosage
    return sums, sumsq


def dosage_variance(sum_g: int, sum_g2: int, n: int) -> float:
    return sum_g2 / n - (sum_g / n) ** 2


def fst_like_from_frequencies(group_afs: dict[str, float]) -> dict[str, Any]:
    ordered = [group for group in SUPER_POP_ORDER if group in group_afs]
    values = [group_afs[group] for group in ordered]
    if not values:
        return {
            "mean_group_af": None,
            "expected_heterozygosity_total": None,
            "expected_heterozygosity_within_mean": None,
            "fst_like": None,
        }
    p_bar = sum(values) / len(values)
    ht = 2 * p_bar * (1 - p_bar)
    hs = sum(2 * p * (1 - p) for p in values) / len(values)
    fst_like = (ht - hs) / ht if ht > 0 else None
    min_group = min(ordered, key=lambda group: group_afs[group])
    max_group = max(ordered, key=lambda group: group_afs[group])
    return {
        "mean_group_af": p_bar,
        "min_group": min_group,
        "min_group_af": group_afs[min_group],
        "max_group": max_group,
        "max_group_af": group_afs[max_group],
        "max_pairwise_af_delta": group_afs[max_group] - group_afs[min_group],
        "expected_heterozygosity_total": ht,
        "expected_heterozygosity_within_mean": hs,
        "fst_like": fst_like,
    }


def superpop_group_vectors(
    vectors: dict[str, list[int]], samples_by_id: dict[str, Sample]
) -> dict[str, dict[str, list[int]]]:
    grouped: dict[str, dict[str, list[int]]] = {}
    for sample_id, vector in vectors.items():
        super_pop = samples_by_id[sample_id].super_population
        grouped.setdefault(super_pop, {})[sample_id] = vector
    return grouped


def allele_panel_rows(
    variants: list[Variant],
    sums: list[int],
    sumsq: list[int],
    n: int,
    group_af_by_variant: dict[int, dict[str, float]],
    fst_rows_by_index: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, (variant, alt_count, alt_sumsq) in enumerate(zip(variants, sums, sumsq), start=1):
        selected_af = alt_count / (2 * n)
        global_af = variant.global_af
        source_stats = fst_like_from_frequencies(variant.source_superpop_afs)
        panel_stats = fst_rows_by_index[index]
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
                "dosage_variance": dosage_variance(alt_count, alt_sumsq, n),
                "igsr_global_af": global_af,
                "abs_delta_vs_igsr_global_af": (
                    abs(selected_af - global_af) if global_af is not None else None
                ),
                "source_superpop_min": source_stats["min_group"],
                "source_superpop_min_af": source_stats["min_group_af"],
                "source_superpop_max": source_stats["max_group"],
                "source_superpop_max_af": source_stats["max_group_af"],
                "source_superpop_af_range": source_stats["max_pairwise_af_delta"],
                "panel_superpop_min": panel_stats["min_group"],
                "panel_superpop_min_af": panel_stats["min_group_af"],
                "panel_superpop_max": panel_stats["max_group"],
                "panel_superpop_max_af": panel_stats["max_group_af"],
                "panel_superpop_af_range": panel_stats["max_pairwise_af_delta"],
                "fst_like_panel": panel_stats["fst_like"],
                "fst_like_igsr_source": source_stats["fst_like"],
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
            source_af = (
                parse_float(variant.info.get(f"{group}_AF"))
                if group_key == "super_population"
                else None
            )
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


def fst_summary_rows(
    variants: list[Variant],
    grouped_vectors: dict[str, dict[str, list[int]]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    group_sums: dict[str, list[int]] = {}
    group_ns: dict[str, int] = {}
    for group, vectors in grouped_vectors.items():
        sums, _sumsq = cleartext_counts(vectors)
        group_sums[group] = sums
        group_ns[group] = len(vectors)

    for index, variant in enumerate(variants, start=1):
        group_afs: dict[str, float] = {}
        for group in SUPER_POP_ORDER:
            n = group_ns[group]
            if n < MIN_REPORTABLE_GROUP_N:
                continue
            group_afs[group] = group_sums[group][index - 1] / (2 * n)

        panel_stats = fst_like_from_frequencies(group_afs)
        source_stats = fst_like_from_frequencies(variant.source_superpop_afs)
        total_alt = sum(group_sums[group][index - 1] for group in SUPER_POP_ORDER)
        total_samples = sum(group_ns[group] for group in SUPER_POP_ORDER)
        rows.append(
            {
                "variant_index": index,
                "coordinate": variant.coordinate,
                "n_groups": len(group_afs),
                "total_samples": total_samples,
                "total_alleles": 2 * total_samples,
                "panel_af": total_alt / (2 * total_samples),
                "mean_group_af": panel_stats["mean_group_af"],
                "min_group": panel_stats["min_group"],
                "min_group_af": panel_stats["min_group_af"],
                "max_group": panel_stats["max_group"],
                "max_group_af": panel_stats["max_group_af"],
                "max_pairwise_af_delta": panel_stats["max_pairwise_af_delta"],
                "expected_heterozygosity_total": panel_stats[
                    "expected_heterozygosity_total"
                ],
                "expected_heterozygosity_within_mean": panel_stats[
                    "expected_heterozygosity_within_mean"
                ],
                "fst_like": panel_stats["fst_like"],
                "igsr_source_mean_group_af": source_stats["mean_group_af"],
                "igsr_source_max_pairwise_af_delta": source_stats[
                    "max_pairwise_af_delta"
                ],
                "igsr_source_fst_like": source_stats["fst_like"],
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


def mean(values: Iterable[float | None]) -> float | None:
    clean = [value for value in values if value is not None and not math.isnan(value)]
    return sum(clean) / len(clean) if clean else None


def max_value(values: Iterable[float | None]) -> float | None:
    clean = [value for value in values if value is not None and not math.isnan(value)]
    return max(clean) if clean else None


def suppressions_ok(group_rows: list[dict[str, Any]]) -> bool:
    for row in group_rows:
        if row["n_samples"] < MIN_REPORTABLE_GROUP_N:
            protected_fields = (
                "alt_count",
                "allele_frequency",
                "igsr_reference_group_af",
                "abs_delta_vs_igsr_reference_group_af",
            )
            if any(row[field] is not None for field in protected_fields):
                return False
    return True


def group_plaintext_checks(
    grouped_vectors: dict[str, dict[str, list[int]]]
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for group in SUPER_POP_ORDER:
        vectors = grouped_vectors[group]
        sums, sumsq = cleartext_counts(vectors)
        count_result = signed_plaintext_application_result("allele_frequency_count", vectors)
        variance_result = signed_plaintext_application_result(
            "allele_frequency_with_variance", vectors
        )
        checks.append(
            {
                "group_type": "super_population",
                "group": group,
                "n_samples": len(vectors),
                "allele_frequency_count_matches_cleartext": (
                    count_result["decoded"]["allele_counts"] == sums
                ),
                "allele_frequency_with_variance_sum_matches_cleartext": (
                    variance_result["decoded"]["sum_g"] == sums
                ),
                "allele_frequency_with_variance_sumsq_matches_cleartext": (
                    variance_result["decoded"]["sum_g2"] == sumsq
                ),
                "count_n_contributors": count_result["decoded"]["n_contributors"],
                "variance_n_contributors": variance_result["decoded"]["n_contributors"],
            }
        )
    return checks


def stable_application_result(result: dict[str, Any]) -> dict[str, Any]:
    artifacts = result["crypto_artifacts"]
    return {
        "application": result["application"],
        "mode": result["mode"],
        "decoded": result["decoded"],
        "artifact_sizes": {
            "public_context_bytes": artifacts["public_context_bytes"],
            "result_bytes": artifacts["result_bytes"],
            "ciphertext_bytes_total": artifacts["ciphertext_bytes_total"],
            "ciphertext_bytes_per_sample": artifacts["ciphertext_bytes_per_sample"],
        },
    }


def json_tool_command() -> str:
    base = "docs/paper/experiments/public_af_fst_2026_07_09/results"
    return (
        "bash docs/paper/experiments/e6_public_af_fst_panel.sh && "
        f"python3 -m json.tool {base}/provenance.json >/dev/null && "
        f"python3 -m json.tool {base}/blindmachine_results.json >/dev/null && "
        f"python3 -m json.tool {base}/verification.json >/dev/null"
    )


def write_report(
    summary: dict[str, Any],
    allele_rows: list[dict[str, Any]],
    fst_rows: list[dict[str, Any]],
    group_rows: list[dict[str, Any]],
) -> None:
    top_fst = sorted(fst_rows, key=lambda row: row["fst_like"], reverse=True)[:8]
    suppressed_count = sum(1 for row in group_rows if row["suppressed"])
    lines = [
        "# Public IGSR Cross-Population AF/FST-ish Panel",
        "",
        f"- Source: IGSR/1000 Genomes Phase 3 release `20130502` ({GENOME_BUILD})",
        f"- Region: `{REGION}`",
        f"- Samples: {summary['sample_count']} public samples selected by deterministic rule",
        f"- Variants: {summary['variant_count']} biallelic SNPs selected for source "
        f"super-population AF range >= {MIN_SOURCE_SUPERPOP_AF_RANGE}",
        f"- Reporting floor: suppress group count/frequency fields when `n < "
        f"{MIN_REPORTABLE_GROUP_N}`",
        "- Existing BlindMachine applications used locally: "
        "`allele_frequency_count`, `allele_frequency_with_variance`",
        "",
        "## Outputs",
        "",
        "- `allele_panel.csv`: aggregate panel frequencies, source AF deltas, "
        "dosage variance, and per-variant FST-ish summaries.",
        "- `group_frequencies.csv`: super-population rows plus suppressed "
        "population-level small cells.",
        "- `fst_summary.csv`: per-variant equal-weight "
        "`(H_T - mean(H_S)) / H_T` across super-populations.",
        "- `blindmachine_results.json`: decoded local BlindMachine application "
        "outputs plus signed pure-function equivalence checks.",
        "- `verification.json`: local verification command and honest hosted "
        "publication status.",
        "",
        "## Highest FST-ish Variants",
        "",
        "| # | Coordinate | Panel AF | Max delta | Min group | Max group | FST-ish | IGSR FST-ish |",
        "|---:|---|---:|---:|---|---|---:|---:|",
    ]
    for row in top_fst:
        lines.append(
            "| {variant_index} | `{coordinate}` | {panel_af:.4f} | {delta:.4f} | "
            "{min_group} {min_af:.4f} | {max_group} {max_af:.4f} | "
            "{fst:.4f} | {source_fst:.4f} |".format(
                variant_index=row["variant_index"],
                coordinate=row["coordinate"],
                panel_af=row["panel_af"],
                delta=row["max_pairwise_af_delta"],
                min_group=row["min_group"],
                min_af=row["min_group_af"],
                max_group=row["max_group"],
                max_af=row["max_group_af"],
                fst=row["fst_like"],
                source_fst=row["igsr_source_fst_like"],
            )
        )

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Mean absolute delta vs IGSR global AF: "
            f"{summary['summary_stats']['mean_abs_delta_vs_igsr_global_af']:.4f}",
            f"- Mean panel FST-ish value: {summary['summary_stats']['mean_fst_like']:.4f}",
            f"- Max panel FST-ish value: {summary['summary_stats']['max_fst_like']:.4f}",
            f"- Suppressed small-cell group rows: {suppressed_count}",
            "",
            "## Validation",
            "",
            "- Local encrypted `allele_frequency_count` output matched cleartext "
            "alternate-allele counts exactly.",
            "- Local encrypted `allele_frequency_with_variance` output matched "
            "cleartext first and second moments exactly.",
            "- Signed pure server aggregate functions were also imported and checked "
            "for each reported super-population group.",
            "- Per-sample genotype vectors, the selected sample list, and the subset "
            "VCF were written only under ignored `work/`.",
            "",
            "## Hosted Verification",
            "",
            "`blindmachine.org` publication status is `not_published`: this local "
            "run did not have hosted verification credentials or a server-side "
            "publication target. Reproduce locally with:",
            "",
            "```bash",
            json_tool_command(),
            "```",
            "",
            "## Interpretation Boundary",
            "",
            "This is a deterministic public-data workflow panel, not a clinical result "
            "and not a population-genetics estimate. The FST-ish statistic is an "
            "equal-weight heterozygosity contrast over a small selected sample panel.",
            "",
        ]
    )
    (RESULTS_DIR / "report.md").write_text("\n".join(lines))


def tool_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {
        "python": sys.version.split()[0],
        "bcftools": run(["bcftools", "--version"]).splitlines()[0],
        "curl": run(["curl", "--version"]).splitlines()[0],
    }
    try:
        import importlib.metadata

        versions["tenseal"] = importlib.metadata.version("tenseal")
    except Exception:
        versions["tenseal"] = None
    return versions


def main() -> int:
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

    grouped_vectors = superpop_group_vectors(vectors, selected_by_id)
    missing_groups = [group for group in SUPER_POP_ORDER if group not in grouped_vectors]
    if missing_groups:
        raise RuntimeError(f"missing super-population groups: {missing_groups}")

    count_result = run_application("allele_frequency_count", vectors)
    variance_result = run_application("allele_frequency_with_variance", vectors)
    count_plain = signed_plaintext_application_result("allele_frequency_count", vectors)
    variance_plain = signed_plaintext_application_result(
        "allele_frequency_with_variance", vectors
    )

    count_decoded = count_result["decoded"]
    variance_decoded = variance_result["decoded"]
    if count_decoded["allele_counts"] != sums:
        raise RuntimeError("allele_frequency_count did not match cleartext sums")
    if variance_decoded["sum_g"] != sums:
        raise RuntimeError("variance app first moment did not match cleartext sums")
    if variance_decoded["sum_g2"] != sumsq:
        raise RuntimeError("variance app second moment did not match cleartext sums")
    if count_plain["decoded"]["allele_counts"] != sums:
        raise RuntimeError("signed count aggregate did not match cleartext sums")
    if variance_plain["decoded"]["sum_g"] != sums:
        raise RuntimeError("signed variance aggregate first moment mismatch")
    if variance_plain["decoded"]["sum_g2"] != sumsq:
        raise RuntimeError("signed variance aggregate second moment mismatch")

    group_rows = group_frequency_rows(variants, selected_by_id, "super_population")
    group_rows.extend(group_frequency_rows(variants, selected_by_id, "population"))
    if not suppressions_ok(group_rows):
        raise RuntimeError("small-cell suppression check failed")

    fst_rows = fst_summary_rows(variants, grouped_vectors)
    fst_rows_by_index = {row["variant_index"]: row for row in fst_rows}
    group_af_by_variant: dict[int, dict[str, float]] = {}
    for row in group_rows:
        if row["group_type"] != "super_population" or row["suppressed"]:
            continue
        group_af_by_variant.setdefault(row["variant_index"], {})[row["group"]] = row[
            "allele_frequency"
        ]
    allele_rows = allele_panel_rows(
        variants,
        sums,
        sumsq,
        n,
        group_af_by_variant,
        fst_rows_by_index,
    )

    write_csv(RESULTS_DIR / "allele_panel.csv", allele_rows)
    write_csv(RESULTS_DIR / "group_frequencies.csv", group_rows)
    write_csv(RESULTS_DIR / "fst_summary.csv", fst_rows)

    group_checks = group_plaintext_checks(grouped_vectors)
    all_group_checks_ok = all(
        row["allele_frequency_count_matches_cleartext"]
        and row["allele_frequency_with_variance_sum_matches_cleartext"]
        and row["allele_frequency_with_variance_sumsq_matches_cleartext"]
        for row in group_checks
    )

    summary = {
        "study": STUDY_NAME,
        "accessed_on_utc": STUDY_ACCESS_DATE,
        "source": {
            "panel_url": PANEL_URL,
            "vcf_url": VCF_URL,
            "igsr_data_url": IGSR_DATA_URL,
            "igsr_permission_url": IGSR_PERMISSION_URL,
            "igsr_phase3_url": IGSR_PHASE3_URL,
            "igsr_ftp_release_url": IGSR_FTP_RELEASE_URL,
            "region": REGION,
            "genome_build": GENOME_BUILD,
            "release": "1000 Genomes Project Phase 3 integrated callset, 20130502",
            "data_access_pattern": (
                "bcftools remote query of a bounded chr22 interval; the selected "
                "sample list, subset VCF, index cache, and per-sample vectors are "
                "kept under ignored work/"
            ),
            "data_reuse_statement": (
                "IGSR provides open data to support research; users should consult "
                "IGSR terms/data reuse statements and cite associated publications."
            ),
            "sources_rejected": [
                {
                    "source": "TCGA/GDC and dbGaP disease cohorts",
                    "reason": "often controlled-access and unnecessary for this public AF panel",
                },
                {
                    "source": "NIST Genome in a Bottle",
                    "reason": (
                        "excellent benchmark truth data, but not a multi-population "
                        "cohort suited to cross-population AF/FST-ish summaries"
                    ),
                },
            ],
            "global_af_filter": {
                "min": MIN_GLOBAL_AF,
                "max": MAX_GLOBAL_AF,
            },
            "source_superpop_af_range_filter": {
                "min": MIN_SOURCE_SUPERPOP_AF_RANGE,
                "definition": (
                    "max(INFO.AFR_AF, AMR_AF, EAS_AF, EUR_AF, SAS_AF) - "
                    "min(INFO.AFR_AF, AMR_AF, EAS_AF, EUR_AF, SAS_AF)"
                ),
            },
            "sample_selection_rule": (
                "for each super-population in order AFR, AMR, EAS, EUR, SAS, "
                "take a deterministic round-robin over alphabetically sorted "
                "1000 Genomes population codes, preserving panel order within "
                f"each population, until {SAMPLES_PER_SUPER_POP} samples are selected"
            ),
            "variant_selection_rule": (
                "within the chr22 interval, keep the first 24 complete-call "
                "biallelic SNPs with IGSR global AF between 0.05 and 0.95, "
                "source super-population AF range >= 0.15, nonzero/nonfixed "
                "alternate-allele count in the selected cohort, and at least "
                f"{MIN_VARIANT_SPACING_BP} bp from the prior kept variant"
            ),
            "bcftools_filters": [
                "-m2 -M2",
                "-v snps",
                f"-i 'AF>{MIN_GLOBAL_AF} && AF<{MAX_GLOBAL_AF}'",
            ],
        },
        "sample_count": n,
        "variant_count": len(variants),
        "selected_sample_counts": {
            "by_super_population": sample_counts(selected, "super_population"),
            "by_population": sample_counts(selected, "population"),
            "sample_ids_not_committed": True,
            "selected_samples_work_path": "work/selected_samples.txt",
            "selected_samples_sha256": sha256_file(WORK_DIR / "selected_samples.txt"),
        },
        "applications": [
            "allele_frequency_count",
            "allele_frequency_with_variance",
        ],
        "checks": {
            "count_matches_cleartext": count_decoded["allele_counts"] == sums,
            "variance_sum_matches_cleartext": variance_decoded["sum_g"] == sums,
            "variance_sumsq_matches_cleartext": variance_decoded["sum_g2"] == sumsq,
            "signed_count_aggregate_matches_cleartext": (
                count_plain["decoded"]["allele_counts"] == sums
            ),
            "signed_variance_aggregate_sum_matches_cleartext": (
                variance_plain["decoded"]["sum_g"] == sums
            ),
            "signed_variance_aggregate_sumsq_matches_cleartext": (
                variance_plain["decoded"]["sum_g2"] == sumsq
            ),
            "group_signed_pure_function_checks_passed": all_group_checks_ok,
            "small_cell_suppression_passed": suppressions_ok(group_rows),
            "n_contributors": count_decoded["n_contributors"],
            "variance_n_contributors": variance_decoded["n_contributors"],
        },
        "summary_stats": {
            "mean_abs_delta_vs_igsr_global_af": mean(
                [row["abs_delta_vs_igsr_global_af"] for row in allele_rows]
            ),
            "mean_fst_like": mean([row["fst_like"] for row in fst_rows]),
            "max_fst_like": max_value([row["fst_like"] for row in fst_rows]),
            "mean_source_fst_like": mean([row["igsr_source_fst_like"] for row in fst_rows]),
            "mean_dosage_variance": mean(variance_decoded["variance"]),
            "suppressed_group_rows": sum(1 for row in group_rows if row["suppressed"]),
        },
        "tool_versions": tool_versions(),
        "work_artifacts": {
            "candidate_subset_vcf_sha256": sha256_file(WORK_DIR / "candidate_subset.vcf"),
            "sample_panel_sha256": sha256_file(
                WORK_DIR / "integrated_call_samples_v3.20130502.ALL.panel"
            ),
            "raw_vectors_dir": "work/raw_vectors/",
        },
        "ethics_boundary": {
            "data_type": "publicly available human genotype VCF subset under IGSR/1000G terms",
            "committed_outputs": (
                "aggregate-only allele-frequency, group-frequency, FST-ish, "
                "application-output, provenance, and verification summaries"
            ),
            "ignored_outputs": (
                "selected sample IDs, per-sample genotype vectors, subset VCF, "
                "remote index cache, and runtime diagnostics under work/"
            ),
            "small_cell_policy": (
                "group-level allele counts, frequencies, source-reference AFs, "
                f"and deltas are suppressed when n < {MIN_REPORTABLE_GROUP_N}"
            ),
            "limitations": [
                "small deterministic workflow panel, not a population estimate",
                "FST-ish values are equal-weight heterozygosity contrasts, not formal inference",
                "no medical or clinical interpretation",
                "public genomic data is not anonymous and still carries re-identification risk",
            ],
        },
    }

    blindmachine_results = {
        "mode": "local_encrypted_execution_plus_signed_plaintext_equivalence",
        "allele_frequency_count": stable_application_result(count_result),
        "allele_frequency_with_variance": stable_application_result(variance_result),
        "signed_plaintext_equivalence": {
            "cohort": {
                "allele_frequency_count_matches_cleartext": (
                    count_plain["decoded"]["allele_counts"] == sums
                ),
                "allele_frequency_with_variance_sum_matches_cleartext": (
                    variance_plain["decoded"]["sum_g"] == sums
                ),
                "allele_frequency_with_variance_sumsq_matches_cleartext": (
                    variance_plain["decoded"]["sum_g2"] == sumsq
                ),
            },
            "super_population_groups": group_checks,
        },
    }

    verification = {
        "status": "not_published",
        "blindmachine_org_url": None,
        "paper_evidence_url": f"https://blindmachine.org/verify/paper/{PAPER_EVIDENCE_SLUG}",
        "paper_evidence_json_url": f"https://blindmachine.org/verify/paper/{PAPER_EVIDENCE_SLUG}.json",
        "reason": (
            "Hosted blindmachine.org verification was not generated in this local "
            "run; no deployment credentials or hosted publication target were used."
        ),
        "local_verification_command": json_tool_command(),
        "expected_result_files": [
            "results/report.md",
            "results/provenance.json",
            "results/allele_panel.csv",
            "results/group_frequencies.csv",
            "results/fst_summary.csv",
            "results/blindmachine_results.json",
            "results/verification.json",
        ],
        "checks": {
            "local_wrapper_reached_completion": True,
            "count_matches_cleartext": summary["checks"]["count_matches_cleartext"],
            "variance_sum_matches_cleartext": summary["checks"][
                "variance_sum_matches_cleartext"
            ],
            "variance_sumsq_matches_cleartext": summary["checks"][
                "variance_sumsq_matches_cleartext"
            ],
            "signed_pure_function_checks_passed": all_group_checks_ok,
            "small_cell_suppression_passed": summary["checks"][
                "small_cell_suppression_passed"
            ],
        },
    }

    (RESULTS_DIR / "provenance.json").write_text(json.dumps(summary, indent=2) + "\n")
    (RESULTS_DIR / "blindmachine_results.json").write_text(
        json.dumps(blindmachine_results, indent=2) + "\n"
    )
    (RESULTS_DIR / "verification.json").write_text(
        json.dumps(verification, indent=2) + "\n"
    )
    (WORK_DIR / "runtime_diagnostics.json").write_text(
        json.dumps(
            {
                "allele_frequency_count": count_result,
                "allele_frequency_with_variance": variance_result,
            },
            indent=2,
        )
        + "\n"
    )
    write_report(summary, allele_rows, fst_rows, group_rows)

    print(f"RESULT: PASS {STUDY_NAME}")
    print(f"  samples: {n} ({SAMPLES_PER_SUPER_POP} per super-population)")
    print(f"  variants: {len(variants)} from {REGION}")
    print(f"  suppressed group rows: {summary['summary_stats']['suppressed_group_rows']}")
    print(f"  results: {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
