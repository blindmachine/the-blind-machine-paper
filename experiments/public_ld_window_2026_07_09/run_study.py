#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import sys

SCRIPT_PATH = Path(__file__).resolve()
STUDY_DIR = SCRIPT_PATH.parent
EXPERIMENTS_DIR = STUDY_DIR.parent
sys.path.insert(0, str(EXPERIMENTS_DIR))

from public_genomics_common import (  # noqa: E402
    ACCESS_DATE,
    CHR22_VCF_URL,
    DataUnavailable,
    GENOME_BUILD,
    PANEL_URL,
    dosage_vectors,
    ensure_bcftools,
    ensure_tenseal_runtime,
    fetch_vcf_text,
    mean,
    require_bundle,
    parse_vcf,
    read_panel,
    repo_root_from_experiment,
    run_application,
    select_samples,
    sha256_file,
    verification_metadata,
    write_csv,
)


STUDY_NAME = "public_ld_window_2026_07_09"
SLUG = "public-genomics-e8-ld-window"
REGION = "22:16050000-16900000"
SAMPLES_PER_SUPER_POP = 5
VARIANT_COUNT = 12
MIN_GLOBAL_AF = 0.05
MAX_GLOBAL_AF = 0.95
SOURCE_PAGES = {
    "igsr_data": "https://www.internationalgenome.org/data/",
    "permission": (
        "https://www.internationalgenome.org/faq/"
        "do-i-need-permission-to-use-igsr-data-in-my-own-scientific-research/"
    ),
    "password": "https://www.internationalgenome.org/faq/do-i-need-a-password-to-access-igsr-data/",
    "phase3": "https://www.internationalgenome.org/category/phase-3/",
    "release_directory": "https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502/",
}
LOCAL_VERIFICATION_COMMAND = (
    "python3 -m pytest applications/genotype_pair_ld/tests && "
    "bash docs/paper/experiments/e8_public_ld_window.sh && "
    "python3 -m json.tool docs/paper/experiments/public_ld_window_2026_07_09/"
    "results/provenance.json >/dev/null && "
    "python3 -m json.tool docs/paper/experiments/public_ld_window_2026_07_09/"
    "results/verification.json >/dev/null"
)

RESULTS_DIR = STUDY_DIR / "results"
WORK_DIR = STUDY_DIR / "work"
REPO_ROOT = repo_root_from_experiment(STUDY_DIR)


def cleartext_ld(vectors: dict[str, list[int]], length: int) -> dict[str, list[Any]]:
    pair_count = length - 1
    moments = {
        "sum_a": [0] * pair_count,
        "sum_b": [0] * pair_count,
        "sum_a2": [0] * pair_count,
        "sum_b2": [0] * pair_count,
        "sum_ab": [0] * pair_count,
    }
    for vector in vectors.values():
        for index in range(pair_count):
            a = vector[index]
            b = vector[index + 1]
            moments["sum_a"][index] += a
            moments["sum_b"][index] += b
            moments["sum_a2"][index] += a * a
            moments["sum_b2"][index] += b * b
            moments["sum_ab"][index] += a * b
    return moments


def ld_rows(variants, decoded: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(decoded["pair_count"]):
        rows.append(
            {
                "pair_index": index + 1,
                "coordinate_a": variants[index].coordinate,
                "coordinate_b": variants[index + 1].coordinate,
                "n_samples": decoded["n_contributors"],
                "sum_a": decoded["sum_a"][index],
                "sum_b": decoded["sum_b"][index],
                "sum_ab": decoded["sum_ab"][index],
                "covariance": decoded["covariance"][index],
                "r2": decoded["r2"][index],
            }
        )
    return rows


def write_report(summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    top_rows = sorted(rows, key=lambda row: row["r2"] or 0, reverse=True)[:8]
    lines = [
        "# Public 1000 Genomes LD Window",
        "",
        f"- Source: IGSR/1000 Genomes Phase 3 `20130502`",
        f"- Region: `{REGION}`",
        f"- Samples: {summary['sample_count']} public samples",
        f"- Variants: {summary['variant_count']} complete-call biallelic SNPs",
        f"- Adjacent pairs: {summary['pair_count']}",
        "- Application: draft `genotype_pair_ld`",
        f"- blindmachine.org verification: `{summary['verification']['blindmachine_org']['status']}`",
        "",
        "## Strongest Adjacent-Pair LD Signals",
        "",
        "| Pair | Coordinate A | Coordinate B | covariance | r2 |",
        "|---:|---|---|---:|---:|",
    ]
    for row in top_rows:
        lines.append(
            "| {idx} | `{a}` | `{b}` | {cov:.4f} | {r2} |".format(
                idx=row["pair_index"],
                a=row["coordinate_a"],
                b=row["coordinate_b"],
                cov=row["covariance"],
                r2=f"{row['r2']:.4f}" if row["r2"] is not None else "",
            )
        )
    lines.extend(
        [
            "",
            "## Validation",
            "",
            "- `genotype_pair_ld` encrypted product moments matched the cleartext oracle exactly.",
            "- LD-style covariance and r2 were derived post-decrypt from aggregate moments.",
            "- Individual-level genotype vectors were written only under ignored `work/`.",
            "",
            "## Interpretation Boundary",
            "",
            "This is a small public-data workflow demonstration of an encrypted-product "
            "application. It is not a population-scale LD reference panel.",
            "",
        ]
    )
    (RESULTS_DIR / "report.md").write_text("\n".join(lines))


def main() -> int:
    ensure_tenseal_runtime(REPO_ROOT, SCRIPT_PATH)
    ensure_bcftools()
    require_bundle(REPO_ROOT, "genotype_pair_ld")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    panel = read_panel(WORK_DIR)
    selected = select_samples(panel, samples_per_super_pop=SAMPLES_PER_SUPER_POP)
    vcf_text = fetch_vcf_text(
        WORK_DIR,
        selected,
        region=REGION,
        min_global_af=MIN_GLOBAL_AF,
        max_global_af=MAX_GLOBAL_AF,
    )
    sample_order, variants = parse_vcf(vcf_text, selected, variant_count=VARIANT_COUNT)
    vectors = dosage_vectors(sample_order, variants, work_dir=WORK_DIR)
    app_result = run_application(REPO_ROOT, "genotype_pair_ld", vectors)
    decoded = app_result["decoded"]
    expected = cleartext_ld(vectors, len(variants))
    for key, values in expected.items():
        if decoded[key] != values:
            raise RuntimeError(f"{key} did not match cleartext oracle")

    rows = ld_rows(variants, decoded)
    write_csv(RESULTS_DIR / "ld_pairs.csv", rows)
    (RESULTS_DIR / "cleartext_oracle.json").write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n"
    )

    verification = verification_metadata(
        SLUG,
        LOCAL_VERIFICATION_COMMAND,
    )
    verification["blindmachine_org"] = {
        "status": "not_published",
        "reason": (
            "Hosted verification certificate generation requires a published "
            "application bundle/result and server credentials. This E8 run is a "
            "local aggregate-only public-data experiment."
        ),
        "local_verification_command": LOCAL_VERIFICATION_COMMAND,
    }
    verification["local_verification"] = {
        "status": "passed",
        "command": LOCAL_VERIFICATION_COMMAND,
        "checks": {
            "exact_moment_matches": {key: decoded[key] == values for key, values in expected.items()},
            "all_exact_moments_match": all(decoded[key] == values for key, values in expected.items()),
        },
    }
    summary = {
        "study": STUDY_NAME,
        "accessed_on_utc": ACCESS_DATE,
        "source": {
            "why_selected": (
                "IGSR/1000 Genomes Phase 3 is an official public multi-sample "
                "human genotype VCF suitable for a small LD workflow demo."
            ),
            "source_pages": SOURCE_PAGES,
            "panel_url": PANEL_URL,
            "vcf_url": CHR22_VCF_URL,
            "region": REGION,
            "genome_build": GENOME_BUILD,
            "release": "1000 Genomes Project Phase 3 integrated callset, 20130502",
            "sample_selection_rule": (
                "take the first five samples encountered for each super-population "
                "in order EUR, EAS, AMR, AFR, SAS"
            ),
            "variant_selection_rule": (
                "first complete-call, biallelic, polymorphic SNPs in the chr22 "
                "window with IGSR global AF between 0.05 and 0.95"
            ),
            "pair_rule": "adjacent variant pairs in selected coordinate order",
            "rejected_sources": [
                {
                    "source": "TCGA/GDC and dbGaP disease cohorts",
                    "reason": "controlled-access human genomic data is out of scope",
                },
                {
                    "source": "Genome in a Bottle",
                    "reason": "single-sample truth sets are not suitable for cohort LD",
                },
            ],
        },
        "sample_count": len(vectors),
        "variant_count": len(variants),
        "pair_count": decoded["pair_count"],
        "selected_sample_ids_committed": False,
        "application": "genotype_pair_ld",
        "application_status": "draft local application; not yet production signed",
        "summary_stats": {
            "mean_r2": mean([row["r2"] for row in rows]),
            "max_r2": max(row["r2"] or 0 for row in rows),
        },
        "validation": verification["local_verification"]["checks"],
        "work_artifacts": {
            "sample_panel_sha256": sha256_file(WORK_DIR / "integrated_call_samples_v3.20130502.ALL.panel"),
            "selected_samples_sha256": sha256_file(WORK_DIR / "selected_samples.txt"),
            "vcf_subset_sha256": sha256_file(sorted(WORK_DIR.glob("*.vcf"))[0]),
        },
        "privacy_boundary": {
            "individual_level_material": "kept under ignored work/",
            "committed_outputs": "aggregate adjacent-pair LD moments only",
            "interpretation": "workflow demonstration only; not a reference LD panel",
        },
        "verification": verification,
    }
    (RESULTS_DIR / "provenance.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (RESULTS_DIR / "verification.json").write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n")
    public_app_result = dict(app_result)
    public_app_result["crypto_artifacts"] = {
        key: value
        for key, value in app_result["crypto_artifacts"].items()
        if key != "ciphertext_sha256s"
    }
    (RESULTS_DIR / "blindmachine_results.json").write_text(
        json.dumps(public_app_result, indent=2, sort_keys=True) + "\n"
    )
    (WORK_DIR / "runtime_diagnostics.json").write_text(
        json.dumps(app_result, indent=2, sort_keys=True) + "\n"
    )
    write_report(summary, rows)
    manifest = {
        "result_files": {
            path.name: sha256_file(path)
            for path in sorted(RESULTS_DIR.glob("*"))
            if path.is_file() and path.name != "manifest.json"
        }
    }
    (RESULTS_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(f"RESULT: PASS {STUDY_NAME}")
    print(f"  samples: {len(vectors)}")
    print(f"  variants: {len(variants)}")
    print(f"  pairs: {decoded['pair_count']}")
    print(f"  paper verification: {verification['paper_evidence_url']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DataUnavailable as exc:
        print(f"SKIP: {exc}", flush=True)
        raise SystemExit(3)
