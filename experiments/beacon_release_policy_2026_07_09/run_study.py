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
    GENOME_BUILD,
    PANEL_URL,
    cleartext_sums,
    dosage_vectors,
    fetch_vcf_text,
    parse_vcf,
    read_panel,
    repo_root_from_experiment,
    run_application,
    select_samples,
    sha256_file,
    sha256_text,
    verification_metadata,
    write_csv,
)


STUDY_NAME = "beacon_release_policy_2026_07_09"
SLUG = "public-genomics-e7-beacon-policy"
REGION = "22:16050000-17250000"
SAMPLES_PER_SUPER_POP = 5
VARIANT_COUNT = 40
MIN_GLOBAL_AF = 0.02
MAX_GLOBAL_AF = 0.60

RESULTS_DIR = STUDY_DIR / "results"
WORK_DIR = STUDY_DIR / "work"
REPO_ROOT = repo_root_from_experiment(STUDY_DIR)


def rounded(values: list[int], base: int) -> list[int]:
    return [int(base * round(value / base)) for value in values]


def recovery_count(diff: list[int | None], target: list[int]) -> int:
    return sum(1 for got, want in zip(diff, target) if got == want)


def policy_rows(full: list[int], base: list[int], target: list[int]) -> list[dict[str, Any]]:
    variant_count = len(target)

    def exact_diff_for_budget(budget: int) -> list[int | None]:
        return [
            full[index] - base[index] if index < budget else None
            for index in range(variant_count)
        ]

    rows: list[dict[str, Any]] = []
    policies = [
        {
            "policy": "no_policy_exact_adjacent_counts",
            "description": "Two adjacent exact-count releases are both available.",
            "diff": exact_diff_for_budget(variant_count),
            "comparable_adjacent_releases": True,
            "min_n_floor": 0,
            "query_budget": variant_count,
        },
        {
            "policy": "min_n_20_only",
            "description": "Minimum N=20 is satisfied by both N=25 and N=24 releases.",
            "diff": exact_diff_for_budget(variant_count),
            "comparable_adjacent_releases": True,
            "min_n_floor": 20,
            "query_budget": variant_count,
        },
        {
            "policy": "min_n_25_blocks_adjacent_base",
            "description": "N=24 adjacent base cohort is suppressed, so differencing is unavailable.",
            "diff": [None] * variant_count,
            "comparable_adjacent_releases": False,
            "min_n_floor": 25,
            "query_budget": 0,
        },
        {
            "policy": "cohort_freeze_single_release",
            "description": "Only one frozen cohort result is released; no adjacent comparison exists.",
            "diff": [None] * variant_count,
            "comparable_adjacent_releases": False,
            "min_n_floor": 20,
            "query_budget": 0,
        },
    ]
    for budget in (1, 2, 5, 10, 20):
        policies.append(
            {
                "policy": f"query_budget_{budget}",
                "description": f"Exact adjacent releases are limited to the first {budget} queries.",
                "diff": exact_diff_for_budget(min(budget, variant_count)),
                "comparable_adjacent_releases": True,
                "min_n_floor": 20,
                "query_budget": min(budget, variant_count),
            }
        )
    rounded_diff = [
        full_count - base_count
        for full_count, base_count in zip(rounded(full, 5), rounded(base, 5))
    ]
    policies.append(
        {
            "policy": "rounded_counts_to_nearest_5",
            "description": "Adjacent releases exist but counts are rounded before differencing.",
            "diff": rounded_diff,
            "comparable_adjacent_releases": True,
            "min_n_floor": 20,
            "query_budget": variant_count,
        }
    )

    target_nonzero = sum(1 for value in target if value > 0)
    for policy in policies:
        diff = policy["diff"]
        comparable = sum(1 for value in diff if value is not None)
        recovered = recovery_count(diff, target)
        recovered_nonzero = sum(
            1
            for got, want in zip(diff, target)
            if got == want and want > 0
        )
        rows.append(
            {
                "policy": policy["policy"],
                "description": policy["description"],
                "min_n_floor": policy["min_n_floor"],
                "query_budget": policy["query_budget"],
                "comparable_adjacent_releases": policy["comparable_adjacent_releases"],
                "variant_positions": variant_count,
                "target_nonzero_positions": target_nonzero,
                "positions_compared": comparable,
                "exact_dosage_positions_recovered": recovered,
                "exact_position_recovery_rate": recovered / variant_count,
                "nonzero_dosage_positions_recovered": recovered_nonzero,
                "nonzero_recovery_rate": (
                    recovered_nonzero / target_nonzero if target_nonzero else 0
                ),
            }
        )
    return rows


def query_budget_rows(full: list[int], base: list[int], target: list[int]) -> list[dict[str, Any]]:
    budgets = sorted({0, 1, 2, 3, 5, 10, 20, len(target)})
    rows = []
    for budget in budgets:
        diff = [
            full[index] - base[index] if index < budget else None
            for index in range(len(target))
        ]
        rows.append(
            {
                "query_budget": budget,
                "variant_positions": len(target),
                "positions_compared": min(budget, len(target)),
                "exact_dosage_positions_recovered": recovery_count(diff, target),
                "exact_position_recovery_rate": recovery_count(diff, target) / len(target),
            }
        )
    return rows


def write_report(summary: dict[str, Any], policies: list[dict[str, Any]]) -> None:
    best = {row["policy"]: row for row in policies}
    lines = [
        "# Beacon Release-Policy Experiment",
        "",
        f"- Source: IGSR/1000 Genomes Phase 3 `20130502`",
        f"- Region: `{REGION}`",
        f"- Cohorts compared: N={summary['included_n']} versus adjacent N={summary['base_n']}",
        f"- Variants: {summary['variant_count']} complete-call biallelic SNPs",
        f"- Paper evidence URL: <{summary['verification']['paper_evidence_url']}>",
        "",
        "## Main Result",
        "",
        "| Policy | Adjacent releases? | Query budget | Recovery rate | Nonzero recovery |",
        "|---|---:|---:|---:|---:|",
    ]
    for key in [
        "no_policy_exact_adjacent_counts",
        "min_n_20_only",
        "min_n_25_blocks_adjacent_base",
        "cohort_freeze_single_release",
        "query_budget_5",
        "rounded_counts_to_nearest_5",
    ]:
        row = best[key]
        lines.append(
            "| {policy} | {adjacent} | {budget} | {rate:.3f} | {nonzero:.3f} |".format(
                policy=row["policy"],
                adjacent=row["comparable_adjacent_releases"],
                budget=row["query_budget"],
                rate=row["exact_position_recovery_rate"],
                nonzero=row["nonzero_recovery_rate"],
            )
        )
    lines.extend(
        [
            "",
            "Exact adjacent aggregate counts recover the held-out public sample's "
            "dosage vector by subtraction. A minimum-N floor only helps if it "
            "blocks adjacent releases; min-N alone does not protect against "
            "two comparable cohorts above the floor. Cohort freeze and query "
            "budgets are therefore release-governance controls, not crypto features.",
            "",
            "## Validation",
            "",
            "- `allele_frequency_count` matched cleartext counts for both adjacent cohorts.",
            "- The exact-count difference matched the held-out target vector.",
            "- Per-sample target traces were written only under ignored `work/`.",
            "",
            "## Interpretation Boundary",
            "",
            "This is a public-data release-policy demonstration. It does not identify "
            "a private person and does not publish the target sample's genotype trace.",
            "",
        ]
    )
    (RESULTS_DIR / "report.md").write_text("\n".join(lines))


def main() -> int:
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

    target_sample_id = sample_order[0]
    target_vector = vectors[target_sample_id]
    base_vectors = {sample_id: vector for sample_id, vector in vectors.items() if sample_id != target_sample_id}
    full_sums, _ = cleartext_sums(vectors)
    base_sums, _ = cleartext_sums(base_vectors)

    full_result = run_application(REPO_ROOT, "allele_frequency_count", vectors)
    base_result = run_application(REPO_ROOT, "allele_frequency_count", base_vectors)
    if full_result["decoded"]["allele_counts"] != full_sums:
        raise RuntimeError("included cohort app output mismatch")
    if base_result["decoded"]["allele_counts"] != base_sums:
        raise RuntimeError("base cohort app output mismatch")
    if [a - b for a, b in zip(full_sums, base_sums)] != target_vector:
        raise RuntimeError("adjacent differencing did not recover the target vector")

    (WORK_DIR / "target_trace.json").write_text(
        json.dumps(
            {
                "target_sample_id": target_sample_id,
                "target_vector": target_vector,
                "note": "ignored per-sample attack trace; not committed",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    policies = policy_rows(full_sums, base_sums, target_vector)
    budgets = query_budget_rows(full_sums, base_sums, target_vector)
    write_csv(RESULTS_DIR / "policy_risk_summary.csv", policies)
    write_csv(RESULTS_DIR / "query_budget_curve.csv", budgets)

    verification = verification_metadata(
        SLUG,
        "bash docs/paper/experiments/e7_beacon_release_policy.sh",
    )
    summary = {
        "study": STUDY_NAME,
        "accessed_on_utc": ACCESS_DATE,
        "source": {
            "panel_url": PANEL_URL,
            "vcf_url": CHR22_VCF_URL,
            "region": REGION,
            "genome_build": GENOME_BUILD,
            "release": "1000 Genomes Project Phase 3 integrated callset, 20130502",
            "sample_selection_rule": (
                "take the first five samples encountered for each super-population "
                "in order EUR, EAS, AMR, AFR, SAS; use the first selected sample "
                "as the held-out adjacent-cohort target"
            ),
            "target_sample_sha256": sha256_text(target_sample_id),
        },
        "included_n": len(vectors),
        "base_n": len(base_vectors),
        "variant_count": len(variants),
        "target_nonzero_positions": sum(1 for value in target_vector if value > 0),
        "applications": ["allele_frequency_count"],
        "privacy_boundary": {
            "individual_level_material": "kept under ignored work/",
            "committed_outputs": "aggregate policy metrics only",
            "interpretation": "release-governance demonstration, not an identification workflow",
        },
        "verification": verification,
        "blindmachine_results": {
            "included_result_sha256": full_result["crypto_artifacts"]["result_sha256"],
            "base_result_sha256": base_result["crypto_artifacts"]["result_sha256"],
        },
    }
    aggregate_risk = {
        "study": STUDY_NAME,
        "variant_count": len(variants),
        "included_n": len(vectors),
        "base_n": len(base_vectors),
        "target_nonzero_positions": summary["target_nonzero_positions"],
        "policies": {
            row["policy"]: {
                "positions_compared": row["positions_compared"],
                "exact_dosage_positions_recovered": row["exact_dosage_positions_recovered"],
                "exact_position_recovery_rate": row["exact_position_recovery_rate"],
                "nonzero_recovery_rate": row["nonzero_recovery_rate"],
            }
            for row in policies
        },
        "interpretation": (
            "Exact adjacent releases recover the held-out public sample's dosage "
            "vector by subtraction; release governance blocks or limits the "
            "comparison surface."
        ),
    }
    (RESULTS_DIR / "provenance.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (RESULTS_DIR / "verification.json").write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n")
    (RESULTS_DIR / "aggregate_risk.json").write_text(json.dumps(aggregate_risk, indent=2, sort_keys=True) + "\n")
    (RESULTS_DIR / "blindmachine_results.json").write_text(
        json.dumps({"included": full_result, "base": base_result}, indent=2, sort_keys=True) + "\n"
    )
    write_report(summary, policies)
    manifest = {
        "result_files": {
            path.name: sha256_file(path)
            for path in sorted(RESULTS_DIR.glob("*"))
            if path.is_file() and path.name != "manifest.json"
        }
    }
    (RESULTS_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(f"RESULT: PASS {STUDY_NAME}")
    print(f"  samples: {len(vectors)} vs adjacent {len(base_vectors)}")
    print(f"  variants: {len(variants)}")
    print(f"  paper verification: {verification['paper_evidence_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
