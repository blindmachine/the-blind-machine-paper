#!/usr/bin/env python3
"""Build PaperVerificationPackage JSON for public-real-DNA experiments."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
VERIFY_DIR = ROOT / "verification"
EXP_DIR = ROOT / "experiments"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def file_entry(path: str, role: str) -> dict:
    if path.startswith("applications/"):
        full = REPO_ROOT / path
        display_path = path
    else:
        full = ROOT / path
        display_path = f"docs/paper/{path}"
    return {
        "path": display_path,
        "role": role,
        "bytes": full.stat().st_size,
        "sha256": sha256(full),
    }


def csv_rows(path: str) -> int:
    with (ROOT / path).open(newline="") as handle:
        return max(sum(1 for _ in csv.reader(handle)) - 1, 0)


def table(path: str, purpose: str) -> dict:
    return {
        "path": f"docs/paper/{path}",
        "rows": csv_rows(path),
        "purpose": purpose,
    }


def app(slug: str, tier: str, digest: str, env_lock: str, signature: str | None = None) -> dict:
    out = {
        "slug": slug,
        "tier": tier,
        "digest": digest,
        "env_lock_digest": env_lock,
    }
    if signature:
        out["signature"] = signature
    else:
        out["status"] = "draft local application, not production signed"
    return out


APPS = {
    "afc": app(
        "allele_frequency_count",
        "additive-BFV-exact",
        "b94bd9320ea0f15b2ec265ecd0cf855f273548ffb920f395212256f4d4664eed",
        "afd4ed396fee544ee91774f8fe3cc1b9d26d6796558b0fa0897660655785963f",
        "429986382a29716079cabbe3029fe1925f92f49a59ba027946e5bed23d0f60e180a25a621dd41e407ceb7ba02d4e65a0094f15e938bec1586b3f0d1dd258030a",
    ),
    "afv": app(
        "allele_frequency_with_variance",
        "mult-supporting-BFV-exact",
        "b48cdffa32c46d2a5de95010ea12e434593b2af2179fcedf7f8e36ebc7245eec",
        "df1559d9c292f359ceb1c0ccb75619688a210e98c4838fdee620dc2ffd048c8d",
        "b933be1a387d57e1b03c7c5b0cde9edd25c39fa60897cf4d8e1b9cb08f42aa068ae3762682fb90adb04c61e5cd412c734e3efd07a2e4a2418e550aabdc02ba00",
    ),
    "ld": app(
        "genotype_pair_ld",
        "mult-supporting-BFV-exact-draft",
        "e9567ab844b6a575ba96227df28103b8b82b8182da0e50075cd6750001f47911",
        "99ba064e0db76099c6eef9001f68b515300472d378ba81fb1fa467efa7add6cc",
    ),
}


def result_files(base: str) -> list[dict]:
    files = []
    for path in sorted((ROOT / base / "results").glob("*")):
        if path.is_file():
            files.append(file_entry(str(path.relative_to(ROOT)), "result_artifact"))
    return files


def package(
    *,
    slug: str,
    title: str,
    subtitle: str,
    summary: str,
    command: str,
    base: str,
    stats: dict,
    applications: list[dict],
    tables: list[dict],
    claims: list[tuple[str, str]],
    extra_files: list[str] | None = None,
) -> dict:
    files = [
        file_entry(command.replace("bash docs/paper/", ""), "reproducer"),
        file_entry(f"{base}/run_study.py", "reproducer"),
    ] + result_files(base)
    for path in extra_files or []:
        files.append(file_entry(path, "draft_application"))

    return {
        "slug": slug,
        "schema": "org.blindmachine.paper_verification_package.v1",
        "title": title,
        "subtitle": subtitle,
        "summary": summary,
        "source_commit": None,
        "source_state": "working tree public-real-DNA experiment; replace with a release commit or tag before camera-ready submission",
        "commands": [
            {
                "label": "Reproduce locally",
                "command": command,
                "description": "Runs the public-data experiment and rewrites aggregate result artifacts.",
            },
            {
                "label": "Validate JSON artifacts",
                "command": f"python3 -m json.tool docs/paper/{base}/results/provenance.json >/dev/null && python3 -m json.tool docs/paper/{base}/results/verification.json >/dev/null",
                "description": "Checks machine-readable provenance and verification metadata.",
            },
        ],
        "stats": stats,
        "applications": applications,
        "claims": [{"claim": claim, "evidence": evidence} for claim, evidence in claims],
        "tables": tables,
        "files": files,
        "caveats": [
            "This package covers public-real-DNA local experiment evidence, not a hosted private-cohort ComputationCertificate.",
            "The hosted blindmachine.org /verify/:certificate_hash certificate URL is not published for this local run.",
            "Individual-level genotype vectors, selected sample lists, VCF subsets, and attack traces remain under ignored work/ directories.",
            "Small public sample panels demonstrate workflow mechanics, not medical claims or population estimates.",
        ],
    }


def main() -> int:
    VERIFY_DIR.mkdir(parents=True, exist_ok=True)

    e6 = json.loads((EXP_DIR / "public_af_fst_2026_07_09/results/provenance.json").read_text())
    e7 = json.loads((EXP_DIR / "beacon_release_policy_2026_07_09/results/provenance.json").read_text())
    e8 = json.loads((EXP_DIR / "public_ld_window_2026_07_09/results/provenance.json").read_text())

    packages = [
        package(
            slug="public-genomics-e6-af-fst",
            title="Public Genomics E6: AF/FST Panel",
            subtitle="Aggregate-only 1000 Genomes allele-frequency and FST-like panel.",
            summary="Binds the public-real-DNA AF/FST panel run over IGSR/1000 Genomes Phase 3 chr22 data.",
            command="bash docs/paper/experiments/e6_public_af_fst_panel.sh",
            base="experiments/public_af_fst_2026_07_09",
            stats={
                "samples": e6["sample_count"],
                "variants": e6["variant_count"],
                "suppressed_group_rows": e6["summary_stats"]["suppressed_group_rows"],
                "max_fst_like": round(e6["summary_stats"]["max_fst_like"], 6),
            },
            applications=[APPS["afc"], APPS["afv"]],
            tables=[
                table("experiments/public_af_fst_2026_07_09/results/allele_panel.csv", "Per-variant allele count, frequency, variance, and IGSR global AF comparison."),
                table("experiments/public_af_fst_2026_07_09/results/group_frequencies.csv", "Population aggregate rows with small-cell suppression."),
                table("experiments/public_af_fst_2026_07_09/results/fst_summary.csv", "FST-like heterozygosity contrast and group AF deltas."),
            ],
            claims=[
                ("Existing allele-frequency applications reproduce public-real-DNA aggregate moments exactly.", "blindmachine_results.json records exact agreement against cleartext sums."),
                ("Small subgroup rows are suppressed.", "provenance.json records the suppression policy and suppressed row count."),
            ],
        ),
        package(
            slug="public-genomics-e7-beacon-policy",
            title="Public Genomics E7: Beacon Release Policy",
            subtitle="Adjacent-cohort output-risk experiment over public 1000 Genomes genotypes.",
            summary="Binds the Beacon-style release-policy experiment showing why output governance is needed after encrypted computation.",
            command="bash docs/paper/experiments/e7_beacon_release_policy.sh",
            base="experiments/beacon_release_policy_2026_07_09",
            stats={
                "included_n": e7["included_n"],
                "base_n": e7["base_n"],
                "variants": e7["variant_count"],
                "target_nonzero_positions": e7["target_nonzero_positions"],
            },
            applications=[APPS["afc"]],
            tables=[
                table("experiments/beacon_release_policy_2026_07_09/results/policy_risk_summary.csv", "Policy-level exact-vector and nonzero recovery rates."),
                table("experiments/beacon_release_policy_2026_07_09/results/query_budget_curve.csv", "Exact recovery as a function of query budget."),
            ],
            claims=[
                ("Encryption protects computation, not every released aggregate answer.", "policy_risk_summary.csv shows exact adjacent releases recover the held-out target vector."),
                ("Min-N only helps when it blocks comparable adjacent releases.", "The min-N 20 row remains recoverable, while freeze/min-N 25 block differencing."),
            ],
        ),
        package(
            slug="public-genomics-e8-ld-window",
            title="Public Genomics E8: LD Window",
            subtitle="Draft encrypted-product genotype-pair LD moments over public 1000 Genomes genotypes.",
            summary="Binds the LD window experiment and draft genotype_pair_ld application.",
            command="bash docs/paper/experiments/e8_public_ld_window.sh",
            base="experiments/public_ld_window_2026_07_09",
            stats={
                "samples": e8["sample_count"],
                "variants": e8["variant_count"],
                "pairs": e8["pair_count"],
                "max_r2": round(e8["summary_stats"]["max_r2"], 6),
            },
            applications=[APPS["ld"]],
            tables=[
                table("experiments/public_ld_window_2026_07_09/results/ld_pairs.csv", "Adjacent-pair genotype product moments, covariance, and r2."),
            ],
            claims=[
                ("LD/r2 is a justified encrypted-product workload.", "genotype_pair_ld computes sum_g_a_g_b under encryption."),
                ("Encrypted product moments match a cleartext oracle exactly.", "cleartext_oracle.json and blindmachine_results.json agree on all integer moment vectors."),
            ],
            extra_files=[
                "applications/genotype_pair_ld/README.md",
                "applications/genotype_pair_ld/SECURITY.md",
                "applications/genotype_pair_ld/signed/manifest.yml",
                "applications/genotype_pair_ld/signed/local_data_owner.py",
                "applications/genotype_pair_ld/signed/local_project_owner.py",
                "applications/genotype_pair_ld/signed/server.py",
                "applications/genotype_pair_ld/tests/test_pair_ld.py",
                "applications/genotype_pair_ld/tests/test_local_loop.py",
            ],
        ),
    ]

    for item in packages:
        (VERIFY_DIR / f"{item['slug']}.json").write_text(json.dumps(item, indent=2, sort_keys=True) + "\n")
        print(f"wrote {item['slug']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
