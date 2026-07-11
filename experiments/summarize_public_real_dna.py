#!/usr/bin/env python3
"""Generate paper-facing summary tables/figures for public-real-DNA experiments."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "public_real_dna_summary_2026_07_09"
RESULTS_DIR = OUT_DIR / "results"

E5 = ROOT / "real_human_dna_igsr_2026_07_09" / "results"
E6 = ROOT / "public_af_fst_2026_07_09" / "results"
E7 = ROOT / "beacon_release_policy_2026_07_09" / "results"
E8 = ROOT / "public_ld_window_2026_07_09" / "results"

BG = "#fbfbf8"
INK = "#1c2526"
AXIS = "#9aa3a3"
SUB = "#536264"
GRID = "#ecebe4"


def read_json(path: Path):
    return json.loads(path.read_text())


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def svg_bar_chart(
    path: Path,
    *,
    title: str,
    labels: list[str],
    values: list[float],
    value_label: str,
    color: str = "#2f6f73",
    flagged: set[int] | None = None,
    flag_color: str = "#b48a6a",
    fmt: str = "{:.3g}",
    width: int = 820,
    height: int = 380,
) -> None:
    flagged = flagged or set()
    margin_left, margin_right, margin_top, margin_bottom = 92, 40, 60, 78
    chart_w = width - margin_left - margin_right
    chart_h = height - margin_top - margin_bottom
    # Headroom so the value label above a full-height bar is not clipped.
    max_value = max(values) if values else 1.0
    max_value = max_value * 1.16 if max_value > 0 else 1.0
    gap = 26
    bar_w = (chart_w - gap * (len(values) - 1)) / len(values)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="100%" height="100%" fill="{BG}"/>',
        f'<text x="{margin_left}" y="30" font-family="Arial, sans-serif" font-size="19" font-weight="700" fill="{INK}">{escape(title)}</text>',
        f'<line x1="{margin_left}" y1="{margin_top + chart_h}" x2="{width - margin_right}" y2="{margin_top + chart_h}" stroke="{AXIS}" stroke-width="1"/>',
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + chart_h}" stroke="{AXIS}" stroke-width="1"/>',
        f'<text x="16" y="{margin_top - 12}" font-family="Arial, sans-serif" font-size="12" fill="{SUB}">{escape(value_label)}</text>',
    ]

    for index, (label, value) in enumerate(zip(labels, values)):
        x = margin_left + index * (bar_w + gap)
        bar_h = chart_h * (value / max_value)
        y = margin_top + chart_h - bar_h
        fill = flag_color if index in flagged else color
        mark = " †" if index in flagged else ""
        parts.extend(
            [
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" rx="3" fill="{fill}"/>',
                f'<text x="{x + bar_w / 2:.1f}" y="{y - 8:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="{INK}">{fmt.format(value)}{mark}</text>',
                f'<text x="{x + bar_w / 2:.1f}" y="{height - 30}" text-anchor="middle" font-family="Arial, sans-serif" font-size="12.5" fill="{INK}">{escape(label)}</text>',
            ]
        )
    parts.append("</svg>\n")
    path.write_text("\n".join(parts))


def svg_concordance(
    path: Path,
    *,
    title: str,
    xs: list[float],
    ys: list[float],
    xlabel: str,
    ylabel: str,
    note: str,
    width: int = 560,
    height: int = 520,
) -> None:
    """Square concordance scatter with a y=x reference line and 0..1 gridlines."""
    margin_left, margin_right, margin_top, margin_bottom = 76, 28, 58, 62
    chart_w = width - margin_left - margin_right
    chart_h = height - margin_top - margin_bottom

    def sx(v: float) -> float:
        return margin_left + chart_w * v

    def sy(v: float) -> float:
        return margin_top + chart_h * (1 - v)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="100%" height="100%" fill="{BG}"/>',
        f'<text x="{margin_left}" y="28" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="{INK}">{escape(title)}</text>',
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + chart_h}" stroke="{AXIS}" stroke-width="1"/>',
        f'<line x1="{margin_left}" y1="{margin_top + chart_h}" x2="{margin_left + chart_w}" y2="{margin_top + chart_h}" stroke="{AXIS}" stroke-width="1"/>',
    ]
    for tick in (0.0, 0.25, 0.5, 0.75, 1.0):
        gx, gy = sx(tick), sy(tick)
        parts.extend(
            [
                f'<line x1="{gx:.1f}" y1="{margin_top}" x2="{gx:.1f}" y2="{margin_top + chart_h}" stroke="{GRID}" stroke-width="1"/>',
                f'<line x1="{margin_left}" y1="{gy:.1f}" x2="{margin_left + chart_w}" y2="{gy:.1f}" stroke="{GRID}" stroke-width="1"/>',
                f'<text x="{gx:.1f}" y="{margin_top + chart_h + 18}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="{SUB}">{tick:g}</text>',
                f'<text x="{margin_left - 8}" y="{gy + 4:.1f}" text-anchor="end" font-family="Arial, sans-serif" font-size="11" fill="{SUB}">{tick:g}</text>',
            ]
        )
    # y = x reference line.
    parts.append(
        f'<line x1="{sx(0.0):.1f}" y1="{sy(0.0):.1f}" x2="{sx(1.0):.1f}" y2="{sy(1.0):.1f}" '
        f'stroke="{AXIS}" stroke-width="1.2" stroke-dasharray="5 4"/>'
    )
    parts.append(
        f'<text x="{sx(0.60):.1f}" y="{sy(0.60) + 16:.1f}" font-family="Arial, sans-serif" '
        f'font-size="11" fill="{SUB}">panel = global (y = x)</text>'
    )
    for x, y in zip(xs, ys):
        parts.append(
            f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="5.5" fill="#2f6f73" '
            f'fill-opacity="0.82" stroke="{INK}" stroke-width="0.6"/>'
        )
    parts.extend(
        [
            f'<text x="{margin_left + chart_w / 2:.1f}" y="{height - 16}" text-anchor="middle" '
            f'font-family="Arial, sans-serif" font-size="13" fill="{INK}">{escape(xlabel)}</text>',
            f'<text x="18" y="{margin_top + chart_h / 2:.1f}" text-anchor="middle" '
            f'font-family="Arial, sans-serif" font-size="13" fill="{INK}" '
            f'transform="rotate(-90 18 {margin_top + chart_h / 2:.1f})">{escape(ylabel)}</text>',
            f'<text x="{margin_left + 8}" y="{margin_top + 16}" font-family="Arial, sans-serif" '
            f'font-size="11.5" fill="{SUB}">{escape(note)}</text>',
        ]
    )
    parts.append("</svg>\n")
    path.write_text("\n".join(parts))


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    e5_rows = read_csv(E5 / "allele_frequencies.csv")
    e6 = read_json(E6 / "provenance.json")
    e7 = read_json(E7 / "provenance.json")
    e8 = read_json(E8 / "provenance.json")
    e6_verification = read_json(E6 / "verification.json")
    policy_rows = read_csv(E7 / "policy_risk_summary.csv")
    ld_rows = read_csv(E8 / "ld_pairs.csv")

    e5_samples = int(e5_rows[0]["n_samples"]) if e5_rows else 0
    e5_variants = len(e5_rows)
    e5_mean_abs_delta = (
        sum(abs(float(r["allele_frequency"]) - float(r["igsr_global_af"])) for r in e5_rows) / e5_variants
        if e5_variants
        else 0.0
    )

    summary_rows = [
        {
            "experiment": "E5 AF panel",
            "public_source": "IGSR/1000 Genomes Phase 3 chr22",
            "samples": e5_samples,
            "variants_or_queries": e5_variants,
            "application": "allele_frequency_count; allele_frequency_with_variance",
            "primary_result": (
                f"exact first/second moments; mean abs AF delta vs IGSR global {e5_mean_abs_delta:.4f}"
            ),
            "paper_evidence_url": "(local run; artifacts under real_human_dna_igsr_2026_07_09/results)",
        },
        {
            "experiment": "E6 AF/FST panel",
            "public_source": "IGSR/1000 Genomes Phase 3 chr22",
            "samples": e6["sample_count"],
            "variants_or_queries": e6["variant_count"],
            "application": "allele_frequency_count; allele_frequency_with_variance",
            "primary_result": f"max FST-like={e6['summary_stats']['max_fst_like']:.4f}; suppressed rows={e6['summary_stats']['suppressed_group_rows']}",
            "paper_evidence_url": e6_verification.get(
                "paper_evidence_url",
                "https://blindmachine.org/verify/paper/public-genomics-e6-af-fst",
            ),
        },
        {
            "experiment": "E7 Beacon policy",
            "public_source": "IGSR/1000 Genomes Phase 3 chr22",
            "samples": e7["included_n"],
            "variants_or_queries": e7["variant_count"],
            "application": "allele_frequency_count plus release-policy harness",
            "primary_result": f"adjacent N={e7['included_n']} vs {e7['base_n']} release-risk comparison",
            "paper_evidence_url": e7["verification"]["paper_evidence_url"],
        },
        {
            "experiment": "E8 LD window",
            "public_source": "IGSR/1000 Genomes Phase 3 chr22",
            "samples": e8["sample_count"],
            "variants_or_queries": e8["pair_count"],
            "application": "genotype_pair_ld draft application",
            "primary_result": f"max r2={e8['summary_stats']['max_r2']:.4f}; exact moments match oracle",
            "paper_evidence_url": e8["verification"]["paper_evidence_url"],
        },
    ]
    write_csv(RESULTS_DIR / "public_real_dna_experiments.csv", summary_rows)

    policy_focus = [
        row
        for row in policy_rows
        if row["policy"]
        in {
            "no_policy_exact_adjacent_counts",
            "min_n_20_only",
            "min_n_25_blocks_adjacent_base",
            "cohort_freeze_single_release",
            "query_budget_5",
            "rounded_counts_to_nearest_5",
        }
    ]
    write_csv(
        RESULTS_DIR / "beacon_policy_table.csv",
        [
            {
                "policy": row["policy"],
                "positions_compared": row["positions_compared"],
                "exact_position_recovery_rate": row["exact_position_recovery_rate"],
                "nonzero_recovery_rate": row["nonzero_recovery_rate"],
            }
            for row in policy_focus
        ],
    )

    top_ld = sorted(
        ld_rows,
        key=lambda row: float(row["r2"]) if row["r2"] else -1,
        reverse=True,
    )[:6]
    write_csv(
        RESULTS_DIR / "ld_top_pairs_table.csv",
        [
            {
                "pair_index": row["pair_index"],
                "coordinate_a": row["coordinate_a"],
                "coordinate_b": row["coordinate_b"],
                "covariance": row["covariance"],
                "r2": row["r2"],
            }
            for row in top_ld
        ],
    )

    # Figure 6: E5 allele-frequency concordance (encrypted panel vs IGSR global).
    svg_concordance(
        RESULTS_DIR / "figure_e5_af_concordance.svg",
        title="E5: encrypted panel allele frequency vs IGSR global",
        xs=[float(r["igsr_global_af"]) for r in e5_rows],
        ys=[float(r["allele_frequency"]) for r in e5_rows],
        xlabel="IGSR global allele frequency",
        ylabel=f"Encrypted panel allele frequency ({e5_samples} samples)",
        note=(
            f"{e5_variants} SNPs · mean |Δ| = {e5_mean_abs_delta:.4f} "
            f"· decrypted counts equal the cleartext oracle exactly"
        ),
    )

    # Figure 7: E7 per-position recovery of the held-out sample by release policy.
    label_map = {
        "no_policy_exact_adjacent_counts": "no policy",
        "min_n_20_only": "min-N 20",
        "min_n_25_blocks_adjacent_base": "min-N 25",
        "cohort_freeze_single_release": "freeze",
        "query_budget_5": "budget 5",
        "rounded_counts_to_nearest_5": "round 5",
    }
    svg_bar_chart(
        RESULTS_DIR / "figure_beacon_policy_recovery.svg",
        title="E7: held-out-sample recovery by release policy",
        labels=[label_map[row["policy"]] for row in policy_focus],
        values=[
            float(row["exact_dosage_positions_recovered"]) / float(row["variant_positions"])
            for row in policy_focus
        ],
        value_label="fraction of 40 dosage positions recovered exactly",
        color="#8a5a44",
    )

    # Figure 8: E8 strongest adjacent-pair LD; flag small-count artifacts (r2 == 1).
    flagged = {i for i, row in enumerate(top_ld) if float(row["r2"] or 0.0) >= 0.999}
    svg_bar_chart(
        RESULTS_DIR / "figure_ld_top_r2.svg",
        title="E8: strongest adjacent-pair LD (r²) in the public chr22 window",
        labels=[f"pair {row['pair_index']}" for row in top_ld],
        values=[float(row["r2"]) if row["r2"] else 0.0 for row in top_ld],
        value_label="r²  († = small-count artifact, see caption)",
        color="#5c6b9b",
        flagged=flagged,
    )

    appendix = [
        "# Appendix: Public-Real-DNA Experiments",
        "",
        "These optional experiments use public IGSR/1000 Genomes Phase 3 data. "
        "They are not part of the no-real-data synthetic reproducibility harness; "
        "they demonstrate that the same application-governed workflow can be run "
        "on public human genotype data while committing only aggregate outputs.",
        "",
        "## Summary Table",
        "",
        "| Experiment | Samples | Variants/queries | Application | Primary result | Evidence page |",
        "|---|---:|---:|---|---|---|",
    ]
    for row in summary_rows:
        appendix.append(
            f"| {row['experiment']} | {row['samples']} | {row['variants_or_queries']} | "
            f"{row['application']} | {row['primary_result']} | {row['paper_evidence_url']} |"
        )
    appendix.extend(
        [
            "",
            "## Figures",
            "",
            "- `results/figure_e5_af_concordance.svg` plots the E5 encrypted panel allele "
            "frequency against the IGSR global frequency (concordance vs a y=x line).",
            "- `results/figure_beacon_policy_recovery.svg` shows the fraction of the 40 "
            "dosage positions recovered exactly under each release policy.",
            "- `results/figure_ld_top_r2.svg` shows the strongest adjacent-pair LD `r2` "
            "values, with small-count artifacts flagged.",
            "",
            "## Boundaries",
            "",
            "- Individual VCF slices, sample lists, raw vectors, and attack traces remain in ignored `work/` directories.",
            "- The public evidence URLs under `/verify/paper/...` are paper evidence packages, not hosted private-cohort computation certificates.",
            "- The hosted `/verify/:certificate_hash` status is `not_published` for all three local runs.",
            "- These small public panels are workflow demonstrations, not clinical results or population estimates.",
            "",
        ]
    )
    (OUT_DIR / "appendix.md").write_text("\n".join(appendix))
    print(f"wrote {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
