#!/usr/bin/env python3
"""Consolidate raw experiment JSON into paper-facing CSV tables and ASSERT the
machine-independent invariants the paper's claims rest on. Exits non-zero if any
hard invariant fails, so `bash run_all.sh` is a one-command PASS/FAIL.

Reproducibility contract
------------------------
TIMING (ms), MEMORY (RSS), and COST (cents) are hardware-dependent; they are
recorded but never asserted. What a reviewer on ANY machine must reproduce
bit-for-bit — and what is ASSERTED here — is:

  INV-1  every benchmarked cell is bit-exact: max_error == 0, exact == true,
         feasibility == "ok" (the decrypted aggregate equals the cleartext oracle).
  INV-2  the two-tier taxonomy: the 4 additive-BFV applications and the 2
         multiplication-supporting-BFV applications are ALL bit-exact.
  INV-3  the payload premium DIRECTION: ciphertext/contribution grows
         additive < variance < covariance (ciphertext sizes are deterministic).
  INV-4  the differencing attack recovers a contributor EXACTLY on an unfrozen
         cohort (the honest "mitigated, not solved" evidence).
  INV-5  (E2, if run) every security-level cell (128/192/256) is bit-exact.
  INV-6  the live run EQUALS the committed results/expected/ reference values on
         the DETERMINISTIC columns, so the reference files are asserted invariants
         rather than silently-drifting documentation. Only byte-stable columns are
         asserted: the 128-bit ciphertext sizes (E1 table + E2 128-bit column) and
         the feasibility sizes. The 192/256-bit ciphertext sizes vary by tens of
         bytes across TenSEAL builds and are reported, not asserted.
  INV-7  the two published-study reproductions are bit-exact where the paper
         claims bit-exactness (E9 HEPRS: encrypted score == oracle, Pearson r vs
         HEPRS >= 0.9999999; E10 GWAS chi-square: integer sufficient statistics
         bit-exact, -log10(p) concordance R² == 1.0) and concordant where it
         claims concordance (E10 covariate-adjusted: R² >= 0.999). Wall-clock and
         memory in Tables 17-18 stay hardware-dependent and are NOT asserted.
"""
from __future__ import annotations

import csv
import json
import os
import sys

EXP = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(EXP, "results", "raw")
OUT = os.path.join(EXP, "results")

ADDITIVE = ["allele_frequency_count", "carrier_count", "cohort_histogram",
            "polygenic_score_aggregate"]
MULTIPLICATIVE = ["allele_frequency_with_variance", "genotype_phenotype_covariance"]
ALL_APPLICATIONS = ADDITIVE + MULTIPLICATIVE

_failures: list[str] = []
_checks = 0


class PartialResultError(Exception):
    """A raw result file exists but is empty or malformed — an interrupted run.

    Distinguished from a MISSING file (a not-yet-run experiment, which is a clean
    skip) so a partial run fails with an explicit invariant error instead of a raw
    JSONDecodeError traceback.
    """


def _load(tag: str):
    path = os.path.join(RAW, tag + ".json")
    if not os.path.exists(path):
        return None  # experiment not run in this profile → clean skip
    rel = os.path.relpath(path, EXP)
    with open(path) as handle:
        text = handle.read()
    if not text.strip():
        raise PartialResultError(
            f"{rel} is empty (0 bytes): a previous run was interrupted mid-cell. "
            f"Re-run from a clean state: `bash run_all.sh` (it now clears results/raw first).")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise PartialResultError(
            f"{rel} is not valid JSON ({exc}): a previous run was interrupted or wrote "
            f"partial output. Re-run from a clean state: `bash run_all.sh`.") from exc


def check(condition: bool, message: str) -> None:
    global _checks
    _checks += 1
    if condition:
        print(f"  ✓ {message}")
    else:
        _failures.append(message)
        print(f"  ✗ {message}")


def _write_csv(name: str, rows: list[dict]) -> None:
    if not rows:
        return
    with open(os.path.join(OUT, name), "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"    wrote results/{name} ({len(rows)} rows)")


def _cell_ok(cell: dict) -> bool:
    return bool(cell.get("exact")) and cell.get("max_error") == 0 and cell.get("feasibility") == "ok"


# --- E1: two-tier exactness taxonomy + payload-premium source data --------
def verify_e1() -> None:
    docs = {p: _load("e1__" + p) for p in ALL_APPLICATIONS}
    if not all(docs.values()):
        print("[E1] skipped (run e1_exactness_taxonomy.sh first)")
        return
    print("[E1] two-tier BFV exactness taxonomy (Table 6) + payload-premium source data (Table 7)")
    rows, ct_per_contrib = [], {}
    exact_additive, exact_mult = set(), set()
    for p in ALL_APPLICATIONS:
        tier = "additive-BFV-exact" if p in ADDITIVE else "mult-supporting-BFV-exact"
        for cell in docs[p]["cells"]:
            rows.append({
                "application": p, "tier": tier, "crypto": cell["crypto"],
                "n": cell["n"], "length": cell["length"], "security": cell["security"],
                "ct_bytes_per_contribution": int(cell["ct_bytes_per_contribution"]),
                "compute_ms": cell["compute_ms"], "cpu_seconds": cell["cpu_seconds"],
                "max_error": cell["max_error"], "exact": cell["exact"],
                "feasibility": cell["feasibility"],
            })
            check(_cell_ok(cell), f"INV-1  {p}: bit-exact (max_error=0, feasibility=ok)")
            if _cell_ok(cell):
                (exact_additive if p in ADDITIVE else exact_mult).add(p)
            ct_per_contrib[p] = int(cell["ct_bytes_per_contribution"])
    check(exact_additive == set(ADDITIVE),
          "INV-2  all 4 additive-BFV applications bit-exact (additive suffices for 4 of 6)")
    check(exact_mult == set(MULTIPLICATIVE),
          "INV-2  both multiplication-supporting-BFV applications bit-exact")
    _write_csv("table_b_exactness.csv", rows)

    afc = ct_per_contrib.get("allele_frequency_count")
    var = ct_per_contrib.get("allele_frequency_with_variance")
    cov = ct_per_contrib.get("genotype_phenotype_covariance")
    if None in (afc, var, cov) or not afc:
        # A degenerate/partial cell (missing or zero ciphertext size) must not
        # crash the premium division below — record it as an explicit invariant
        # failure so the harness reports FAIL cleanly instead of a traceback.
        check(False,
              "INV-3  payload premium needs nonzero additive/variance/covariance "
              f"ciphertext sizes (got afc={afc}, var={var}, cov={cov})")
    else:
        check(afc < var < cov,
              f"INV-3  payload premium ordering additive({afc}B) < variance({var}B) < covariance({cov}B)")
        _write_csv("table_c_premium.csv", [
            {"arm": "additive (afc)", "ct_bytes_per_contribution": afc, "premium_x": 1.0},
            {"arm": "multiplicative (variance)", "ct_bytes_per_contribution": var,
             "premium_x": round(var / afc, 2)},
            {"arm": "multiplicative (covariance)", "ct_bytes_per_contribution": cov,
             "premium_x": round(cov / afc, 2)},
        ])


# --- E2: security matrix (optional) ---------------------------------------
def verify_e2() -> None:
    docs = {p: _load("e2__" + p) for p in ALL_APPLICATIONS}
    if not any(docs.values()):
        print("[E2] skipped (run e2_security_matrix.sh, or `run_all.sh full`)")
        return
    print("[E2] security-level matrix 128/192/256 (Table 8)")
    rows = []
    for p in ALL_APPLICATIONS:
        if not docs[p]:
            continue
        for cell in docs[p]["cells"]:
            rows.append({
                "application": p, "security": cell["security"], "crypto": cell["crypto"],
                "ct_bytes_per_contribution": int(cell["ct_bytes_per_contribution"]),
                "compute_ms": cell["compute_ms"], "max_error": cell["max_error"],
                "exact": cell["exact"],
            })
            check(_cell_ok(cell), f"INV-5  {p}@{cell['security']}-bit: bit-exact")
    _write_csv("security_matrix.csv", rows)


# --- E3: feasibility (optional; recorded, not asserted beyond exactness) ---
def verify_e3() -> None:
    doc = _load("e3__afc")
    if not doc:
        print("[E3] skipped (run e3_feasibility.sh, or `run_all.sh full`)")
        return
    print("[E3] feasibility sweep (camera-ready curve source)")
    rows = []
    for cell in doc["cells"]:
        rows.append({
            "n": cell["n"], "length": cell["length"], "compute_ms": cell["compute_ms"],
            "runtime_ms": cell["runtime_ms"],
            "ct_bytes_per_contribution": int(cell["ct_bytes_per_contribution"]),
            "cpu_seconds": cell["cpu_seconds"], "max_error": cell["max_error"],
            "exact": cell["exact"],
        })
        check(_cell_ok(cell), f"INV-1  afc N={cell['n']} L={cell['length']}: bit-exact")
    _write_csv("feasibility.csv", rows)


# --- E4: differencing demonstration ---------------------------------------
def verify_e4() -> None:
    doc = _load("e4__differencing")
    if not doc:
        print("[E4] skipped (run e4_differencing.sh)")
        return
    print("[E4] differencing demonstration (Figure 2)")
    check(doc.get("recovered_exactly") is True,
          "INV-4  K-vs-K+1 recovers a contributor EXACTLY on an unfrozen cohort")
    check(doc.get("target_vector") == doc.get("recovered_vector"),
          "INV-4  recovered vector == target vector (exact individual leak)")


# --- INV-6: committed reference values are asserted, not decorative --------
# results/expected/*.json pins the DETERMINISTIC columns a reviewer must
# reproduce bit-for-bit. Only the 128-bit ciphertext sizes are byte-stable;
# 192/256-bit sizes vary by tens of bytes across TenSEAL builds, so only the
# 128-bit column and exactness are asserted here — otherwise the reference file
# would be a decoy that drifts silently while the harness still prints PASS.
def _load_expected(name: str):
    path = os.path.join(EXP, "results", "expected", name)
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        return json.load(handle)


def verify_expected_references() -> None:
    ref_b = _load_expected("table_b_reference.json")
    e1 = {p: _load("e1__" + p) for p in ALL_APPLICATIONS}
    if ref_b and all(e1.values()):
        print("[REF] INV-6: live E1 128-bit table == committed results/expected/table_b_reference.json")
        for p in ALL_APPLICATIONS:
            cell, want = e1[p]["cells"][0], ref_b.get(p, {})
            live_ct = int(cell.get("ct_bytes_per_contribution") or 0)
            check(live_ct == int(want.get("ct_bytes_per_contribution", -1)),
                  f"INV-6  {p}: ct/contribution {live_ct} == committed {want.get('ct_bytes_per_contribution')}")
            check(cell.get("crypto") == want.get("crypto"),
                  f"INV-6  {p}: crypto {cell.get('crypto')} == committed {want.get('crypto')}")
            # A degenerate cell (max_error null / ct 0 from a run without the
            # sealed engine) must report a clean FAIL, not a float(None) crash.
            live_me, want_me = cell.get("max_error"), want.get("max_error")
            check(live_me is not None and want_me is not None and float(live_me) == float(want_me),
                  f"INV-6  {p}: max_error {live_me} == committed {want_me}")

    ref_f = _load_expected("feasibility_reference.json")
    e3 = _load("e3__afc")
    if ref_f and e3:
        print("[REF] INV-6: live E3 feasibility ct sizes == committed feasibility_reference.json")
        for cell in e3["cells"]:
            key = f"n{cell['n']}_L{cell['length']}"
            if key in ref_f:
                check(int(cell["ct_bytes_per_contribution"]) == int(ref_f[key]["ct_bytes_per_contribution"]),
                      f"INV-6  feasibility {key}: ct/contribution == committed {ref_f[key]['ct_bytes_per_contribution']}")

    ref_s = _load_expected("security_matrix_reference.json")
    e2 = {p: _load("e2__" + p) for p in ALL_APPLICATIONS}
    if ref_s and any(e2.values()):
        print("[REF] INV-6: live E2 128-bit column == committed security_matrix_reference.json "
              "(192/256-bit sizes vary by build, reported only)")
        for p in ALL_APPLICATIONS:
            if not e2.get(p) or p not in ref_s:
                continue
            live = {str(c["security"]): int(c["ct_bytes_per_contribution"]) for c in e2[p]["cells"]}
            want128 = ref_s[p].get("128", {}).get("ct_bytes_per_contribution")
            if "128" in live and want128 is not None:
                check(live["128"] == int(want128),
                      f"INV-6  {p}@128-bit: ct/contribution {live['128']} == committed {want128}")


# --- E9/E10: published-study reproductions (machine-independent exactness) --
# The two headline reproductions (Section 8.3 HEPRS, Section 8.4 GWAS) keep their
# evidence in per-study results/ dirs rather than results/raw/. Assert ONLY the
# machine-independent invariants — the bit-exactness flags and the committed
# -log10(p) concordance R² — never the hardware-dependent wall-clock or memory,
# exactly as E1-E4 do. Absent files are a clean skip, not a failure.
def _load_json(path: str):
    if not os.path.exists(path):
        return None
    with open(path) as handle:
        text = handle.read()
    if not text.strip():
        raise PartialResultError(f"{os.path.relpath(path, EXP)} is empty (0 bytes): interrupted run.")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise PartialResultError(f"{os.path.relpath(path, EXP)} is not valid JSON ({exc}).") from exc


def verify_e9_e10() -> None:
    heprs = os.path.join(EXP, "heprs_prs_reproduction_2026_07_17", "results")
    gwas_dir = os.path.join(EXP, "gwas_chi_square_pnas2020_2026_07_17", "results")
    repro = _load_json(os.path.join(heprs, "reproduction.json"))
    h2h = _load_json(os.path.join(heprs, "head_to_head_benchmark.json"))
    gwas = _load_json(os.path.join(gwas_dir, "gwas_chi_square_pnas2020.json"))
    if not any((repro, h2h, gwas)):
        print("[E9/E10] skipped (run e9_heprs_prs_reproduction.sh / e10_gwas_chi_square.sh)")
        return
    print("[E9/E10] published-study reproductions: HEPRS PRS (Table 17) + Blatt et al. GWAS (Table 18)")
    if repro:
        ex = repro.get("example", {})
        check(ex.get("encrypted_equals_plaintext_oracle_exact") is True,
              "INV-7  E9 HEPRS: encrypted score == plaintext oracle (bit-exact)")
        check(float(ex.get("pearson_r_vs_heprs_pred", 0)) >= 0.9999999,
              "INV-7  E9 HEPRS: reproduces HEPRS predictions (Pearson r >= 0.9999999)")
        check(all(bool(r.get("exact")) for r in repro.get("scaling", [])),
              "INV-7  E9 HEPRS: every scaling cell bit-exact")
        check(repro.get("pass") is True, "INV-7  E9 HEPRS: reproduction PASS")
    if h2h:
        check(bool(h2h.get("example", {}).get("exact")),
              "INV-7  E9 HEPRS head-to-head: example bit-exact")
        check(all(bool(r.get("exact")) for r in h2h.get("sweep", [])),
              "INV-7  E9 HEPRS head-to-head: every sweep cell bit-exact (flat-memory evidence, Table 17)")
    if gwas:
        check(gwas.get("invariant_bit_exact") is True,
              "INV-7  E10 GWAS chi-square: sufficient statistics bit-exact")
        checks = gwas.get("checks", {})
        for key in ("sum_g_bit_exact", "sum_gy_bit_exact", "cases_exact", "n_exact", "chi2_exact", "p_exact"):
            check(checks.get(key) is True, f"INV-7  E10 GWAS chi-square: {key}")
        check(float(gwas.get("neg_log10_p_r2_vs_cleartext", 0)) >= 0.999999,
              "INV-7  E10 GWAS chi-square: -log10(p) concordance R² == 1.0 (bit-exact)")
        cov = gwas.get("covariate_adjusted", {})
        if cov:
            check(float(cov.get("neg_log10_p_r2_vs_cleartext", 0)) >= 0.999,
                  "INV-7  E10 GWAS covariate-adjusted: -log10(p) concordance R² >= 0.999 (concordant, not bit-exact)")


def main() -> int:
    print("=" * 72)
    print("The Blind Machine — experiment verification (machine-independent invariants)")
    print("=" * 72)
    try:
        verify_e1()
        verify_e2()
        verify_e3()
        verify_e4()
        verify_e9_e10()
        verify_expected_references()
    except PartialResultError as exc:
        print("-" * 72)
        print(f"RESULT: FAIL — partial/malformed result file:\n  {exc}")
        return 1
    print("-" * 72)
    if _failures:
        print(f"RESULT: FAIL — {len(_failures)}/{_checks} invariant checks failed:")
        for message in _failures:
            print(f"  - {message}")
        return 1
    print(f"RESULT: PASS — all {_checks} machine-independent invariants hold.")
    print("Paper-facing tables written to results/*.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
