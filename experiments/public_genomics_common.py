#!/usr/bin/env python3
"""Shared helpers for optional public-human-genomics experiments.

The helpers deliberately keep individual-level genotype material under each
experiment's ignored work/ directory. Callers should commit only aggregate
results and provenance.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SUPER_POP_ORDER = ("EUR", "EAS", "AMR", "AFR", "SAS")
BASE_URL = "https://ftp.1000genomes.ebi.ac.uk/vol1/ftp/release/20130502"
PANEL_URL = f"{BASE_URL}/integrated_call_samples_v3.20130502.ALL.panel"
CHR22_VCF_URL = (
    f"{BASE_URL}/"
    "ALL.chr22.phase3_shapeit2_mvncall_integrated_v5b.20130502.genotypes.vcf.gz"
)
GENOME_BUILD = "GRCh37"
ACCESS_DATE = "2026-07-09"


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


# Exit code the E5-E8 studies use for a clean SKIP (a genuinely-missing
# prerequisite), so replicate_all.sh can tell PASS (0) from SKIP (3) from FAIL.
SKIP_EXIT = 3


class DataUnavailable(RuntimeError):
    """A required external tool or data source could not be reached (bcftools/tabix
    missing, or the public genome fetch failed). This is a SKIP condition — a
    missing prerequisite — not a wrong scientific result (which stays a FAIL)."""


# The six signed paper bundles plus the E8 draft bundle. Any ONE sealed env among
# these provides the TenSEAL runtime the studies need (they import a bundle's
# server.py, which `import tenseal`). Kept in sync with lib.sh's ALL_APPLICATIONS.
_SEALED_ENV_APPS = (
    "allele_frequency_count",
    "carrier_count",
    "cohort_histogram",
    "polygenic_score_aggregate",
    "polygenic_score_inference",
    "allele_frequency_with_variance",
    "genotype_phenotype_covariance",
    "genotype_pair_ld",
)


def find_repo_root(start: Path) -> Path:
    """The directory that holds `applications/`, found by walking up from `start`.

    Works in BOTH layouts: the monorepo (`docs/paper/experiments/<study>`, so the
    repo root is several levels up) and the published paper package
    (`experiments/<study>`, where `applications/` is a sibling of `experiments/`).
    The old `parents[3]` assumption pointed ABOVE a standalone package, which is why
    an external clone could not find the bundles. `BLIND_PAPER_ROOT` overrides."""
    override = os.environ.get("BLIND_PAPER_ROOT")
    if override:
        return Path(override).resolve()
    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / "applications").is_dir():
            return candidate
    return start.parents[3]  # historic monorepo fallback


def repo_root_from_experiment(study_dir: Path) -> Path:
    return find_repo_root(study_dir)


def _skip(message: str):
    print(f"SKIP: {message}", flush=True)
    raise SystemExit(SKIP_EXIT)


def ensure_tenseal_runtime(repo_root: Path, script_path: Path) -> None:
    """Guarantee the study runs under a TenSEAL-capable interpreter.

    The real-DNA studies import each bundle's `server.py`, which `import tenseal`.
    Launched under a bare `python3` without TenSEAL, this re-execs the script under
    a sealed application env (`applications/<app>/signed/env/.venv/bin/python`,
    materialized by `setup.sh`). If none is sealed, SKIP cleanly rather than crash
    with a ModuleNotFoundError — a missing runtime is not a replication failure.
    `BLIND_STUDY_REEXEC` guards against an infinite re-exec loop."""
    try:
        import tenseal  # noqa: F401
        return
    except Exception:
        pass
    if os.environ.get("BLIND_STUDY_REEXEC") == "1":
        _skip("TenSEAL is not importable even under the sealed application env; "
              "re-run `bash experiments/setup.sh` to (re)seal it.")
    for app in _SEALED_ENV_APPS:
        py = repo_root / "applications" / app / "signed" / "env" / ".venv" / "bin" / "python"
        if py.is_file():
            env = {**os.environ, "BLIND_STUDY_REEXEC": "1"}
            os.execve(str(py), [str(py), str(script_path), *sys.argv[1:]], env)
    _skip("no sealed application environment found — run `bash experiments/setup.sh` "
          "first (it seals TenSEAL over Microsoft SEAL once), then re-run this study.")


def ensure_bcftools() -> None:
    """SKIP (not FAIL) when the E5-E8 toolchain is absent: bcftools + tabix read the
    public 1000 Genomes VCF slices, so without them the real-DNA studies cannot fetch
    data at all. A tool you could not install is not a failed replication."""
    missing = [tool for tool in ("bcftools", "tabix") if shutil.which(tool) is None]
    if missing:
        _skip(f"missing tool(s): {', '.join(missing)} — E5-E8 need bcftools+tabix to "
              "read the public 1000 Genomes slices. Install them, then re-run.")


def require_bundle(repo_root: Path, app_name: str) -> None:
    """SKIP if a bundle a study needs was not shipped — e.g. the draft
    `genotype_pair_ld` for E8 in a package that excluded it."""
    server = repo_root / "applications" / app_name / "signed" / "server.py"
    if not server.is_file():
        _skip(f"application bundle `{app_name}` is not present at {server.parent}; "
              "this study cannot run without it.")


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
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr[-2000:]}"
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
    candidate = directory / "integrated_call_samples_v3.20130502.ALL.panel"
    return candidate.read_text() if candidate.is_file() else None


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode())


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
    dosage = 0
    for allele in gt.replace("|", "/").split("/"):
        if allele == "1":
            dosage += 1
        elif allele == "0":
            continue
        else:
            return None
    return dosage


def read_panel(work_dir: Path) -> list[Sample]:
    work_dir.mkdir(parents=True, exist_ok=True)
    panel_path = work_dir / "integrated_call_samples_v3.20130502.ALL.panel"
    if panel_path.exists():
        panel_text = panel_path.read_text()
    else:
        panel_text = _mirror_panel_text()
        if panel_text is None:
            panel_text = run(["curl", "-L", "--fail", "--silent", "--show-error", PANEL_URL])
        panel_path.write_text(panel_text)

    rows: list[Sample] = []
    for line in panel_text.splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            rows.append(Sample(parts[0], parts[1], parts[2], parts[3]))
    return rows


def select_samples(
    panel: list[Sample],
    *,
    samples_per_super_pop: int,
    super_pop_order: tuple[str, ...] = SUPER_POP_ORDER,
) -> list[Sample]:
    counts = {super_pop: 0 for super_pop in super_pop_order}
    selected: list[Sample] = []
    for sample in panel:
        if sample.super_population not in counts:
            continue
        if counts[sample.super_population] >= samples_per_super_pop:
            continue
        selected.append(sample)
        counts[sample.super_population] += 1
        if all(count == samples_per_super_pop for count in counts.values()):
            return selected
    missing = [key for key, count in counts.items() if count < samples_per_super_pop]
    raise RuntimeError(f"panel did not contain enough samples for {missing}")


def fetch_vcf_text(
    work_dir: Path,
    samples: list[Sample],
    *,
    region: str,
    min_global_af: float,
    max_global_af: float,
    vcf_url: str = CHR22_VCF_URL,
) -> str:
    work_dir.mkdir(parents=True, exist_ok=True)
    sample_file = work_dir / "selected_samples.txt"
    sample_file.write_text("\n".join(sample.sample_id for sample in samples) + "\n")
    cache_key = (
        region.replace(":", "_").replace("-", "_")
        + f"__af_{min_global_af}_{max_global_af}__n{len(samples)}.vcf"
    )
    vcf_path = work_dir / cache_key
    if vcf_path.exists():
        return vcf_path.read_text()

    expr = f"AF>{min_global_af} && AF<{max_global_af}"
    cmd = [
        "bcftools",
        "view",
        "--no-version",
        "-S",
        str(sample_file),
        "-r",
        region,
        "-m2",
        "-M2",
        "-v",
        "snps",
        "-i",
        expr,
        bcftools_source(vcf_url),
    ]
    vcf_text = run(cmd, cwd=work_dir)
    vcf_path.write_text(vcf_text)
    return vcf_text


def parse_vcf(
    vcf_text: str,
    selected: list[Sample],
    *,
    variant_count: int,
    require_complete: bool = True,
) -> tuple[list[str], list[Variant]]:
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
        if require_complete and len(present) != len(sample_order):
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
        if len(variants) >= variant_count:
            break

    if sample_order is None:
        raise RuntimeError("VCF header did not include a #CHROM line")
    if len(variants) < variant_count:
        raise RuntimeError(
            f"only found {len(variants)} usable variants; need {variant_count}"
        )
    return sample_order, variants


def dosage_vectors(
    sample_order: list[str],
    variants: list[Variant],
    *,
    work_dir: Path,
    filename_prefix: str = "",
) -> dict[str, list[int]]:
    raw_dir = work_dir / "raw_vectors"
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
        (raw_dir / f"{filename_prefix}{sample_id}.json").write_text(
            json.dumps({"vector": vector}, sort_keys=True) + "\n"
        )
    return vectors


def import_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run_application(repo_root: Path, app_name: str, raw_records: dict[str, Any]) -> dict[str, Any]:
    signed_dir = repo_root / "applications" / app_name / "signed"
    data_owner = import_module(
        f"{app_name}_data_owner_{time.time_ns()}",
        signed_dir / "local_data_owner.py",
    )
    project_owner = import_module(
        f"{app_name}_project_owner_{time.time_ns()}",
        signed_dir / "local_project_owner.py",
    )
    server = import_module(
        f"{app_name}_server_{time.time_ns()}",
        signed_dir / "server.py",
    )

    first = next(iter(raw_records.values()))
    if app_name == "genotype_pair_ld":
        if isinstance(first, dict) and "pairs" in first:
            length = len(first["pairs"])
        elif isinstance(first, dict) and "genotype" in first:
            length = len(first["genotype"]) - 1
        else:
            length = len(first) - 1
    elif isinstance(first, dict) and "genotype" in first:
        length = len(first["genotype"])
    else:
        length = len(first)

    timings: dict[str, float] = {}

    def timed(label: str, func):
        start = time.perf_counter()
        value = func()
        timings[label] = (time.perf_counter() - start) * 1000.0
        return value

    secret_context, public_context = timed("keygen_ms", project_owner.keygen)
    encoded = timed(
        "encode_ms",
        lambda: {
            sample_id: data_owner.encode(record, length)
            for sample_id, record in raw_records.items()
        },
    )
    ciphertexts = timed(
        "encrypt_ms",
        lambda: [
            data_owner.encrypt(public_context, encoded[sample_id])
            for sample_id in raw_records.keys()
        ],
    )
    result_bytes = timed("compute_ms", lambda: server.compute(ciphertexts, public_context))
    plain = timed("decrypt_ms", lambda: project_owner.decrypt(secret_context, result_bytes))
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
            "ciphertext_bytes_per_sample": (
                sum(ciphertext_sizes) / len(ciphertext_sizes) if ciphertext_sizes else 0
            ),
            "ciphertext_sha256s": [sha256_bytes(blob) for blob in ciphertexts],
        },
    }


def cleartext_sums(vectors: dict[str, list[int]]) -> tuple[list[int], list[int]]:
    length = len(next(iter(vectors.values())))
    sums = [0] * length
    sumsq = [0] * length
    for vector in vectors.values():
        for index, dosage in enumerate(vector):
            sums[index] += dosage
            sumsq[index] += dosage * dosage
    return sums, sumsq


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


def mean(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return sum(present) / len(present) if present else None


def verification_metadata(slug: str, local_command: str) -> dict[str, Any]:
    return {
        "paper_evidence_url": f"https://blindmachine.org/verify/paper/{slug}",
        "paper_evidence_json_url": f"https://blindmachine.org/verify/paper/{slug}.json",
        "local_reproduction_command": local_command,
        "hosted_computation_certificate": {
            "status": "not_published",
            "certificate_url": None,
            "reason": (
                "This optional public-real-DNA experiment was run locally and has "
                "not been submitted to the hosted blindmachine.org computation "
                "service, so no /verify/:certificate_hash page exists yet."
            ),
        },
    }
