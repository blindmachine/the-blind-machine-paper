"""Per-application I/O adapters for the encrypted-on-synthetic engine.

``measure_encrypted_engine`` (blind/simulate.py) drives the real numbered stages
through their argparse CLIs. This module carries the small amount of per-application
knowledge that used to live ONLY in the paper's bypass driver
(docs/paper/artifacts/measure_real_bench.py: its ``KIND`` map, ``gen_*`` raw
shapers, and ``oracle_check``) as a compact, manifest-selected descriptor:

  * ``raw_for(vec)``      — how to shape one contributor's raw input file;
  * ``encrypt_outputs``   — 1 (default) or 2 separate ciphertext files per
                            contributor. Every shipped application — covariance
                            included — emits ONE blob (covariance co-packs its
                            ``(g, y)`` pair into a single BMCT1 container at
                            stage 20), so this stays 1; the ``2`` path exists only
                            for a hypothetical two-file encrypt stage;
  * ``compute_sorted``    — True for the digest-sorted fold (the server's real
                            Stager order); False only for an order-significant
                            fold. One-blob-per-contributor folds are order-
                            independent, so shipped applications keep the default;
  * ``result_keys``       — the decode keys to pull the comparable vector from;
  * ``oracle``            — the trusted CLI's cleartext reconstruction from the
                            signed declarative manifest. Bundle Python is never
                            imported into the host interpreter; disagreement with
                            the sandboxed encrypted pipeline fails equivalence.

Selection is manifest-driven (general signals, never a hard-coded application name):

  * ``input.phenotype`` / ``submitted_as == separate_ciphertexts`` → covariance
    (one packed BMCT1 (g, y) blob per contributor, ct×ct product moment);
  * ``input.buckets``   → cohort histogram (raw is a single bucket index → one-hot);
  * ``input.weights``   → polygenic score (public plaintext-scalar weighting);
  * ``input.value_domain == [0, 1]`` → carrier count (dosage thresholded to {0,1});
  * ``computation`` starting ``multiplicative`` → allele_frequency_with_variance
    (first-moment ``sum_g`` is the additive aggregate checked for exactness);
  * everything else → the DEFAULT additive single-output shape (allele frequency).

Application-controlled Python is executed only by the container sandbox. These
oracles intentionally duplicate small, manifest-declared transformations in
trusted CLI code; a drift becomes an equivalence failure rather than host code
execution.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field, replace
from typing import Any, Callable

# Decode keys the DEFAULT (additive, single-output) application exposes its
# comparable aggregate vector under, in priority order.
_DEFAULT_RESULT_KEYS = (
    "allele_counts", "counts", "vector", "result",
)


@dataclass
class ApplicationIO:
    """A compact descriptor of one application's stage I/O shape.

    ``application_io_for`` binds ``bundle`` so the oracle can read only its signed,
    declarative manifest."""

    name: str
    raw_for: Callable[[list[int]], Any]
    encrypt_outputs: int = 1
    compute_sorted: bool = True
    result_keys: tuple[str, ...] = _DEFAULT_RESULT_KEYS
    oracle: Callable[["ApplicationIO", list[list[int]], str], list] | None = None
    encode_argv: tuple[str, ...] = field(default_factory=tuple)
    bundle: Any = None

    def extract_result(self, data: Any) -> list:
        """Pull the comparable aggregate vector out of a decoded artifact."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in self.result_keys:
                if key in data:
                    return data[key]
            return data.get("vector", data.get("result", []))
        return data

    def compute_oracle(self, cohort: list[list[int]], computation: str) -> list:
        """The cleartext oracle result to assert exactness against."""
        if self.oracle is not None:
            return self.oracle(self, cohort, computation)
        from blind.simulate import run_cleartext_oracle
        return run_cleartext_oracle(cohort, computation)


# --- trusted manifest-driven cleartext oracles ---------------------------------


def _encoded_vector(io: "ApplicationIO", vec: list[int], length: int) -> list[int]:
    if len(vec) > length:
        raise ValueError("synthetic vector exceeds the manifest coordinate length")
    domain = (getattr(io.bundle.manifest, "raw", {}) or {}).get("input", {}).get(
        "value_domain", [0, 1, 2]
    )
    encoded: list[int] = []
    for value in vec:
        # `value_domain` describes the ENCODED value space, so apply the manifest's
        # encoding (carrier-indicator thresholds a {0,1,2} genotype dosage to {0,1})
        # BEFORE the domain check — otherwise a legitimate raw dosage of 2 is wrongly
        # rejected against a carrier app's [0,1] domain. The check still fails closed
        # on any encoded value the manifest doesn't permit.
        encoded_value = 1 if io.name == "carrier-indicator" and value >= 1 else int(value)
        if encoded_value not in domain:
            raise ValueError(f"encoded value {encoded_value!r} is outside the manifest domain")
        encoded.append(encoded_value)
    return encoded + [0] * (length - len(encoded))


def _encode_and_sum(io: "ApplicationIO", cohort: list[list[int]], _computation: str) -> list:
    """Coordinate-wise additive fold of the manifest-declared encoding.

    Correct for every additive single-output application regardless of what
    ``encode`` does per coordinate: allele_frequency_count (dosage passthrough),
    carrier_count (dosage → {0,1} indicator), and the first-moment ``sum_g`` of
    allele_frequency_with_variance all reduce to Σ_i encode(vec_i)."""
    length = len(cohort[0]) if cohort else 0
    counts = [0] * length
    for vec in cohort:
        for j, v in enumerate(_encoded_vector(io, list(vec), length)):
            counts[j] += v
    return counts


def _histogram_oracle(io: "ApplicationIO", cohort: list[list[int]], _computation: str) -> list:
    """One-hot additive histogram over each contributor's bucket index."""
    length = len(cohort[0]) if cohort else 0
    counts = [0] * length
    for vec in cohort:
        counts[_histogram_bucket(vec, length)] += 1
    return counts


def _pgs_oracle(io: "ApplicationIO", cohort: list[list[int]], _computation: str) -> list:
    """Public-weighted aggregate reconstructed from signed manifest parameters."""
    length = len(cohort[0]) if cohort else 0
    counts = [0] * length
    for vec in cohort:
        for j, v in enumerate(_encoded_vector(io, list(vec), length)):
            counts[j] += v
    raw = getattr(io.bundle.manifest, "raw", {}) or {}
    weights_config = raw.get("weights") or raw.get("input", {}).get("weights") or {}
    values = weights_config.get("values") or {}
    seed = values.get("seed")
    bounds = values.get("range")
    if not isinstance(seed, str) or not isinstance(bounds, list) or len(bounds) != 2:
        raise ValueError("weighted application manifest lacks a deterministic seed/range")
    lower, upper = (int(bounds[0]), int(bounds[1]))
    # These are deterministic public benchmark weights, not security randomness.
    rng = random.Random(seed)  # nosec B311
    weights = [rng.randint(lower, upper) for _ in range(length)]
    return [weights[j] * counts[j] for j in range(length)]


# --- covariance (one packed (g, y) blob per contributor, ct×ct product moment) -


def _covariance_phenotype(vec: list[int]) -> int:
    return sum(vec) % 2


def _covariance_raw(vec: list[int]) -> dict:
    return {"genotype": list(vec), "phenotype": _covariance_phenotype(vec)}


def _covariance_oracle(_io: "ApplicationIO", cohort: list[list[int]], _computation: str) -> list:
    length = len(cohort[0]) if cohort else 0
    sum_gy = [0] * length
    for vec in cohort:
        y = _covariance_phenotype(vec)
        for j, g in enumerate(vec):
            sum_gy[j] += g * y
    return sum_gy


# --- histogram raw shaping (dosage vector → a single deterministic bucket) -----


def _histogram_bucket(vec: list[int], length: int) -> int:
    """Deterministic bucket index in [0, length) for a synthetic contributor.

    blind bench draws length-``L`` dosage vectors; the histogram application expects
    ONE bucket index per contributor. Fold the vector to a stable bucket so the
    raw shape matches the stage's contract and the oracle is reproducible."""
    return sum(vec) % length if length else 0


# --- descriptor templates (bundle bound in application_io_for) -------------------

DEFAULT_IO = ApplicationIO(
    name="additive-single", raw_for=lambda vec: list(vec),
    result_keys=("allele_counts", "counts", "vector", "result"),
    oracle=_encode_and_sum,
)

CARRIER_IO = ApplicationIO(
    name="carrier-indicator", raw_for=lambda vec: list(vec),
    result_keys=("carrier_counts", "counts", "vector", "result"),
    oracle=_encode_and_sum,
)

HISTOGRAM_IO = ApplicationIO(
    name="histogram-onehot",
    raw_for=lambda vec: _histogram_bucket(list(vec), len(vec)),
    result_keys=("counts", "histogram", "vector", "result"),
    oracle=_histogram_oracle,
)

PGS_IO = ApplicationIO(
    name="pgs-weighted", raw_for=lambda vec: list(vec),
    result_keys=("weighted_counts", "counts", "vector", "result"),
    oracle=_pgs_oracle,
)

VARIANCE_IO = ApplicationIO(
    name="variance-first-moment", raw_for=lambda vec: list(vec),
    result_keys=("sum_g", "vector", "result"),
    oracle=_encode_and_sum,
)

COVARIANCE_IO = ApplicationIO(
    name="covariance-multi",
    raw_for=_covariance_raw,
    # ONE packed BMCT1 (g, y) blob per contributor (stage 20 emits `--out`, not
    # `--out-g`/`--out-y`): the canonical one-blob-per-contributor contribution
    # shape. Co-packing the pair makes staging-level (g,y) mismatch structurally
    # impossible, so the compute fold is order-independent across contributors —
    # digest-sorting (the server's real Stager order) is therefore correct here,
    # so this application keeps the default `compute_sorted=True`.
    encrypt_outputs=1,
    result_keys=("sum_gy", "covariance", "vector", "result"),
    oracle=_covariance_oracle,
)


def _template_for(bundle) -> ApplicationIO:
    raw = getattr(bundle.manifest, "raw", {}) or {}
    inp = raw.get("input", {})
    inp = inp if isinstance(inp, dict) else {}
    if "phenotype" in inp or inp.get("submitted_as") == "separate_ciphertexts":
        return COVARIANCE_IO
    if "buckets" in inp:
        return HISTOGRAM_IO
    if "weights" in inp or "weights" in raw:
        return PGS_IO
    if inp.get("value_domain") == [0, 1]:
        return CARRIER_IO
    if str(getattr(bundle.manifest, "computation", "") or "").lower().startswith("multiplicative"):
        return VARIANCE_IO
    return DEFAULT_IO


def application_io_for(bundle) -> ApplicationIO:
    """Select the I/O descriptor for a bundle from its manifest (general signals
    first, never a hard-coded application name) and bind its declarative manifest."""
    return replace(_template_for(bundle), bundle=bundle)
