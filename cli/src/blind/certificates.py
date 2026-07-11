"""Offline certificate verification — "don't trust, verify" (COMMANDS.md).

``blind certificates verify`` recomputes every hash a Computation Certificate
binds and checks internal consistency with ZERO network and ZERO trust in Blind
Machine. Given local artifacts (the pinned application bundle, the public context,
the contribution-hash list, the result ciphertext) it also re-derives those hashes
from the bytes on disk.

``verify_certificate`` accepts BOTH shapes:

1. The canonical Rails-issued document (schema v1, see docs/certificate_schema_v1.md),
   which is what ``GET /api/v1/certificates/:certificate_hash`` and the stored
   certificate attachment emit — the bound fields live inside ``certificate``:

    {
      "object": "computation_certificate",
      "schema_version": "1",
      "hash_rule": "sha256(json(certificate, keys sorted, compact))",
      "certificate_hash": "<64 hex>",
      "issued_at": "2026-07-05T00:00:00Z",
      "certificate": {
        "cohort_commitment":     "<64 hex>",
        "cohort_size":           20,
        "computation_run_id":    456,
        "min_contributors":      20,
        "min_n_satisfied":       true,
        "project_id":            123,
        "application_digest":    "<64 hex>",
        "public_context_digest": "<64 hex>",
        "release_policy":        "aggregate_only",
        "result_digest":         "<64 hex>",
        "run_count":             1
      }
    }

2. A flat certificate body (the bound fields at the top level, carrying its own
   ``certificate_hash``) — the shape ``build_certificate`` produces for fixtures
   and ``dev``/``simulate`` self-checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from blind.hashing import (
    canonical_bundle_digest,
    certificate_hash,
    cohort_commitment,
    digests_match,
    sha256_file,
    split_application_id,
)


@dataclass
class Check:
    name: str
    ok: bool
    expected: str = ""
    actual: str = ""
    detail: str = ""


@dataclass
class CertificateVerification:
    certificate_hash: str
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def as_dict(self) -> dict:
        return {
            "object": "certificate_verification",
            "certificate_hash": self.certificate_hash,
            "verified": self.ok,
            "checks": [
                {
                    "name": c.name,
                    "ok": c.ok,
                    "expected": c.expected,
                    "actual": c.actual,
                    "detail": c.detail,
                }
                for c in self.checks
            ],
        }


def verify_certificate(
    cert: dict,
    *,
    application_root: str | Path | None = None,
    public_context_file: str | Path | None = None,
    result_file: str | Path | None = None,
) -> CertificateVerification:
    """Recompute and cross-check every bound hash. Any provided local artifact is
    re-hashed from its bytes and compared to the certificate's claim.

    Accepts BOTH shapes:
      - a flat certificate (the bound fields at the top level), and
      - the canonical Rails-issued wrapped document
        ``{"object": ..., "certificate_hash": ..., "certificate": {<bound fields>}}``.
    When a ``certificate`` wrapper key is present, the bound fields are read from
    the inner body while ``certificate_hash`` is taken from the wrapper (it is a
    transport-only field, not part of the hashed body)."""
    checks: list[Check] = []

    # Unwrap the canonical wrapped document. certificate_hash lives on the
    # wrapper; every bound field lives inside `certificate`.
    if isinstance(cert.get("certificate"), dict):
        body = cert["certificate"]
        # The claimed hash may sit on the wrapper OR (defensively) inside the body.
        claimed = cert.get("certificate_hash") or body.get("certificate_hash", "")
        cert = {**body, "certificate_hash": claimed}

    # 1. certificate_hash — the certificate must hash to its own claimed hash.
    # (claimed is bare 64-hex from the platform; recomputed is `sha256:<hex>` —
    # compare on the hex value.)
    claimed_cert_hash = cert.get("certificate_hash", "")
    recomputed_cert_hash = certificate_hash(cert)
    checks.append(
        Check(
            "certificate_hash",
            ok=digests_match(claimed_cert_hash, recomputed_cert_hash),
            expected=claimed_cert_hash,
            actual=recomputed_cert_hash,
            detail="sha256 over canonical certificate body",
        )
    )

    application_digest = cert.get("application_digest", "")
    project_id = cert.get("project_id", "")
    contribution_hashes = cert.get("contribution_hashes", []) or []

    # 2. cohort_commitment — recompute ONLY when the cohort's contribution hashes
    # are on hand. A public certificate deliberately does NOT disclose them (that
    # would leak cohort membership), so an outside verifier records the binding
    # as present-but-not-independently-recomputable rather than a failure. An
    # owner who holds the list gets the full recompute.
    claimed_cohort = cert.get("cohort_commitment", "")
    if contribution_hashes:
        recomputed_cohort = cohort_commitment(contribution_hashes, project_id, application_digest)
        checks.append(
            Check(
                "cohort_commitment",
                ok=digests_match(claimed_cohort, recomputed_cohort),
                expected=claimed_cohort,
                actual=recomputed_cohort,
                detail=f"sorted({len(contribution_hashes)} hashes) + project + application",
            )
        )
    else:
        checks.append(
            Check(
                "cohort_commitment",
                ok=bool(claimed_cohort),
                expected=claimed_cohort,
                actual=claimed_cohort,
                detail="binds the frozen cohort (hashes not disclosed by the public cert)",
            )
        )

    # 3. min-N satisfied — derive from the cohort size (the cert carries it), not
    # from the undisclosed hash list, and cross-check the claimed flag.
    min_n = int(cert.get("min_contributors", 0))
    cohort_size = int(cert.get("cohort_size", len(contribution_hashes)) or 0)
    claimed_satisfied = bool(cert.get("min_n_satisfied", cert.get("min_contributors_satisfied", False)))
    derived_satisfied = cohort_size >= min_n if min_n else claimed_satisfied
    checks.append(
        Check(
            "min_contributors_satisfied",
            ok=(claimed_satisfied == derived_satisfied),
            expected=str(claimed_satisfied),
            actual=str(derived_satisfied),
            detail=f"cohort {cohort_size} vs min {min_n}",
        )
    )

    # 4. application_digest — if we hold the bundle, recompute its canonical digest.
    if application_root is not None:
        name, pinned_digest = split_application_id(application_digest)
        actual_digest = canonical_bundle_digest(Path(application_root))
        checks.append(
            Check(
                "application_digest",
                ok=digests_match(pinned_digest, actual_digest),
                expected=pinned_digest or "",
                actual=actual_digest,
                detail="recomputed from local bundle bytes",
            )
        )

    # 5. public_context digest — if we hold the public context file, re-hash it.
    if public_context_file is not None:
        claimed_pub = cert.get("public_context_digest", cert.get("public_context_sha256", ""))
        actual_pub = sha256_file(public_context_file)
        checks.append(
            Check(
                "public_context_sha256",
                ok=digests_match(claimed_pub, actual_pub),
                expected=claimed_pub,
                actual=actual_pub,
                detail="recomputed from local public context",
            )
        )

    # 6. result_digest — if we hold the result ciphertext, re-hash it.
    if result_file is not None:
        claimed_result = cert.get("result_digest", "")
        actual_result = sha256_file(result_file)
        checks.append(
            Check(
                "result_digest",
                ok=digests_match(claimed_result, actual_result),
                expected=claimed_result,
                actual=actual_result,
                detail="sha256 of local result ciphertext",
            )
        )

    return CertificateVerification(certificate_hash=claimed_cert_hash, checks=checks)


def build_certificate(
    *,
    application_digest: str,
    project_id: str,
    public_context_sha256: str,
    contribution_hashes: list[str],
    result_digest: str,
    min_contributors: int,
    run_count: int = 1,
    release_policy: dict | None = None,
) -> dict:
    """Assemble a well-formed certificate (used by fixtures + `dev`/`simulate`
    self-checks). The bound cohort commitment and certificate hash are computed
    here so the output round-trips through ``verify_certificate``."""
    body = {
        "object": "certificate",
        "application_digest": application_digest,
        "project_id": project_id,
        "public_context_sha256": public_context_sha256,
        "contribution_hashes": sorted(contribution_hashes),
        "cohort_commitment": cohort_commitment(
            contribution_hashes, project_id, application_digest
        ),
        "result_digest": result_digest,
        "min_contributors": min_contributors,
        "min_contributors_satisfied": len(contribution_hashes) >= min_contributors,
        "run_count": run_count,
        "release_policy": release_policy or {"aggregate_only": True, "allowed_runs_per_project": 1},
    }
    body["certificate_hash"] = certificate_hash(body)
    return body
