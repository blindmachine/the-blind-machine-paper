"""Offline certificate verification — recompute every hash, zero trust."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from blind.certificates import build_certificate, verify_certificate
from blind.hashing import certificate_hash

# The cross-language golden fixture: a REAL certificate emitted by the Rails
# ComputationCertificate#document_json (regenerate from the Rails side with
# REGENERATE_CERTIFICATE_GOLDEN=1, see computation_certificate_test.rb). This is
# the wrapped canonical schema-v1 document the public API item endpoint serves.
# Proving `verify_certificate` accepts it offline is the G8 deliverable.
_GOLDEN_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "certificate_v1_golden.json"
)


def _cert():
    return build_certificate(
        application_digest="allele_frequency_count@sha256:abc123",
        project_id="proj_7Ka9F2",
        public_context_sha256="sha256:7b229f",
        contribution_hashes=["sha256:2c8b7a", "sha256:5d093e", "sha256:1a2b3c"],
        result_digest="sha256:8f0c2d",
        min_contributors=3,
    )


def test_valid_certificate_verifies_fully():
    cert = _cert()
    v = verify_certificate(cert)
    assert v.ok, [(c.name, c.expected, c.actual) for c in v.checks if not c.ok]
    names = {c.name for c in v.checks}
    assert {"certificate_hash", "cohort_commitment", "min_contributors_satisfied"} <= names


def test_tampered_result_digest_is_caught():
    cert = _cert()
    cert["result_digest"] = "sha256:tampered"  # cert_hash no longer matches body
    v = verify_certificate(cert)
    assert not v.ok
    assert any(c.name == "certificate_hash" and not c.ok for c in v.checks)


def test_tampered_cohort_commitment_is_caught():
    cert = _cert()
    cert["cohort_commitment"] = "sha256:00"
    cert["certificate_hash"] = certificate_hash(cert)
    v = verify_certificate(cert)
    # cert_hash now consistent, but recomputed cohort commitment != claimed
    assert not v.ok
    assert any(c.name == "cohort_commitment" and not c.ok for c in v.checks)


def test_min_n_derived_not_trusted():
    cert = _cert()
    cert["min_contributors_satisfied"] = False  # lies: 3 >= 3 is True
    cert["certificate_hash"] = certificate_hash(cert)
    v = verify_certificate(cert)
    assert not v.ok
    assert any(c.name == "min_contributors_satisfied" and not c.ok for c in v.checks)


def test_rehash_local_public_context(tmp_path):
    from blind.hashing import sha256_file

    pub = tmp_path / "public.context"
    pub.write_text("PUBLIC-CONTEXT-BYTES")
    cert = build_certificate(
        application_digest="p@sha256:abc",
        project_id="proj_1",
        public_context_sha256=sha256_file(pub),
        contribution_hashes=["sha256:a", "sha256:b", "sha256:c"],
        result_digest="sha256:r",
        min_contributors=3,
    )
    v = verify_certificate(cert, public_context_file=pub)
    assert v.ok
    assert any(c.name == "public_context_sha256" and c.ok for c in v.checks)


def _load_golden() -> dict:
    return json.loads(_GOLDEN_FIXTURE.read_text())


def test_rails_golden_certificate_verifies_offline():
    """A Rails-emitted wrapped certificate verifies with ZERO trust and ZERO
    network — the cross-language contract the paper's G8 milestone depends on."""
    assert _GOLDEN_FIXTURE.exists(), "checked-in certificate fixture is missing"
    doc = _load_golden()
    # It is the wrapped canonical document, not a flat cert.
    assert doc["object"] == "computation_certificate"
    assert doc["schema_version"] == "1"
    assert "certificate" in doc and "certificate_hash" in doc

    v = verify_certificate(doc)
    assert v.ok, [(c.name, c.expected, c.actual) for c in v.checks if not c.ok]
    # The hash check ran against the UNWRAPPED bound-field body.
    assert any(c.name == "certificate_hash" and c.ok for c in v.checks)


def test_rails_golden_certificate_tamper_is_caught():
    """Flip one bound field in the Rails-emitted document → the body no longer
    hashes to the wrapper's claimed certificate_hash, and verification fails."""
    doc = _load_golden()
    tampered = copy.deepcopy(doc)
    tampered["certificate"]["result_digest"] = "0" * 64  # body no longer matches
    v = verify_certificate(tampered)
    assert not v.ok
    assert any(c.name == "certificate_hash" and not c.ok for c in v.checks)


def test_wrapped_and_flat_certificates_verify_identically():
    """`verify_certificate` accepts BOTH the wrapped Rails document and a flat
    certificate body carrying its own certificate_hash."""
    doc = _load_golden()
    flat = {**doc["certificate"], "certificate_hash": doc["certificate_hash"]}
    assert verify_certificate(flat).ok
    assert verify_certificate(doc).ok


def test_rehash_local_bundle(installed):
    store, bundle, application_id = installed
    cert = build_certificate(
        application_digest=application_id,
        project_id="proj_1",
        public_context_sha256="sha256:x",
        contribution_hashes=["sha256:a", "sha256:b", "sha256:c"],
        result_digest="sha256:r",
        min_contributors=3,
    )
    v = verify_certificate(cert, application_root=bundle.root)
    assert any(c.name == "application_digest" and c.ok for c in v.checks), \
        [(c.name, c.expected, c.actual) for c in v.checks]
