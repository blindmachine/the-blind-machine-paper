"""Bundle load / digest-verify / Ed25519 signature-verify + tar-extract safety."""

from __future__ import annotations

import io
import tarfile

import pytest

from blind.errors import UsageError, VerificationError
from blind.runtime import bundle as bundle_mod
from blind.workspace import installed_bundle


def test_load_bundle_and_digest(make_bundle):
    src, application_id = make_bundle()
    b = bundle_mod.load_bundle(src)
    assert b.name == "allele_frequency_count"
    assert application_id.endswith(b.digest)
    assert b.manifest.computation == "additive_bfv"
    assert b.manifest.min_contributors == 3


def test_load_bundle_rejects_missing_files(tmp_path):
    d = tmp_path / "broken"
    d.mkdir()
    (d / "manifest.yml").write_text("name: x\n")
    with pytest.raises(UsageError):
        bundle_mod.load_bundle(d)


def test_verify_digest_matches_and_mismatches(make_bundle):
    src, application_id = make_bundle()
    b = bundle_mod.load_bundle(src)
    assert bundle_mod.verify_digest(src, b.digest) == b.digest
    with pytest.raises(VerificationError):
        bundle_mod.verify_digest(src, "sha256:deadbeef")


def test_signature_verifies_when_signed(make_bundle, signing_keys):
    src, _ = make_bundle(sign=True)
    assert bundle_mod.verify_signature(src) is True


def test_tampered_bundle_fails_signature(make_bundle, signing_keys):
    src, _ = make_bundle(sign=True)
    # Tamper a stage AFTER signing → digest changes → signature no longer matches.
    (src / "signed" / "10_encode.py").write_text("print('tampered')\n")
    with pytest.raises(VerificationError):
        bundle_mod.verify_signature(src)


def test_signature_missing_raises(make_bundle):
    src, _ = make_bundle(sign=True)
    (src / ".blind-signature").unlink()
    with pytest.raises(VerificationError):
        bundle_mod.verify_signature(src)


def test_verify_signature_fails_closed_without_matching_key(make_bundle, monkeypatch):
    """V1.1: a bundle signed by a key that is NOT the pinned/override key is
    REFUSED. Dropping every override falls back to the PINNED production key, which
    did not sign this fixture, so verification must RAISE — never silently proceed
    ('signature unpinned')."""
    src, _ = make_bundle(sign=True)  # signed with the per-test key ($BLIND_SIGNING_KEY)
    monkeypatch.delenv("BLIND_SIGNING_KEY", raising=False)
    monkeypatch.setattr(bundle_mod, "_BUILTIN_SIGNING_KEY_HEX", "", raising=False)
    with pytest.raises(VerificationError):
        bundle_mod.verify_signature(src)


def test_verify_signature_rejects_weak_all_zero_key(make_bundle):
    """V1.3: the all-zero Ed25519 key is a valid low-order (forgeable) point;
    verifying against it must be refused, not accepted."""
    src, _ = make_bundle(sign=True)
    with pytest.raises(VerificationError):
        bundle_mod.verify_signature(src, signing_key_hex="0" * 64)


def test_active_signing_key_defaults_to_pinned(monkeypatch):
    """With no override, verification resolves to the PINNED shipped key — never
    an empty 'no key' that would let signature checks silently no-op (V1.1)."""
    monkeypatch.delenv("BLIND_SIGNING_KEY", raising=False)
    monkeypatch.setattr(bundle_mod, "_BUILTIN_SIGNING_KEY_HEX", "", raising=False)
    assert bundle_mod.active_signing_key_hex() == bundle_mod._PINNED_SIGNING_KEY_HEX
    assert len(bundle_mod._PINNED_SIGNING_KEY_HEX) == 64


def test_custom_signing_key_requires_separate_unsafe_opt_in(make_bundle, monkeypatch):
    src, _ = make_bundle(sign=True)
    monkeypatch.delenv("BLIND_UNSAFE_ALLOW_CUSTOM_SIGNING_KEY", raising=False)
    with pytest.raises(VerificationError):
        bundle_mod.verify_signature(src)


def test_extract_bundle_rejects_path_traversal(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("../escape.txt")
        data = b"nope"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(VerificationError):
        bundle_mod.extract_bundle(buf.getvalue(), tmp_path / "dest")


def test_extract_bundle_rejects_windows_backslash_traversal(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(r"..\escape.txt")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"nope"))
    with pytest.raises(VerificationError):
        bundle_mod.extract_bundle(buf.getvalue(), tmp_path / "dest")


def test_downloaded_bundle_rejects_preseeded_unsigned_venv(make_bundle):
    src, _ = make_bundle()
    poisoned = src / "signed" / "env" / ".venv" / "lib" / "python" / "site-packages"
    poisoned.mkdir(parents=True)
    (poisoned / "shadow.py").write_text("raise RuntimeError('poisoned')\n")
    with pytest.raises(VerificationError):
        bundle_mod.verify_download_structure(src)


def test_installed_bundle_rejects_unsigned_shadow_bytecode(installed):
    store, bundle, application_id = installed
    shadow = bundle.root / "__pycache__"
    shadow.mkdir()
    (shadow / "server.cpython-311.pyc").write_bytes(b"unsigned")
    with pytest.raises(VerificationError):
        installed_bundle(store, application_id)


def test_installed_bundle_rejects_tampered_signed_source(installed):
    store, bundle, application_id = installed
    (bundle.root / "10_encode.py").write_text("raise RuntimeError('tampered')\n")
    with pytest.raises(VerificationError):
        installed_bundle(store, application_id)


def test_extract_bundle_roundtrip(make_bundle, tmp_path):
    src, _ = make_bundle()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(src, arcname="bundle")
    dest = tmp_path / "unpacked"
    bundle_mod.extract_bundle(buf.getvalue(), dest)
    # single top-level dir is flattened
    assert (dest / "signed" / "manifest.yml").exists()
    assert (dest / "signed" / "30_compute_encrypted.py").exists()
    assert (dest / "README.md").exists()
    assert (dest / "SECURITY.md").exists()
    assert (dest / "tests" / "vectors" / "v1.json").exists()


def test_extract_bundle_preserves_signed_top_level(make_bundle, tmp_path):
    src, _ = make_bundle()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(src / "signed", arcname="signed")

    dest = tmp_path / "unpacked"
    bundle_mod.extract_bundle(buf.getvalue(), dest)

    assert (dest / "signed" / "manifest.yml").exists()
    assert not (dest / "manifest.yml").exists()
