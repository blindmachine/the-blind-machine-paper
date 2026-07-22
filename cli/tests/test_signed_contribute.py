"""Signed-invitation contribute path (RFC 0003), end to end through the CLI.

These are the integration twins of the red-team findings: a genuine signed link
verifies and uploads, and every substitution / downgrade / replay attempt a
malicious server could mount is REFUSED before any ciphertext is produced. The
trust anchor is the owner key in the link's #k= fragment — never a server field."""

from __future__ import annotations

import json

import httpx
from typer.testing import CliRunner

import blind.context as ctxmod
from blind import invitations as inv
from blind.cli.app import app
from blind.hashing import normalize_digest, sha256_hex
from blind.workspace import run_keygen
from tests.conftest import mock_transport

runner = CliRunner()


def _out(result):
    text = result.stdout
    start = text.index("{")
    depth = 0
    for i in range(start, len(text)):
        depth += 1 if text[i] == "{" else (-1 if text[i] == "}" else 0)
        if depth == 0:
            return json.loads(text[start:i + 1])
    raise AssertionError("no JSON object:\n" + text)


def _setup(installed, *, sign=True, priv=None, pub=None, tamper=None, drop_sig=False,
           expires="7d", token="tok_signed", project="proj_c"):
    """Wire a mock server that serves a (optionally signed) invitation packet + the
    matching public context, and return (link, ctx_bytes_digest). `tamper` mutates
    the signed_intent AFTER signing (server tampering); `drop_sig` omits the
    signature (downgrade)."""
    store, bundle, application_id = installed
    kg = run_keygen(store, "owner_proj", bundle)
    ctx_bytes = kg.public_context_path.read_bytes()
    pub_digest = normalize_digest(kg.public_context_sha256)

    if priv is None or pub is None:
        priv, pub = inv.generate_owner_keypair()

    packet = {
        "object": "contribution_packet", "project_id": project,
        "application": application_id, "public_context_digest": "sha256:" + pub_digest,
        "context_epoch": 1, "min_contributors": 20, "cohort_size": 0,
    }
    app_digest = normalize_digest(application_id.split("@", 1)[1])
    link = f"https://blindmachine.org/c/{token}"
    if sign:
        intent = inv.build_intent(
            project_id=project, token=token, application_digest=app_digest,
            public_context_digest=pub_digest, context_epoch=1, min_contributors=20,
            expires_at=inv.expiry_iso(expires))
        signature = inv.owner_sign(priv, intent)
        if tamper:
            intent = tamper(dict(intent))
        packet["signed_intent"] = intent
        packet["invitation_signature"] = None if drop_sig else signature
        link = inv.build_invite_link(link, pub)

    def pubctx_route(_request):
        return httpx.Response(200, content=ctx_bytes,
                              headers={"X-Public-Context-Digest": pub_digest})

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/invitations/{token}"): packet,
        ("GET", f"/api/v1/projects/{project}/public_context"): pubctx_route,
        ("POST", f"/api/v1/projects/{project}/contributions"): {
            "id": "contrib_1", "cohort_size": 1, "min_n_satisfied": False},
    }))
    return link


def _contribute(link, tmp_path, *args):
    raw = tmp_path / "v.json"
    raw.write_text(json.dumps({"vector": [1, 0, 2, 1]}))
    return runner.invoke(app, ["--json", "contribute", *args, link, str(raw)])


# -- happy path -------------------------------------------------------------------

def test_signed_link_verifies_and_uploads(installed, tmp_path):
    link = _setup(installed)
    r = _contribute(link, tmp_path)
    assert r.exit_code == 0, r.stdout
    d = _out(r)
    assert d["uploaded"] is True
    assert d["public_context_signed"] is True
    assert d["public_context_pinned"] is True


# -- the red-team refusals --------------------------------------------------------

def test_downgrade_by_dropping_the_signature_is_refused(installed, tmp_path):
    # #k= present in the link, but the server omits the signature → hard refuse.
    link = _setup(installed, drop_sig=True)
    r = _contribute(link, tmp_path)
    assert r.exit_code != 0


def test_substituted_context_digest_in_the_intent_is_refused(installed, tmp_path):
    # Server tampers the signed public_context_digest → signature no longer verifies.
    link = _setup(installed, tamper=lambda i: {**i, "public_context_digest": "ef" * 32})
    r = _contribute(link, tmp_path)
    assert r.exit_code != 0


def test_signature_under_a_wrong_key_is_refused(installed, tmp_path):
    # The link fragment carries the real owner key, but the server signed under its
    # OWN key (simulated by signing with an attacker key while the fragment is honest).
    honest_priv, honest_pub = inv.generate_owner_keypair()
    attacker_priv, _ = inv.generate_owner_keypair()
    # Sign with the attacker key, but publish the honest pub in the fragment.
    link = _setup(installed, priv=attacker_priv, pub=honest_pub)
    r = _contribute(link, tmp_path)
    assert r.exit_code != 0


def test_substituted_context_bytes_are_refused(installed, tmp_path):
    # Genuine signed intent, but the server serves DIFFERENT context bytes than the
    # signed digest — the _fetch digest check fails.
    store, bundle, application_id = installed
    kg = run_keygen(store, "owner_proj", bundle)
    signed_digest = normalize_digest(kg.public_context_sha256)
    app_digest = normalize_digest(application_id.split("@", 1)[1])
    priv, pub = inv.generate_owner_keypair()
    token, project = "tok_swap", "proj_c"
    intent = inv.build_intent(
        project_id=project, token=token, application_digest=app_digest,
        public_context_digest=signed_digest, context_epoch=1, min_contributors=20,
        expires_at=inv.expiry_iso("7d"))
    signature = inv.owner_sign(priv, intent)

    def evil_ctx(_request):
        # different bytes → different digest than the one that was signed
        return httpx.Response(200, content=b"SERVER-SUBSTITUTED-CONTEXT",
                              headers={"X-Public-Context-Digest": "ff" * 32})

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/invitations/{token}"): {
            "object": "contribution_packet", "project_id": project,
            "application": application_id, "context_epoch": 1, "min_contributors": 20,
            "signed_intent": intent, "invitation_signature": signature},
        ("GET", f"/api/v1/projects/{project}/public_context"): evil_ctx,
        ("POST", f"/api/v1/projects/{project}/contributions"): {"id": "x"},
    }))
    link = inv.build_invite_link(f"https://blindmachine.org/c/{token}", pub)
    r = _contribute(link, tmp_path)
    assert r.exit_code != 0


def test_substituted_application_is_refused(installed, tmp_path):
    # Genuine owner signature, but over a DIFFERENT application_digest than the bundle
    # the server serves the contributor → the app cross-check refuses.
    store, bundle, application_id = installed
    kg = run_keygen(store, "owner_proj", bundle)
    digest = normalize_digest(kg.public_context_sha256)
    priv, pub = inv.generate_owner_keypair()
    token, project = "tok_app", "proj_c"
    intent = inv.build_intent(
        project_id=project, token=token, application_digest=sha256_hex(b"not-the-bundle"),
        public_context_digest=digest, context_epoch=1, min_contributors=20,
        expires_at=inv.expiry_iso("7d"))
    signature = inv.owner_sign(priv, intent)
    ctx_bytes = kg.public_context_path.read_bytes()

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/invitations/{token}"): {
            "object": "contribution_packet", "project_id": project,
            "application": application_id, "context_epoch": 1, "min_contributors": 20,
            "signed_intent": intent, "invitation_signature": signature},
        ("GET", f"/api/v1/projects/{project}/public_context"):
            lambda _r: httpx.Response(200, content=ctx_bytes,
                                      headers={"X-Public-Context-Digest": digest}),
        ("POST", f"/api/v1/projects/{project}/contributions"): {"id": "x"},
    }))
    link = inv.build_invite_link(f"https://blindmachine.org/c/{token}", pub)
    r = _contribute(link, tmp_path)
    assert r.exit_code != 0


def test_expired_signed_invitation_is_refused(installed, tmp_path):
    # A signed intent whose expiry is already in the past → refuse against the local
    # clock, regardless of whether the server would 404.
    def past(i):
        return {**i, "expires_at": "2000-01-01T00:00:00Z"}
    # tamper AFTER signing would break the signature; instead sign a genuinely-past
    # intent, so verification passes but the local expiry check fails.
    store, bundle, application_id = installed
    kg = run_keygen(store, "owner_proj", bundle)
    digest = normalize_digest(kg.public_context_sha256)
    app_digest = normalize_digest(application_id.split("@", 1)[1])
    priv, pub = inv.generate_owner_keypair()
    token, project = "tok_exp", "proj_c"
    intent = inv.build_intent(
        project_id=project, token=token, application_digest=app_digest,
        public_context_digest=digest, context_epoch=1, min_contributors=20,
        expires_at="2000-01-01T00:00:00Z")
    signature = inv.owner_sign(priv, intent)
    ctx_bytes = kg.public_context_path.read_bytes()

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/invitations/{token}"): {
            "object": "contribution_packet", "project_id": project,
            "application": application_id, "context_epoch": 1, "min_contributors": 20,
            "signed_intent": intent, "invitation_signature": signature},
        ("GET", f"/api/v1/projects/{project}/public_context"):
            lambda _r: httpx.Response(200, content=ctx_bytes,
                                      headers={"X-Public-Context-Digest": digest}),
        ("POST", f"/api/v1/projects/{project}/contributions"): {"id": "x"},
    }))
    link = inv.build_invite_link(f"https://blindmachine.org/c/{token}", pub)
    r = _contribute(link, tmp_path)
    assert r.exit_code != 0
