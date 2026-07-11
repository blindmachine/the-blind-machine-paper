"""Porcelain layer — the guided study loop (contribute / projects start|status|run|proof).

These sit over the resource ("plumbing") commands and reuse their hardened byte
paths; here we assert the ORCHESTRATION: the invite link resolves to a project,
status computes the single next action, `start` conducts setup, `run` gates on
readiness and freezes explicitly, and `proof` surfaces the verify command.
Remote calls use the zero-network mock transport (see tests/conftest.py)."""

from __future__ import annotations

import json

import httpx
from typer.testing import CliRunner

import blind.context as ctxmod
from blind.cli.app import app
from tests.conftest import mock_transport

runner = CliRunner()


def _json_out(result):
    text = result.stdout
    start = text.index("{")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise AssertionError("no JSON object in output:\n" + text)


# -- blind contribute <link> <file> ----------------------------------------


def test_contribute_resolves_packet_from_link_and_uploads_ciphertext(installed, tmp_path):
    """The data owner's ONE command: the invite link alone yields the project +
    application + pinned public context; the raw file is encoded/encrypted locally
    and only ciphertext uploads."""
    from blind.hashing import normalize_digest
    from blind.workspace import run_keygen

    store, bundle, application_id = installed
    # A valid public context the (owner's) server would serve to the contributor.
    kg = run_keygen(store, "owner_proj", bundle)
    ctx_bytes = kg.public_context_path.read_bytes()
    pub_digest = kg.public_context_sha256  # sha256:<hex>
    token, project = "tok_abc", "proj_c"

    def pubctx_route(_request):
        return httpx.Response(200, content=ctx_bytes,
                              headers={"X-Public-Context-Digest": normalize_digest(pub_digest)})

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/invitations/{token}"): {
            "object": "contribution_packet", "project_id": project,
            "application": application_id, "public_context_digest": pub_digest,
            "min_contributors": 20, "cohort_size": 0},
        ("GET", f"/api/v1/projects/{project}/public_context"): pubctx_route,
        ("POST", f"/api/v1/projects/{project}/contributions"): {
            "id": "contrib_1", "cohort_size": 1, "min_n_satisfied": False},
    }))

    raw = tmp_path / "my_vector.json"
    raw.write_text(json.dumps({"vector": [1, 0, 2, 1]}))
    r = runner.invoke(app, ["--json", "contribute",
                            f"https://blindmachine.org/c/{token}", str(raw)])
    assert r.exit_code == 0, r.stdout
    d = _json_out(r)
    assert d["object"] == "contribution"
    assert d["uploaded"] is True
    assert d["ciphertext_sha256"]
    # Auto-pinned from the packet, so no unpinned-context warning path was taken.
    assert d["public_context_pinned"] is True


def test_contribute_rejects_unresolvable_link():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/invitations/dead"): {"object": "contribution_packet"},  # no project
    }))
    r = runner.invoke(app, ["--json", "contribute",
                            "https://blindmachine.org/c/dead", "/nonexistent.csv"])
    assert r.exit_code != 0


# -- blind projects status <id> --------------------------------------------


def test_status_collecting_shows_how_many_more_contributors():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/projects/proj_s"): {
            "id": "proj_s", "state": "active", "cohort_size": 17,
            "min_contributors": 20, "min_n_satisfied": False, "run_count": 0,
            "application_digest": "sha256:aa"},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "projects", "status", "proj_s"])
    assert r.exit_code == 0, r.stdout
    d = _json_out(r)
    assert d["object"] == "project_status"
    assert "Collecting" in d["next_action"]
    assert "3 more" in d["next_command"]


def test_status_ready_points_at_run():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/projects/proj_r"): {
            "id": "proj_r", "state": "active", "cohort_size": 21,
            "min_contributors": 20, "min_n_satisfied": True, "run_count": 0},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "projects", "status", "proj_r"])
    d = _json_out(r)
    assert d["next_command"] == "blind projects run proj_r"


# -- blind projects start <application> ------------------------------------


def test_start_conducts_full_setup(installed):
    store, bundle, application_id = installed
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/projects"): {"id": "proj_new", "state": "active",
                                       "min_contributors": 20},
        ("PUT", "/api/v1/projects/proj_new/public_context"): {"ok": True},
        ("POST", "/api/v1/projects/proj_new/invitations"): {
            "url": "https://blindmachine.org/c/tok9", "expires_at": "2026-07-15T00:00:00Z"},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "projects", "start",
                            application_id, "--name", "Rare disease cohort", "--min", "20"])
    assert r.exit_code == 0, r.stdout
    d = _json_out(r)
    assert d["object"] == "project_started"
    assert d["id"] == "proj_new"
    assert "blind contribute https://blindmachine.org/c/tok9" in d["contribute_command"]
    assert d["public_context_sha256"].startswith("sha256:")


# -- blind projects run <id> -----------------------------------------------


def test_run_refuses_cleanly_when_below_min_n():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/projects/proj_b"): {
            "id": "proj_b", "state": "active", "cohort_size": 5,
            "min_contributors": 20, "min_n_satisfied": False},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "projects", "run", "proj_b"])
    assert r.exit_code == 0, r.stdout
    d = _json_out(r)
    assert d["object"] == "project_run_blocked"
    assert d["reason"] == "min_contributors_not_met"


def test_run_conducts_freeze_dispatch_decrypt(installed):
    from blind.workspace import run_keygen

    store, bundle, application_id = installed
    project = "proj_run"
    run_keygen(store, project, bundle)  # the owner's LOCAL secret key
    result_stub = json.dumps({"vector": [3, 3, 3, 2], "sentinel": 3}).encode()

    def result_route(_request):
        return httpx.Response(200, content=result_stub,
                              headers={"X-Result-Digest": "sha256:rd"})

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/projects/{project}"): {
            "id": project, "state": "active", "cohort_size": 3,
            "min_contributors": 3, "min_n_satisfied": True},
        ("POST", f"/api/v1/projects/{project}/jobs/estimate"): {"estimated_cost_usd": "0.02"},
        ("POST", f"/api/v1/projects/{project}/freeze"): {
            "cohort_commitment": "sha256:cc", "cohort_size": 3},
        ("POST", f"/api/v1/projects/{project}/jobs"): {
            "id": "job_1", "state": "completed", "certificate_hash": "certhash123"},
        ("GET", "/api/v1/jobs/job_1/result"): result_route,
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "-y", "projects", "run", project])
    assert r.exit_code == 0, r.stdout
    d = _json_out(r)
    assert d["object"] == "project_run"
    assert d["sentinel_n"] == 3
    assert d["certificate_hash"] == "certhash123"
    assert d["verify_command"] == "blind verify certhash123"


# -- blind projects proof <id> ---------------------------------------------


def test_proof_surfaces_the_reviewer_verify_command():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/projects/proj_p/certificates"): {
            "certificates": [{"certificate_hash": "abc123",
                              "public_url": "https://blindmachine.org/verify/abc123"}]},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "projects", "proof", "proj_p"])
    assert r.exit_code == 0, r.stdout
    d = _json_out(r)
    assert d["object"] == "project_proof"
    assert d["certificate_hash"] == "abc123"
    assert d["verify_command"] == "blind verify abc123"
