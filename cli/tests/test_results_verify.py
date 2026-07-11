"""`blind results verify` — the server reexecute path (POST returns a QUEUED
re-execution run that the CLI must poll to a verdict — the real Rails contract)
and the honest --local re-execution path (real local re-run of the pinned
compute stage over user-supplied ciphertexts).

Digest encodings are the REAL ones: the platform stores/serves bare 64-hex
result digests (its certificate DIGEST_PATTERN forbids the `sha256:` prefix),
while the CLI's canonical form is `sha256:<hex>`. Comparisons normalize.
"""

from __future__ import annotations

import json

import httpx
from typer.testing import CliRunner

import blind.context as ctxmod
from blind.cli.app import app
from blind.errors import PreconditionError, UsageError, VerificationError
from blind.runtime.compute import run_compute_stage
from tests.conftest import json_out, mock_transport

runner = CliRunner()

# A bare 64-hex result digest, exactly as the Rails API serves it.
BARE_DIGEST = "ab" * 32
OTHER_DIGEST = "cd" * 32


def _write_cohort(tmp_path, vectors):
    inputs = tmp_path / "cohort"
    inputs.mkdir()
    for i, vec in enumerate(vectors):
        (inputs / f"ct{i}.ct").write_text(json.dumps({"vector": vec, "sentinel": 1}))
    context = tmp_path / "public.context"
    context.write_text(json.dumps({"scheme": "stub-additive", "public": True}))
    return inputs, context


def _sequence(*responses):
    """A callable mock route that serves `responses` in order (last repeats)."""
    state = {"i": 0}

    def handler(request):
        body = responses[min(state["i"], len(responses) - 1)]
        state["i"] += 1
        status, payload = body if isinstance(body, tuple) else (200, body)
        return httpx.Response(status, json=payload)

    return handler


def _queued_reexecution(**overrides):
    """The 201 body the real reexecute endpoint returns: a freshly QUEUED run
    with result_digest/matches still null (jobs_controller#reexecute)."""
    body = {"id": "job_2", "project_id": "proj_1", "state": "queued",
            "result_digest": None, "failure_reason": None,
            "reexecutes_run_id": "job_1", "matches": None}
    body.update(overrides)
    return body


# -- server path -------------------------------------------------------------

def test_verify_server_polls_queued_reexecution_to_identical_verdict():
    """Regression (critical): the 201 from POST .../reexecute is a QUEUED run,
    NOT a verdict. The CLI must poll the re-execution to completion and only
    then compare digests — never report success off nulls."""
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/jobs/job_1/reexecute"): (201, _queued_reexecution()),
        ("GET", "/api/v1/jobs/job_2"): _sequence(
            _queued_reexecution(state="running"),
            _queued_reexecution(state="completed", result_digest=BARE_DIGEST,
                                matches=True),
        ),
        ("GET", "/api/v1/jobs/job_1"): {"id": "job_1", "state": "completed",
                                        "result_digest": BARE_DIGEST},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_1",
                            "--interval", "0"])
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert data["object"] == "result_verification"
    assert data["mode"] == "server"
    assert data["reexecution_id"] == "job_2"
    assert data["server_result_digest"] == BARE_DIGEST
    assert data["recomputed_result_digest"] == BARE_DIGEST
    assert data["identical"] is True
    assert "failure_reason" not in data


def test_verify_server_never_claims_success_while_reexecution_pending():
    """Regression (critical): a re-execution that stays queued must NOT verify
    — the old code compared null == null and printed 'identical'."""
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/jobs/job_1/reexecute"): (201, _queued_reexecution()),
        ("GET", "/api/v1/jobs/job_2"): _queued_reexecution(),
        ("GET", "/api/v1/jobs/job_1"): {"id": "job_1", "state": "completed",
                                        "result_digest": BARE_DIGEST},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_1",
                            "--interval", "0", "--timeout", "0"])
    assert r.exit_code != 0
    assert isinstance(r.exception, PreconditionError)
    assert "Verified" not in r.stdout


def test_verify_server_detects_digest_mismatch():
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/jobs/job_1/reexecute"): (201, _queued_reexecution()),
        ("GET", "/api/v1/jobs/job_2"): _queued_reexecution(
            state="completed", result_digest=OTHER_DIGEST, matches=False),
        ("GET", "/api/v1/jobs/job_1"): {"id": "job_1", "state": "completed",
                                        "result_digest": BARE_DIGEST},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_1",
                            "--interval", "0"])
    assert r.exit_code == VerificationError.code
    data = json_out(r)
    assert data["identical"] is False
    assert data["server_result_digest"] == BARE_DIGEST
    assert data["recomputed_result_digest"] == OTHER_DIGEST


def test_verify_server_surfaces_failure_reason():
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/jobs/job_1/reexecute"): (201, _queued_reexecution()),
        ("GET", "/api/v1/jobs/job_2"): _queued_reexecution(
            state="failed", failure_reason="ciphertext_digest_mismatch"),
        ("GET", "/api/v1/jobs/job_1"): {"id": "job_1", "state": "completed",
                                        "result_digest": BARE_DIGEST},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_1",
                            "--interval", "0"])
    assert r.exit_code == VerificationError.code
    data = json_out(r)
    assert data["mode"] == "server"
    assert data["identical"] is False
    assert data["failure_reason"] == "ciphertext_digest_mismatch"


def test_verify_server_respects_matches_verdict_over_equal_digests():
    """The server's `matches` verdict, when present, is authoritative — even
    when the digests the mock serves happen to look equal."""
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/jobs/job_1/reexecute"): (201, _queued_reexecution(
            state="completed", result_digest=BARE_DIGEST, matches=False)),
        ("GET", "/api/v1/jobs/job_1"): {"id": "job_1", "state": "completed",
                                        "result_digest": BARE_DIGEST},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_1",
                            "--interval", "0"])
    assert r.exit_code == VerificationError.code
    assert json_out(r)["identical"] is False


def test_top_level_verify_shortcut_dispatches_to_server_mode():
    """`blind verify <job>` calls the results verify function directly — the
    poll knobs must arrive as real values there too (regression: typer
    OptionInfo defaults leaking into the deadline arithmetic)."""
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/jobs/job_1/reexecute"): (201, _queued_reexecution(
            state="completed", result_digest=BARE_DIGEST, matches=True)),
        ("GET", "/api/v1/jobs/job_1"): {"id": "job_1", "state": "completed",
                                        "result_digest": BARE_DIGEST},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "verify", "job_1"])
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert data["mode"] == "server"
    assert data["identical"] is True


# -- local path ---------------------------------------------------------------

def test_verify_local_recomputes_and_matches_bare_hex_server_digest(installed, tmp_path):
    """Regression (major): the platform serves BARE 64-hex result digests while
    the CLI recomputes `sha256:<hex>` — a bit-identical recomputation must
    still verify (the old code string-compared and always reported MISMATCH)."""
    store, bundle, application_id = installed
    inputs, context = _write_cohort(tmp_path, [[1, 0, 2, 1], [0, 1, 1, 0], [2, 2, 0, 1]])
    cts = sorted(p for p in inputs.iterdir())
    expected = run_compute_stage(bundle, context, cts, tmp_path / "expected.bin").sha256
    bare = expected.split(":", 1)[1]  # what the Rails API actually sends

    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_9"): {"id": "job_9", "state": "completed",
                                        "result_digest": bare,
                                        "project_id": "proj_local"},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_9",
                            "--local", "--inputs", str(inputs),
                            "--context", str(context), "--bundle", str(bundle.root)])
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert data["object"] == "result_verification"
    assert data["mode"] == "local"
    assert data["server_result_digest"] == bare
    assert data["recomputed_result_digest"] == expected
    assert data["identical"] is True
    assert data["ciphertext_count"] == 3


def test_verify_local_also_accepts_prefixed_server_digest(installed, tmp_path):
    """Both digest encodings verify: a `sha256:`-prefixed server digest (older
    servers / other tooling) is equivalent to the bare form."""
    store, bundle, application_id = installed
    inputs, context = _write_cohort(tmp_path, [[1, 1], [0, 2], [2, 0]])
    cts = sorted(p for p in inputs.iterdir())
    expected = run_compute_stage(bundle, context, cts, tmp_path / "expected.bin").sha256

    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_9"): {"id": "job_9", "state": "completed",
                                        "result_digest": expected,
                                        "project_id": "proj_local"},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_9",
                            "--local", "--inputs", str(inputs),
                            "--context", str(context), "--bundle", str(bundle.root)])
    assert r.exit_code == 0, r.stdout
    assert json_out(r)["identical"] is True


def test_verify_local_resolves_pinned_bundle_and_context_from_store(installed, tmp_path):
    from blind.workspace import write_project_meta

    store, bundle, application_id = installed
    inputs, context = _write_cohort(tmp_path, [[1, 1], [2, 0], [0, 2]])
    cts = sorted(p for p in inputs.iterdir())
    expected = run_compute_stage(bundle, context, cts, tmp_path / "expected.bin").sha256

    # the project's pinned application + cached public context, as keys create leaves them
    write_project_meta(store, "proj_local", {"application": application_id})
    key_dir = store.key_dir("proj_local")
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / "public.context").write_bytes(context.read_bytes())

    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_9"): {"id": "job_9", "state": "completed",
                                        "result_digest": expected.split(":", 1)[1],
                                        "project_id": "proj_local"},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_9",
                            "--local", "--inputs", str(inputs)])
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert data["identical"] is True
    assert data["mode"] == "local"


def test_verify_local_detects_mismatch(installed, tmp_path):
    store, bundle, application_id = installed
    inputs, context = _write_cohort(tmp_path, [[1, 0], [0, 1]])

    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_9"): {"id": "job_9", "state": "completed",
                                        "result_digest": "sha256:deadbeef",
                                        "project_id": "proj_local"},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_9",
                            "--local", "--inputs", str(inputs),
                            "--context", str(context), "--bundle", str(bundle.root)])
    assert r.exit_code == VerificationError.code
    data = json_out(r)
    assert data["identical"] is False
    assert data["server_result_digest"] == "sha256:deadbeef"
    assert data["recomputed_result_digest"] != "sha256:deadbeef"


def test_verify_local_requires_inputs_dir():
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_9",
                            "--local"])
    assert r.exit_code != 0
    assert isinstance(r.exception, UsageError)


def test_verify_local_refuses_incomplete_job(installed, tmp_path):
    from blind.errors import PreconditionError

    store, bundle, application_id = installed
    inputs, context = _write_cohort(tmp_path, [[1]])
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_9"): {"id": "job_9", "state": "running",
                                        "result_digest": None,
                                        "project_id": "proj_local"},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "results", "verify", "job_9",
                            "--local", "--inputs", str(inputs),
                            "--context", str(context), "--bundle", str(bundle.root)])
    assert r.exit_code != 0
    assert isinstance(r.exception, PreconditionError)
