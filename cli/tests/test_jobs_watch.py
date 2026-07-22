"""`blind jobs watch` — polling the NDJSON stage stream (legacy 4-line shape AND
the interleaved fine-stage shape), dedupe, terminal detection, failure_reason."""

from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

import blind.context as ctxmod
from blind.cli.app import app
from tests.conftest import json_out, mock_transport

runner = CliRunner()

LEGACY_COMPLETED = "\n".join([
    '{"stage":"queued","at":"2026-07-05T10:00:00Z"}',
    '{"stage":"running","at":"2026-07-05T10:00:01Z"}',
    '{"stage":"completed","at":"2026-07-05T10:00:40Z","result_digest":"sha256:8f0c"}',
]) + "\n"

FINE_LINES = [
    '{"stage":"queued","at":"2026-07-05T10:00:00Z"}',
    '{"stage":"running","at":"2026-07-05T10:00:01Z"}',
    '{"stage":"verify_contexts","at":"2026-07-05T10:00:01Z","status":"ok","elapsed_ms":40,'
    '"bundle_digest":"sha256:bd","ciphertext_count":3}',
    '{"stage":"seal_env","at":"2026-07-05T10:00:02Z","status":"ok","elapsed_ms":3010,'
    '"env_lock":"sha256:5e7d","cache":"hit"}',
    '{"stage":"compute","at":"2026-07-05T10:00:05Z","status":"ok","elapsed_ms":31000,'
    '"ciphertext_count":3,"exit_status":0}',
    '{"stage":"store_result","at":"2026-07-05T10:00:36Z","status":"ok","elapsed_ms":90,'
    '"result_digest":"sha256:8f0c"}',
    '{"stage":"completed","at":"2026-07-05T10:00:37Z","result_digest":"sha256:8f0c"}',
]
FINE_COMPLETED = "\n".join(FINE_LINES) + "\n"

FAILED = "\n".join([
    '{"stage":"queued","at":"2026-07-05T10:00:00Z"}',
    '{"stage":"running","at":"2026-07-05T10:00:01Z"}',
    '{"stage":"verify_contexts","at":"2026-07-05T10:00:01Z","status":"failed",'
    '"elapsed_ms":12,"error":"ciphertext_digest_mismatch"}',
    '{"stage":"failed","at":"2026-07-05T10:00:02Z","failure_reason":"ciphertext_digest_mismatch"}',
]) + "\n"


def _ndjson_route(body: str):
    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body.encode(),
                              headers={"content-type": "application/x-ndjson"})
    return route


def _watch(job: str = "job_1", *extra):
    return runner.invoke(
        app,
        ["--json", "--api-key-stdin", "jobs", "watch", job, "--interval", "0", *extra],
        input="k\n",
    )


def test_watch_legacy_four_line_shape():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(LEGACY_COMPLETED),
    }))
    r = _watch()
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert data["object"] == "job_watch"
    assert data["job"] == "job_1"
    assert [s["stage"] for s in data["stages"]] == ["queued", "running", "completed"]
    assert data["result_digest"] == "sha256:8f0c"


def test_watch_interleaved_fine_stage_shape():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(FINE_COMPLETED),
    }))
    r = _watch()
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert [s["stage"] for s in data["stages"]] == [
        "queued", "running",
        "verify_contexts", "seal_env", "compute", "store_result",
        "completed",
    ]
    # unknown/detail keys survive the NDJSON round trip
    seal = next(s for s in data["stages"] if s["stage"] == "seal_env")
    assert seal["env_lock"] == "sha256:5e7d"
    assert seal["cache"] == "hit"
    assert seal["elapsed_ms"] == 3010
    assert data["result_digest"] == "sha256:8f0c"


def test_watch_polls_and_dedupes_across_responses():
    calls = {"n": 0}
    partial = "\n".join(FINE_LINES[:2]) + "\n"

    def route(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        body = partial if calls["n"] == 1 else FINE_COMPLETED
        return httpx.Response(200, content=body.encode(),
                              headers={"content-type": "application/x-ndjson"})

    ctxmod.set_test_transport(mock_transport({("GET", "/api/v1/jobs/job_1/events"): route}))
    r = _watch()
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert calls["n"] == 2  # kept polling until the terminal line
    stages = [s["stage"] for s in data["stages"]]
    assert stages == ["queued", "running",
                      "verify_contexts", "seal_env", "compute", "store_result", "completed"]
    assert len(stages) == len(set(zip(
        stages,
        [s.get("at") for s in data["stages"]],
        [s.get("status") for s in data["stages"]],
    )))  # each (stage, at, status) transition appears exactly once


def test_watch_failed_run_exits_nonzero_with_failure_reason():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(FAILED),
    }))
    r = _watch()
    assert r.exit_code == 1
    data = json_out(r)
    assert data["failure_reason"] == "ciphertext_digest_mismatch"
    assert data["result_digest"] is None
    failed = next(s for s in data["stages"] if s["stage"] == "verify_contexts")
    assert failed["status"] == "failed"
    assert failed["error"] == "ciphertext_digest_mismatch"


def test_watch_times_out_without_terminal_line():
    body = "\n".join(FINE_LINES[:2]) + "\n"
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(body),
    }))
    r = _watch("job_1", "--timeout", "0")
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert [s["stage"] for s in data["stages"]] == ["queued", "running"]
    assert data["result_digest"] is None


def test_watch_pretty_mode_renders_stages_and_completion_panel():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(FINE_COMPLETED),
    }))
    r = runner.invoke(
        app, ["--api-key-stdin", "jobs", "watch", "job_1", "--interval", "0"], input="k\n"
    )
    assert r.exit_code == 0, r.stdout
    assert "verify_contexts" in r.stdout
    assert "seal_env" in r.stdout
    assert "Job complete" in r.stdout


def test_job_events_refuses_malformed_lines():
    body = "\n".join([
        '{"stage":"queued","at":"t0"}',
        "this is not json",
        '{"stage":"verify_contexts","at":"t1","status":"ok","novel_key":123}',
    ]) + "\n"
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(body),
    }))
    from blind.api import ApiClient
    client = ApiClient("https://x.test", token="t",
                       transport=mock_transport({
                           ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(body)}))
    from blind.errors import VerificationError

    with pytest.raises(VerificationError):
        client.job_events("job_1")


def test_job_events_keeps_unknown_keys_in_valid_stream():
    body = '\n'.join([
        '{"stage":"queued","at":"t0"}',
        '{"stage":"verify_contexts","at":"t1","status":"ok","novel_key":123}',
    ]) + '\n'
    from blind.api import ApiClient

    client = ApiClient("https://x.test", token="t", transport=mock_transport({
        ("GET", "/api/v1/jobs/job_1/events"): _ndjson_route(body),
    }))
    data = client.job_events("job_1")
    assert [event["stage"] for event in data["events"]] == ["queued", "verify_contexts"]
    assert data["events"][1]["novel_key"] == 123


def test_job_logs_parses_plain_text_body():
    def route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[worker] line one\n[worker] line two\n",
                              headers={"content-type": "text/plain"})

    from blind.api import ApiClient
    client = ApiClient("https://x.test", token="t",
                       transport=mock_transport({("GET", "/api/v1/jobs/job_1/logs"): route}))
    data = client.job_logs("job_1")
    assert data["logs"] == ["[worker] line one", "[worker] line two"]


def test_jobs_retrieve_shows_failure_reason_row():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_1"): {"id": "job_1", "state": "failed",
                                        "failure_reason": "wall_limit_exceeded"},
    }))
    r = runner.invoke(app, ["--api-key-stdin", "jobs", "retrieve", "job_1"], input="k\n")
    assert r.exit_code == 0, r.stdout
    assert "failure reason" in r.stdout
    assert "wall_limit_exceeded" in r.stdout
    # --json keeps the raw field
    rj = runner.invoke(
        app, ["--json", "--api-key-stdin", "jobs", "retrieve", "job_1"], input="k\n"
    )
    assert json_out(rj)["failure_reason"] == "wall_limit_exceeded"
