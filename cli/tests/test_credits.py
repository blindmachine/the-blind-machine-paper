"""`blind credits` + the insufficient_credits refusal path (zero network)."""

from __future__ import annotations

from typer.testing import CliRunner

import blind.context as ctxmod
from blind.cli.app import app
from tests.conftest import json_out, mock_transport

runner = CliRunner()

_INSUFFICIENT_ROUTES = {
    ("POST", "/api/v1/projects/proj_1/jobs/estimate"): {
        "estimated_cpu_seconds": 2.0, "estimated_cost_cents": 50,
        "estimated_cost_usd": "0.50", "cohort_commitment": "sha256:c"},
    ("POST", "/api/v1/projects/proj_1/jobs"): (409, {"error": "insufficient_credits"}),
    ("GET", "/api/v1/credits"): {"balance_cents": 0, "balance_usd": "0.00"},
}


def test_credits_prints_balance():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/credits"): {"balance_cents": 1250, "balance_usd": "12.50"},
    }))
    r = runner.invoke(app, ["--json", "--api-key-stdin", "credits"], input="k\n")
    assert r.exit_code == 0, r.stdout
    data = json_out(r)
    assert data["object"] == "credits"
    assert data["balance_cents"] == 1250
    assert data["balance_usd"] == "12.50"


def test_credits_pretty_shows_balance_and_top_up_url():
    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/credits"): {"balance_cents": 1250, "balance_usd": "12.50"},
    }))
    r = runner.invoke(app, ["--api-key-stdin", "credits"], input="k\n")
    assert r.exit_code == 0, r.stdout
    assert "$12.50" in r.stdout
    assert "/billing" in r.stdout


def test_jobs_create_insufficient_credits_enriches_the_error_envelope():
    ctxmod.set_test_transport(mock_transport(_INSUFFICIENT_ROUTES))
    r = runner.invoke(app, ["--json", "--api-key-stdin",
                            "jobs", "create", "--project", "proj_1"], input="k\n")
    assert r.exit_code == 5, r.stdout  # precondition exit code (UX.md Part D)
    data = json_out(r)
    assert data["object"] == "error"
    assert data["kind"] == "precondition"
    assert data["balance_cents"] == 0
    assert data["balance_usd"] == "0.00"
    assert data["estimated_cost_usd"] == "0.50"
    assert data["top_up_url"].endswith("/billing")


def test_jobs_create_insufficient_credits_prints_balance_estimate_and_top_up():
    ctxmod.set_test_transport(mock_transport(_INSUFFICIENT_ROUTES))
    r = runner.invoke(app, ["--api-key-stdin",
                            "jobs", "create", "--project", "proj_1", "--yes"], input="k\n")
    assert r.exit_code == 5, r.stdout
    assert "Insufficient credits" in r.stdout
    assert "$0.00" in r.stdout
    assert "$0.50" in r.stdout
    assert "/billing" in r.stdout


def test_jobs_create_other_conflicts_still_raise():
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/projects/proj_1/jobs/estimate"): {
            "estimated_cost_cents": 50, "estimated_cost_usd": "0.50"},
        ("POST", "/api/v1/projects/proj_1/jobs"): (409, {"error": "not_frozen"}),
    }))
    r = runner.invoke(app, ["--json", "--api-key-stdin",
                            "jobs", "create", "--project", "proj_1"], input="k\n")
    assert r.exit_code != 0
    assert "not_frozen" in str(r.exception or r.stdout)
