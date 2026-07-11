"""End-to-end CLI smoke tests via Typer's CliRunner. Remote commands use a mock
transport (zero network). Exercises the trust/verify surface byte-paths."""

from __future__ import annotations

import io
import json
import tarfile

import httpx
from typer.testing import CliRunner

import blind.context as ctxmod
from blind.cli.app import app
from tests.conftest import mock_transport

runner = CliRunner()


def _json_out(result):
    # rich may pretty-print JSON; find the first { and parse to the matching braces.
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


def test_version_json():
    result = runner.invoke(app, ["--json", "version"])
    assert result.exit_code == 0
    data = _json_out(result)
    assert data["object"] == "version"
    assert data["version"] == "0.1.0"


def test_resources_lists_all_groups():
    result = runner.invoke(app, ["--json", "resources"])
    data = _json_out(result)
    assert "applications" in data["data"]
    assert "certificates" in data["data"]
    assert "simulations" in data["data"]


def test_config_set_and_list():
    r1 = runner.invoke(app, ["config", "--set", "api=https://example.test"])
    assert r1.exit_code == 0
    r2 = runner.invoke(app, ["--json", "config", "--list"])
    data = _json_out(r2)
    assert data["api"] == "https://example.test"


def test_doctor_offline_json():
    result = runner.invoke(app, ["--json", "doctor", "--offline"])
    assert result.exit_code == 0
    data = _json_out(result)
    assert data["object"] == "doctor"
    names = {c["name"] for c in data["checks"]}
    assert {"python", "uv (env sealer)", "cryptography", "~/.blind"} <= names
    # API must be absent under --offline
    assert "API" not in names


def test_applications_install_verify_explain(make_bundle, signing_keys):
    src, application_id = make_bundle(sign=True)
    name = application_id.split("@")[0]
    digest = application_id.split("@")[1]

    # tar the bundle (strip the .blind-signature; server serves it separately)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(src, arcname="bundle")
    tar_bytes = buf.getvalue()
    sig_bytes = (src / ".blind-signature").read_text().strip().encode()

    def bundle_route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=tar_bytes)

    def sig_route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=sig_bytes)

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/applications/{name}/versions/{digest}/bundle"): bundle_route,
        ("GET", f"/api/v1/applications/{name}/versions/{digest}/signature"): sig_route,
    }))

    r = runner.invoke(app, ["--json", "applications", "install", application_id, "--no-seal"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["digest_verified"] is True
    assert data["signature_verified"] is True
    assert data["digest"] == digest

    # offline verify (no transport needed)
    ctxmod.set_test_transport(None)
    rv = runner.invoke(app, ["--json", "applications", "verify", application_id])
    vd = _json_out(rv)
    assert vd["verified"] is True

    re = runner.invoke(app, ["--json", "applications", "explain", application_id])
    ed = _json_out(re)
    assert ed["computation"] == "additive_bfv"


def test_certificates_verify_file_offline(tmp_path):
    from blind.certificates import build_certificate

    cert = build_certificate(
        application_digest="p@sha256:abc",
        project_id="proj_1",
        public_context_sha256="sha256:pub",
        contribution_hashes=["sha256:a", "sha256:b", "sha256:c"],
        result_digest="sha256:r",
        min_contributors=3,
    )
    cert_file = tmp_path / "cert.json"
    cert_file.write_text(json.dumps(cert))
    r = runner.invoke(app, ["--json", "certificates", "verify", "--file", str(cert_file)])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["verified"] is True


def test_certificates_verify_detects_tamper(tmp_path):
    from blind.certificates import build_certificate

    cert = build_certificate(
        application_digest="p@sha256:abc", project_id="proj_1",
        public_context_sha256="sha256:pub",
        contribution_hashes=["sha256:a", "sha256:b", "sha256:c"],
        result_digest="sha256:r", min_contributors=3,
    )
    cert["result_digest"] = "sha256:tampered"
    cert_file = tmp_path / "cert.json"
    cert_file.write_text(json.dumps(cert))
    r = runner.invoke(app, ["--json", "certificates", "verify", "--file", str(cert_file)])
    assert r.exit_code == 6  # VerificationError exit code
    data = _json_out(r)
    assert data["verified"] is False


def test_simulate_cli(installed):
    store, bundle, application_id = installed
    r = runner.invoke(app, ["--json", "simulate", application_id, "--synthetic",
                            "--n", "4,6", "--length", "4", "--encrypted"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["authoritative"] is False
    assert len(data["runs"]) == 2
    assert all(run["equivalence"]["passed"] for run in data["runs"])


def test_verify_dispatch_to_application(installed):
    store, bundle, application_id = installed
    r = runner.invoke(app, ["--json", "verify", application_id])
    data = _json_out(r)
    assert data["object"] == "application_verification"
    assert data["verified"] is True


def test_login_with_api_key():
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/auth/token"): {"access_token": "tok_abc"},
        ("GET", "/api/v1/me"): {"email": "researcher@example.test"},
    }))
    r = runner.invoke(app, ["--json", "login", "--api-key", "sk_test_123"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["method"] == "api_key"
    assert data["account"] == "researcher@example.test"


def test_projects_create_cli():
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/projects"): {"id": "proj_9", "state": "active",
                                       "min_contributors": 20},
    }))
    r = runner.invoke(app, ["--json", "--api-key", "k", "projects", "create",
                            "--application", "allele_frequency_count@sha256:ab",
                            "--name", "Cohort", "--min-contributors", "20"])
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["id"] == "proj_9"
