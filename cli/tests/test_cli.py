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
    route_digest = digest.removeprefix("sha256:")

    # tar the bundle (strip the .blind-signature; server serves it separately)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(
            src,
            arcname="bundle",
            filter=lambda member: None if member.name.endswith("/.blind-signature") else member,
        )
    tar_bytes = buf.getvalue()
    sig_bytes = (src / ".blind-signature").read_text().strip().encode()

    def bundle_route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=tar_bytes)

    def sig_route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=sig_bytes)

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/applications/{name}/versions/{route_digest}/bundle"): bundle_route,
        ("GET", f"/api/v1/applications/{name}/versions/{route_digest}/signature"): sig_route,
    }))

    r = runner.invoke(app, ["--json", "applications", "install", application_id])
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


def test_failed_forced_install_preserves_verified_existing_bundle(installed, make_bundle):
    store, _bundle, application_id = installed
    src, replacement_id = make_bundle(sign=True)
    assert replacement_id == application_id
    name, digest = application_id.split("@", 1)
    route_digest = digest.removeprefix("sha256:")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(
            src,
            arcname="bundle",
            filter=lambda member: None if member.name.endswith("/.blind-signature") else member,
        )
    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/applications/{name}/versions/{route_digest}/bundle"):
            lambda _request: httpx.Response(200, content=buf.getvalue()),
        ("GET", f"/api/v1/applications/{name}/versions/{route_digest}/signature"):
            lambda _request: httpx.Response(200, content=("00" * 64).encode()),
    }))

    result = runner.invoke(
        app, ["--json", "applications", "install", application_id, "--force"]
    )
    assert result.exit_code != 0

    from blind.workspace import installed_bundle

    assert installed_bundle(store, application_id).digest == digest


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


def test_applications_verify_exits_nonzero_on_tampered_signature(installed):
    """A scripted/CI caller gates on the EXIT CODE of `blind applications verify`;
    a tampered/unsigned bundle must exit 6, not just print a red row (issue #2)."""
    store, _bundle, application_id = installed
    # Corrupt the detached signature so Ed25519 verification fails closed.
    (store.application_dir(application_id) / ".blind-signature").write_text("00" * 64 + "\n")

    ctxmod.set_test_transport(None)  # verify is fully offline
    r = runner.invoke(app, ["--json", "applications", "verify", application_id])
    assert r.exit_code == 6, r.stdout
    data = _json_out(r)
    assert data["verified"] is False
    assert data["checks"]["signature"] is False


def test_results_retrieve_fails_closed_when_digest_absent():
    """A hostile server that strips X-Result-Digest must not get its (possibly
    swapped) bytes accepted as a result (issue #1, absent-header case)."""
    from blind.errors import VerificationError

    def result_route(_request):
        return httpx.Response(200, content=b"\x01\x02unverifiable")  # NO digest header

    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_x/result"): result_route,
    }))
    r = runner.invoke(app, ["--json", "--api-key-stdin", "results", "retrieve", "job_x"],
                      input="k\n")
    assert r.exit_code != 0
    assert isinstance(r.exception, VerificationError)
    assert r.exception.code == 6


def test_results_retrieve_accepts_matching_digest(tmp_path):
    from blind.hashing import sha256_prefixed

    ct = b"\x09\x09aggregate-ciphertext"

    def result_route(_request):
        return httpx.Response(200, content=ct,
                              headers={"X-Result-Digest": sha256_prefixed(ct)})

    ctxmod.set_test_transport(mock_transport({
        ("GET", "/api/v1/jobs/job_ok/result"): result_route,
    }))
    r = runner.invoke(app, ["--json", "--api-key-stdin", "results", "retrieve", "job_ok",
                            "--out", str(tmp_path / "r")], input="k\n")
    assert r.exit_code == 0, r.stdout
    assert _json_out(r)["verified"] is True


def _consistent_certificate():
    from blind.certificates import build_certificate

    return build_certificate(
        application_digest="p@sha256:abc", project_id="proj_1",
        public_context_sha256="sha256:pub",
        contribution_hashes=["sha256:a", "sha256:b", "sha256:c"],
        result_digest="sha256:r", min_contributors=3)


def test_certificates_verify_rejects_substituted_certificate():
    """A certificate is content-addressed: the untrusted server, asked for X, must
    not be able to answer with a DIFFERENT self-consistent certificate Y."""
    cert = _consistent_certificate()  # internally consistent, but its own hash != requested
    requested = "f" * 64
    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/certificates/{requested}"): cert,
    }))
    r = runner.invoke(app, ["--json", "certificates", "verify", requested])
    assert r.exit_code == 6, r.stdout
    assert _json_out(r)["requested_hash_bound"] is False


def test_certificates_verify_binds_correct_requested_hash():
    from blind.hashing import normalize_digest

    cert = _consistent_certificate()
    requested = normalize_digest(cert["certificate_hash"])  # ask for the RIGHT one
    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/certificates/{requested}"): cert,
    }))
    r = runner.invoke(app, ["--json", "certificates", "verify", requested])
    assert r.exit_code == 0, r.stdout
    assert _json_out(r)["verified"] is True


def test_certificates_retrieve_rejects_substituted_certificate():
    from blind.errors import VerificationError

    cert = _consistent_certificate()
    requested = "e" * 64
    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/certificates/{requested}"): cert,
    }))
    r = runner.invoke(app, ["--json", "certificates", "retrieve", requested])
    assert r.exit_code != 0
    assert isinstance(r.exception, VerificationError)


def test_keys_retrieve_exits_nonzero_on_public_context_mismatch(installed):
    """`blind keys retrieve` hashes the server's ACTUAL public-context bytes (not
    its self-reported header); a definite local≠server mismatch fails the exit code."""
    from blind.workspace import run_keygen

    store, bundle, application_id = installed
    project = "proj_keys"
    run_keygen(store, project, bundle)  # writes local public.context + stores the secret

    def pc_route(_request):
        # Different bytes than the local context, plus a mismatching (ignored) header.
        return httpx.Response(200, content=b"tampered-public-context",
                              headers={"X-Public-Context-Digest": "sha256:" + "0" * 64})

    ctxmod.set_test_transport(mock_transport({
        ("GET", f"/api/v1/projects/{project}/public_context"): pc_route,
    }))
    r = runner.invoke(app, ["--json", "--api-key-stdin", "keys", "retrieve", "--project", project],
                      input="k\n")
    assert r.exit_code == 6, r.stdout
    assert _json_out(r)["matches_server"] is False


def test_login_with_api_key():
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/auth/token"): {"access_token": "tok_abc"},
        ("GET", "/api/v1/me"): {"email": "researcher@example.test"},
    }))
    r = runner.invoke(app, ["--json", "login", "--api-key-stdin"], input="sk_test_123\n")
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["method"] == "api_key"
    assert data["account"] == "researcher@example.test"


def test_password_stdin_login_flow():
    captured = {}

    def exchange(request):
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={
            "access_token": "tok_password",
            "account": {"email": "password@example.test"},
        })

    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/auth/token"): exchange,
    }))
    r = runner.invoke(
        app,
        ["--json", "login", "--email", "password@example.test", "--password-stdin"],
        input="stdin-only-password  \n",
    )
    assert r.exit_code == 0, r.stdout
    assert _json_out(r)["method"] == "password"
    assert captured["password"] == "stdin-only-password  "


def test_password_stdin_registration_flow():
    captured = {}

    def register(request):
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={
            "access_token": "tok_registered",
            "account": {"email": "new@example.test"},
        })

    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/auth/registration"): register,
    }))
    r = runner.invoke(
        app,
        ["--json", "register", "--email", "new@example.test", "--password-stdin"],
        input="stdin-only-password\n",
    )
    assert r.exit_code == 0, r.stdout
    assert _json_out(r)["method"] == "register"
    assert captured["password"] == "stdin-only-password"


def test_explicit_password_login_flow():
    captured = {}

    def exchange(request):
        captured.update(json.loads(request.content))
        return httpx.Response(200, json={
            "access_token": "tok_password",
            "account": {"email": "password@example.test"},
        })

    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/auth/token"): exchange,
    }))
    r = runner.invoke(
        app,
        ["--json", "login", "--email", "password@example.test", "--password", "password"],
    )
    assert r.exit_code == 0, r.stdout
    assert _json_out(r)["method"] == "password"
    assert captured["password"] == "password"


def test_explicit_password_registration_flow():
    captured = {}

    def register(request):
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={
            "access_token": "tok_registered",
            "account": {"email": "new@example.test"},
        })

    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/auth/registration"): register,
    }))
    r = runner.invoke(
        app,
        ["--json", "register", "--email", "new@example.test", "--password", "password"],
    )
    assert r.exit_code == 0, r.stdout
    assert _json_out(r)["method"] == "register"
    assert captured["password"] == "password"


def test_arbitrary_credential_file_flags_are_removed():
    for flag in ("--api-key-file", "--password-file"):
        r = runner.invoke(app, ["login", flag, "/tmp/must-not-be-read"])
        assert r.exit_code == 2
        assert "must-not-be-read" not in r.stdout


def test_api_key_values_are_not_accepted_as_cli_arguments():
    r = runner.invoke(app, ["login", "--api-key", "must-not-appear"])
    assert r.exit_code == 2
    assert "must-not-appear" not in r.stdout


def test_stdin_credentials_reject_multiline_and_oversized_values():
    for secret in ("first-line\nsecond-line\n", "x" * (16 * 1024 + 1)):
        r = runner.invoke(app, ["login", "--api-key-stdin"], input=secret)
        assert r.exit_code != 0
        assert secret[:32] not in r.stdout


def test_projects_create_cli():
    ctxmod.set_test_transport(mock_transport({
        ("POST", "/api/v1/projects"): {"id": "proj_9", "state": "active",
                                       "min_contributors": 20},
    }))
    r = runner.invoke(
        app,
        ["--json", "--api-key-stdin", "projects", "create",
         "--application", "allele_frequency_count@sha256:ab",
         "--name", "Cohort", "--min-contributors", "20"],
        input="k\n",
    )
    assert r.exit_code == 0, r.stdout
    data = _json_out(r)
    assert data["id"] == "proj_9"
