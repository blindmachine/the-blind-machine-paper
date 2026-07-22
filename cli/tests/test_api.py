"""ApiClient contract — all HTTP mocked (zero network). Field names per COMMANDS.md."""

from __future__ import annotations

import gzip

import httpx
import pytest

from blind import api as api_module
from blind.api import ApiClient, parse_field_pairs
from blind.errors import AuthError, PreconditionError, VerificationError
from tests.conftest import mock_transport


def test_bearer_header_and_path_versioning():
    seen = {}

    def route(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"projects": []})

    client = ApiClient("https://x.test", token="tok_123",
                       transport=mock_transport({("GET", "/api/v1/projects"): route}))
    client.list_projects()
    assert seen["auth"] == "Bearer tok_123"
    assert seen["path"] == "/api/v1/projects"


def test_create_project_posts_fields():
    captured = {}

    def route(request: httpx.Request) -> httpx.Response:
        import json
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"id": "proj_1", "state": "active"})

    client = ApiClient("https://x.test", token="t",
                       transport=mock_transport({("POST", "/api/v1/projects"): route}))
    out = client.create_project(application="p@sha256:ab", name="Cohort", min_contributors=20)
    assert out["id"] == "proj_1"
    assert captured["application"] == "p@sha256:ab"
    assert captured["min_contributors"] == 20


def test_auth_required_without_token_raises():
    client = ApiClient("https://x.test", token=None, transport=mock_transport({}))
    with pytest.raises(AuthError):
        client.list_projects()


def test_public_endpoints_need_no_auth():
    client = ApiClient("https://x.test", token=None, transport=mock_transport(
        {("GET", "/api/v1/applications"): {"applications": [{"name": "allele_frequency_count"}]}}))
    out = client.list_applications()
    assert out["applications"][0]["name"] == "allele_frequency_count"


def test_bundle_download_rejects_oversized_response(monkeypatch):
    monkeypatch.setattr(api_module, "MAX_BUNDLE_DOWNLOAD_BYTES", 4)
    client = ApiClient("https://x.test", transport=mock_transport({
        ("GET", "/api/v1/applications/demo/versions/" + "a" * 64 + "/bundle"):
            lambda _request: httpx.Response(200, content=b"12345"),
    }))
    with pytest.raises(VerificationError):
        client.download_bundle("demo", "a" * 64)


def test_bundle_download_rejects_content_encoding():
    path = "/api/v1/applications/demo/versions/" + "a" * 64 + "/bundle"
    client = ApiClient("https://x.test", transport=mock_transport({
        ("GET", path): lambda _request: httpx.Response(
            200, content=gzip.compress(b"encoded"), headers={"Content-Encoding": "gzip"}
        ),
    }))
    with pytest.raises(VerificationError):
        client.download_bundle("demo", "a" * 64)


def test_error_mapping():
    client = ApiClient("https://x.test", token="t", transport=mock_transport(
        {("POST", "/api/v1/projects/proj_1/jobs"): (409, {"error": "cohort not frozen"})}))
    with pytest.raises(PreconditionError):
        client.create_job("proj_1")

    client2 = ApiClient("https://x.test", token="t", transport=mock_transport(
        {("GET", "/api/v1/projects"): (401, {"error": "bad token"})}))
    with pytest.raises(AuthError):
        client2.list_projects()


def test_freeze_and_contribution_paths():
    client = ApiClient("https://x.test", token="t", transport=mock_transport({
        ("POST", "/api/v1/projects/proj_1/freeze"): {"cohort_commitment": "sha256:aa",
                                                      "cohort_size": 21,
                                                      "min_contributors_satisfied": True},
        ("POST", "/api/v1/projects/proj_1/contributions"): {"id": "contr_a1",
                                                             "cohort_size": 21},
    }))
    fr = client.freeze_project("proj_1")
    assert fr["cohort_commitment"] == "sha256:aa"
    co = client.create_contribution("proj_1", "sha256:ct", "CIPHER", token="invite_tok")
    assert co["id"] == "contr_a1"


def test_no_secret_key_endpoint_exists():
    """Structural: the client exposes public-context upload but nothing for a secret."""
    methods = dir(ApiClient)
    assert "put_public_context" in methods
    assert not any("secret" in m.lower() or "private" in m.lower() for m in methods)


def test_parse_field_pairs():
    assert parse_field_pairs(["a=1", "b=x", 'c={"k":1}']) == {"a": 1, "b": "x", "c": {"k": 1}}
    with pytest.raises(ValueError):
        parse_field_pairs(["bad"])
