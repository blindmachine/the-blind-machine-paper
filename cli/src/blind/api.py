"""HTTP client for The Blind Machine /api/v1 contract (COMMANDS.md).

Field names and paths mirror COMMANDS.md byte-for-byte. The client is injectable:
tests pass an ``httpx.MockTransport`` so the whole suite makes ZERO network calls.

Auth: account calls use ``Authorization: Bearer <token>``. The accountless
bearer-link contributor path uses the 7-day invite token in the same header.
There is deliberately NO method that uploads a secret key — only the public
context (``put_public_context``) and encrypted ciphertext ever go up.
"""

from __future__ import annotations

import json as _json
from typing import Any

import httpx

from blind.errors import AuthError, NetworkError, PreconditionError, VerificationError
from blind.hashing import normalize_digest

API_VERSION = "v1"
MAX_BUNDLE_DOWNLOAD_BYTES = 32 * 1024 * 1024
MAX_SIGNATURE_DOWNLOAD_BYTES = 256


class ApiClient:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        # transport injection is the test seam (httpx.MockTransport → no sockets).
        self._client = httpx.Client(
            base_url=self.base_url,
            transport=transport,
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "blind-cli/0.1.0"},
        )

    # -- low level ----------------------------------------------------------
    def _headers(self, token: str | None = None) -> dict:
        tok = token or self.token
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def request(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
        token: str | None = None,
        auth_required: bool = True,
    ) -> Any:
        url = self._api_path(path)
        if auth_required and not (token or self.token):
            raise AuthError("Not logged in. Run `blind login` or use --api-key-stdin.")
        try:
            resp = self._client.request(
                method, url, json=json, params=params, headers=self._headers(token)
            )
        except httpx.HTTPError as exc:  # connection/timeout/etc.
            raise NetworkError(f"Could not reach {self.base_url}: {exc}") from exc
        return self._handle(resp)

    def _raw(self, method: str, path: str) -> httpx.Response:
        """Authenticated request returning the raw response (non-JSON bodies:
        NDJSON stage streams, plain-text logs). Errors map exactly like request()."""
        if not self.token:
            raise AuthError("Not logged in. Run `blind login` or use a private API-key source.")
        try:
            resp = self._client.request(method, self._api_path(path), headers=self._headers())
        except httpx.HTTPError as exc:
            raise NetworkError(f"Could not reach {self.base_url}: {exc}") from exc
        if not resp.is_success:
            self._handle(resp)  # raises the mapped typed error
        return resp

    def _raw_body(
        self,
        method: str,
        path: str,
        *,
        content: bytes | None = None,
        params: dict | None = None,
        token: str | None = None,
        auth_required: bool = True,
    ) -> httpx.Response:
        """Send/receive a RAW octet-stream body (the trust artifacts — public
        context, ciphertext, result — are binary TenSEAL blobs, never JSON).
        Uploads put the bytes in the request body and the digest in a query
        param; downloads return the raw response so the caller reads
        ``resp.content`` + the ``X-*-Digest`` header. Errors map like request()."""
        url = self._api_path(path)
        if auth_required and not (token or self.token):
            raise AuthError("Not logged in. Run `blind login` or use a private API-key source.")
        headers = self._headers(token)
        if content is not None:
            headers["Content-Type"] = "application/octet-stream"
        try:
            resp = self._client.request(
                method, url, content=content, params=params, headers=headers
            )
        except httpx.HTTPError as exc:
            raise NetworkError(f"Could not reach {self.base_url}: {exc}") from exc
        if not resp.is_success:
            self._handle(resp)  # raises the mapped typed error
        return resp

    def _api_path(self, path: str) -> str:
        path = path.lstrip("/")
        if path.startswith("api/"):
            return "/" + path
        if path.startswith(f"{API_VERSION}/"):
            return "/api/" + path
        return f"/api/{API_VERSION}/" + path

    def _handle(self, resp: httpx.Response) -> Any:
        if resp.status_code == 204:
            return {}
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        if resp.is_success:
            return body
        reason = (body or {}).get("error")
        message = reason or (body or {}).get("message") or resp.text
        if resp.status_code in (401, 403):
            raise AuthError(f"Authentication failed ({resp.status_code}): {message}")
        if resp.status_code == 409 or resp.status_code == 422:
            raise PreconditionError(f"Refused ({resp.status_code}): {message}", reason=reason)
        if resp.status_code == 412:
            raise VerificationError(f"Precondition failed ({resp.status_code}): {message}")
        raise NetworkError(f"HTTP {resp.status_code}: {message}")

    # -- convenience verbs --------------------------------------------------
    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def patch(self, path, **kw):
        return self.request("PATCH", path, **kw)

    def put(self, path, **kw):
        return self.request("PUT", path, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def close(self) -> None:
        self._client.close()

    # ======================================================================
    # Typed endpoints — mirror COMMANDS.md "HTTP API contract"
    # ======================================================================

    # Auth -----------------------------------------------------------------
    def start_device(self) -> dict:
        return self.post("auth/device", json={}, auth_required=False)

    def exchange_token(
        self,
        *,
        device_code: str | None = None,
        api_key: str | None = None,
        email: str | None = None,
        password: str | None = None,
    ) -> dict:
        payload: dict = {}
        if device_code:
            payload["device_code"] = device_code
        if api_key:
            payload["api_key"] = api_key
        if email:
            payload["email_address"] = email
        if password:
            payload["password"] = password
        return self.post("auth/token", json=payload, auth_required=False)

    def register(self, *, email: str, password: str) -> dict:
        """Create an account (`blind register`) and return { access_token, account }."""
        return self.post(
            "auth/registration",
            json={"email_address": email, "password": password, "password_confirmation": password},
            auth_required=False,
        )

    def me(self, token: str | None = None) -> dict:
        return self.get("me", token=token)

    # Credits ----------------------------------------------------------------
    def credits(self) -> dict:
        return self.get("credits")

    # Applications ---------------------------------------------------------
    def list_applications(self, crypto: str | None = None) -> dict:
        params = {"crypto": crypto} if crypto else None
        return self.get("applications", params=params, auth_required=False)

    def retrieve_application(self, name: str) -> dict:
        return self.get(f"applications/{name}", auth_required=False)

    def retrieve_application_version(self, name: str, digest: str) -> dict:
        return self.get(f"applications/{name}/versions/{digest}", auth_required=False)

    def _download_limited(self, url: str, *, max_bytes: int, label: str) -> bytes:
        headers = {"Accept": "application/octet-stream", "Accept-Encoding": "identity"}
        try:
            with self._client.stream("GET", url, headers=headers) as resp:
                if not resp.is_success:
                    raise NetworkError(f"{label} download failed: HTTP {resp.status_code}")
                encoding = resp.headers.get("content-encoding", "identity").lower()
                if encoding not in {"", "identity"}:
                    raise VerificationError(f"Refusing encoded {label} response")
                declared = resp.headers.get("content-length")
                if declared:
                    try:
                        if int(declared) < 0 or int(declared) > max_bytes:
                            raise VerificationError(f"{label} download exceeds the size limit")
                    except ValueError as exc:
                        raise VerificationError(f"{label} response has an invalid Content-Length") from exc
                payload = bytearray()
                chunks = [resp.content] if resp.is_stream_consumed else resp.iter_raw()
                for chunk in chunks:
                    if len(payload) + len(chunk) > max_bytes:
                        raise VerificationError(f"{label} download exceeds the size limit")
                    payload.extend(chunk)
                return bytes(payload)
        except (NetworkError, VerificationError):
            raise
        except httpx.HTTPError as exc:
            raise NetworkError(f"Could not download {label.lower()}: {exc}") from exc

    def download_bundle(self, name: str, digest: str) -> bytes:
        url = self._api_path(f"applications/{name}/versions/{digest}/bundle")
        return self._download_limited(
            url, max_bytes=MAX_BUNDLE_DOWNLOAD_BYTES, label="Bundle"
        )

    def download_signature(self, name: str, digest: str) -> bytes:
        url = self._api_path(f"applications/{name}/versions/{digest}/signature")
        return self._download_limited(
            url, max_bytes=MAX_SIGNATURE_DOWNLOAD_BYTES, label="Signature"
        )

    # Projects -------------------------------------------------------------
    def create_project(self, **fields) -> dict:
        return self.post("projects", json=fields)

    def list_projects(self, state: str | None = None) -> dict:
        params = {"state": state} if state else None
        return self.get("projects", params=params)

    def retrieve_project(self, project_id: str) -> dict:
        return self.get(f"projects/{project_id}")

    def update_project(self, project_id: str, **fields) -> dict:
        return self.patch(f"projects/{project_id}", json=fields)

    def delete_project(self, project_id: str, reason: str | None = None) -> dict:
        return self.delete(f"projects/{project_id}", json={"reason": reason} if reason else None)

    def freeze_project(self, project_id: str) -> dict:
        return self.post(f"projects/{project_id}/freeze", json={})

    def invite_project(self, project_id: str, **fields) -> dict:
        return self.post(f"projects/{project_id}/invitations", json=fields)

    def project_events(self, project_id: str, since: str | None = None) -> dict:
        params = {"since": since} if since else None
        return self.get(f"projects/{project_id}/events", params=params)

    def put_owner_key(self, project_id: str, owner_signing_pubkey: str) -> dict:
        """Register the project owner's PUBLIC Ed25519 signing key (RFC 0003). Only
        the public half is sent — the private key never leaves the machine, and the
        server never verifies with it (the contributor does, against the link key)."""
        return self.put(
            f"projects/{project_id}/owner_key",
            json={"owner_signing_pubkey": owner_signing_pubkey},
        )

    # Keys (public context only — no secret endpoint exists) ---------------
    def put_public_context(self, project_id: str, public_context_sha256: str, data) -> dict:
        """Publish the PUBLIC context bytes (raw octet-stream body). The digest
        rides in a query param (bare 64-hex, the platform's encoding)."""
        body = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
        resp = self._raw_body(
            "PUT", f"projects/{project_id}/public_context",
            content=bytes(body),
            params={"public_context_digest": normalize_digest(public_context_sha256)},
        )
        return _safe_json(resp)

    def get_public_context(self, project_id: str, token: str | None = None) -> dict:
        """Fetch the PUBLIC context. The server serves raw octet-stream bytes +
        an ``X-Public-Context-Digest`` header — not JSON."""
        resp = self._raw_body(
            "GET", f"projects/{project_id}/public_context", token=token
        )
        return {
            "public_context_bytes": resp.content,
            "public_context_digest": resp.headers.get("X-Public-Context-Digest", ""),
        }

    # Contributions --------------------------------------------------------
    def create_contribution(
        self, project_id: str, ciphertext_sha256: str, ciphertext, token: str | None = None
    ) -> dict:
        """Upload one Encrypted ciphertext blob (raw octet-stream body) + its
        digest (query param, bare 64-hex). Only ciphertext ever goes up."""
        body = ciphertext if isinstance(ciphertext, (bytes, bytearray)) else str(ciphertext).encode()
        resp = self._raw_body(
            "POST", f"projects/{project_id}/contributions",
            content=bytes(body),
            params={"ciphertext_digest": normalize_digest(ciphertext_sha256)},
            token=token,
        )
        return _safe_json(resp)

    def list_contributions(self, project_id: str, mine: bool = False) -> dict:
        path = f"projects/{project_id}/contributions"
        if mine:
            path += "/mine"
        return self.get(path)

    def retrieve_contribution(self, contribution_id: str) -> dict:
        return self.get(f"contributions/{contribution_id}")

    # Invitations (accountless contribution packet) ------------------------
    def get_invitation_packet(self, token: str) -> dict:
        """Resolve a bearer invite token to its contribution packet — project id,
        pinned application (`name@sha256:…`), published public-context digest,
        min-N, and expiry. Accountless: the token in the path is the only
        authorization, so no account/API key is required."""
        return self.get(f"invitations/{token}", token=token, auth_required=False)

    # Jobs -----------------------------------------------------------------
    def estimate_job(self, project_id: str) -> dict:
        return self.post(f"projects/{project_id}/jobs/estimate", json={})

    def create_job(self, project_id: str) -> dict:
        return self.post(f"projects/{project_id}/jobs", json={})

    def list_jobs(self, project_id: str, state: str | None = None) -> dict:
        params = {"state": state} if state else None
        return self.get(f"projects/{project_id}/jobs", params=params)

    def retrieve_job(self, job_id: str) -> dict:
        return self.get(f"jobs/{job_id}")

    def job_events(self, job_id: str) -> dict:
        """GET the job stage stream. The server emits NDJSON (one JSON object per
        line: lifecycle queued/running/completed/failed lines interleaved with
        fine worker stages). Malformed lines are refused so a corrupted/hostile
        stream cannot hide a failure transition. Plain-JSON bodies (older servers / mocks) are
        accepted too. Returns ``{"events": [...]}``."""
        resp = self._raw("GET", f"jobs/{job_id}/events")
        try:
            body = resp.json()
        except Exception:
            body = None
        if isinstance(body, dict):
            return body if "events" in body else {"events": [body]}
        if isinstance(body, list):
            return {"events": body}
        events = []
        for line in (resp.text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = _json.loads(line)
            except _json.JSONDecodeError as exc:
                raise VerificationError("Malformed JSON in job event stream") from exc
            if not isinstance(event, dict):
                raise VerificationError("Job event stream entries must be JSON objects")
            events.append(event)
        return {"events": events}

    def job_logs(self, job_id: str) -> dict:
        """GET the worker log. The server serves plain text; a JSON body with a
        ``logs`` key is accepted too. Returns ``{"logs": [...]}``."""
        resp = self._raw("GET", f"jobs/{job_id}/logs")
        try:
            body = resp.json()
        except Exception:
            body = None
        if isinstance(body, dict) and "logs" in body:
            return body
        if isinstance(body, list):
            return {"logs": body}
        return {"logs": (resp.text or "").splitlines()}

    # Results + certificates ----------------------------------------------
    def retrieve_result(self, job_id: str) -> dict:
        """Download the Encrypted result. The server streams raw octet-stream
        bytes + an ``X-Result-Digest`` header — not JSON."""
        resp = self._raw_body("GET", f"jobs/{job_id}/result")
        digest = resp.headers.get("X-Result-Digest", "")
        # Fail closed by construction: an honest server ALWAYS sets this integrity
        # header (jobs_controller#result), so an absent/empty one is a hostile or
        # tampering middlebox — never return unverifiable bytes to a caller (belt to
        # each caller's digest-match brace via hashing.require_result_digest).
        if not normalize_digest(digest):
            raise VerificationError(
                "Result response is missing the X-Result-Digest integrity header")
        return {
            "ciphertext_bytes": resp.content,
            "result_digest": digest,
        }

    def list_certificates(self, project_id: str) -> dict:
        return self.get(f"projects/{project_id}/certificates")

    # Public verification (no auth) ---------------------------------------
    def retrieve_certificate(self, certificate_hash: str) -> dict:
        return self.get(f"certificates/{certificate_hash}", auth_required=False)

    def lookup_result_digest(self, result_digest: str) -> dict:
        return self.get(f"results/{result_digest}", auth_required=False)

    # Raw power commands ---------------------------------------------------
    def raw_get(self, path: str) -> Any:
        return self.get(path)

    def raw_post(self, path: str, data: dict | None = None) -> Any:
        return self.post(path, json=data or {})


def _safe_json(resp: httpx.Response) -> dict:
    """Best-effort JSON body for a raw-body response (uploads answer with a small
    JSON envelope). An empty/non-JSON body degrades to ``{}``."""
    try:
        body = resp.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {"data": body}


def parse_field_pairs(pairs: list[str]) -> dict:
    """Turn ['a=1','b=x'] into {'a': 1, 'b': 'x'} for `--field k=v`. Values that
    parse as JSON scalars are coerced; everything else stays a string."""
    out: dict = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"Bad --field (want k=v): {pair!r}")
        key, val = pair.split("=", 1)
        try:
            out[key] = _json.loads(val)
        except Exception:
            out[key] = val
    return out
