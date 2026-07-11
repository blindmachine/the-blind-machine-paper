"""Device-code + API-key login flows (COMMANDS.md `login`).

RFC-8628-style device flow:
  1. POST /api/v1/auth/device      → {device_code, user_code, verification_uri, interval}
  2. user approves at /device in a browser
  3. poll POST /api/v1/auth/token  → {access_token} (or {status: "pending"})

Non-interactive: `--api-key <key>` exchanges the key for a bearer token in one
call. The resulting token is stored at ~/.blind/auth/<profile>.token (chmod 600).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from blind.api import ApiClient
from blind.errors import AuthError


@dataclass
class LoginResult:
    token: str
    account: dict
    method: str  # "device" | "api_key"


def login_with_api_key(client: ApiClient, api_key: str) -> LoginResult:
    resp = client.exchange_token(api_key=api_key)
    token = resp.get("access_token")
    if not token:
        raise AuthError("Auth server did not return an access_token for the API key.")
    account = client.me(token=token)
    return LoginResult(token=token, account=account, method="api_key")


def login_with_device(
    client: ApiClient,
    *,
    on_prompt=None,
    poll: bool = True,
    max_wait: float = 300.0,
) -> LoginResult:
    """Start the device flow. ``on_prompt(user_code, verification_uri)`` displays
    the code to the user. Polls /auth/token until approved or timeout."""
    start = client.start_device()
    device_code = start["device_code"]
    user_code = start.get("user_code", "")
    verification_uri = start.get("verification_uri", "")
    interval = float(start.get("interval", 2))
    if on_prompt:
        on_prompt(user_code, verification_uri)

    if not poll:
        # Single attempt (tests / scripting).
        resp = client.exchange_token(device_code=device_code)
        token = resp.get("access_token")
        if not token:
            raise AuthError("Device not yet approved.")
        return LoginResult(token=token, account=client.me(token=token), method="device")

    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        resp = client.exchange_token(device_code=device_code)
        token = resp.get("access_token")
        if token:
            return LoginResult(token=token, account=client.me(token=token), method="device")
        if resp.get("status") not in (None, "pending", "authorization_pending"):
            raise AuthError(f"Device login failed: {resp.get('status')}")
        time.sleep(interval)
    raise AuthError("Device login timed out. Re-run `blind login`.")
