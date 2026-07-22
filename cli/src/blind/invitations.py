"""Signed invitations (RFC 0003) — the keyholder-side trust anchor for the
public-context digest.

A malicious hosted service can serve a public FHE context whose SECRET key the
*service* holds, so contributors encrypt to the server's key instead of the
legitimate keyholder's (paper §7.2). Auto-pinning the digest from the server's
own invitation packet defends against nothing — the server substitutes context and
digest in lock-step.

The fix: the project OWNER holds a local Ed25519 signing key (beside the FHE secret,
never uploaded) and signs a canonical *invitation intent* that binds the exact
``public_context_digest``. The owner's PUBLIC key is delivered to the contributor in
the invite link's URL **fragment** (``…/c/<token>#k=<b64url-pubkey>``) — a value the
server never sees on fetch and cannot substitute, *provided the link reached the
contributor over a channel the service does not operate*. The contributor's CLI
verifies the signature under the FRAGMENT key (never a server-supplied key) before
encrypting, and fails closed.

This module is the single source of truth for HOW the intent is canonicalized,
signed, and verified. It mirrors ``runtime/bundle.py``'s Ed25519 convention (sign
over a bare 64-hex digest string, reject weak keys, raise rather than return False)
but with an explicit ``kind`` domain-separation tag so an owner signature can never
be replayed as a bundle / context / certificate signature.
"""

from __future__ import annotations

import base64
import re
import secrets
from datetime import datetime, timedelta, timezone

from blind.errors import VerificationError
from blind.hashing import canonical_json, digests_match, normalize_digest, sha256_hex

# Domain-separation tag baked INTO the signed payload (RFC 0003 [H7]). An owner
# Ed25519 signature is a signature over sha256(canonical_json(intent)); because the
# intent always carries this `kind`, the signed bytes are structurally distinct from
# a bundle digest / context digest / certificate hash, so an owner signature can
# never be cross-presented in another verification context.
INVITE_KIND = "blind-invitation-v1"

# The exact keys the owner signs. Order does not matter (canonical_json sorts), but
# the SET and each field's TYPE are load-bearing ([H10]) — the contributor validates
# every field against this discipline before hashing, and refuses a malformed intent.
INTENT_FIELDS = frozenset({
    "kind", "project_id", "token_commitment", "application_digest",
    "public_context_digest", "context_epoch", "min_contributors", "expires_at",
})

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Strict UTC ISO-8601 second-precision, e.g. 2026-07-19T12:34:56Z. The owner emits
# this exact shape; the contributor parses it for the local expiry check.
_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# -- owner signing keypair (local; the private half never leaves the machine) ----

def generate_owner_keypair() -> tuple[str, str]:
    """Return (private_hex, public_hex) for a fresh Ed25519 owner signing key.

    Both halves are the raw 32-byte forms, hex-encoded. The private half is stored
    in the OS keychain (``Store.store_signing_key``); the public half rides the
    invite link fragment and is registered with the server for UI/audit only."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )

    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_raw.hex(), pub_raw.hex()


def _reject_weak_owner_key(key_hex: str) -> str:
    """An owner signing key must be a real 32-byte Ed25519 key. Refuse anything that
    is not 64 hex chars or is the all-zero (trivially forgeable) key."""
    cleaned = (key_hex or "").strip().lower()
    if not _HEX64.match(cleaned):
        raise VerificationError(
            "Owner signing key is not a 64-hex Ed25519 key — refusing to verify")
    if cleaned == "0" * 64:
        raise VerificationError(
            "Owner signing key is the all-zero (forgeable) key — refusing to verify")
    return cleaned


def key_fingerprint(public_hex: str) -> str:
    """Short human-comparable fingerprint of an owner PUBLIC key, e.g. ``a1b2 c3d4
    e5f6 0718`` — printed after a successful verify so a human MAY confirm it against
    an independent utterance from the keyholder (cheap TOFU-lite against a partly
    compromised link channel). Not itself a trust boundary."""
    h = normalize_digest(public_hex) or (public_hex or "").strip().lower()
    body = h[:16]
    return " ".join(body[i:i + 4] for i in range(0, len(body), 4))


# -- the invitation intent: build, validate, digest ------------------------------

def token_commitment(token: str) -> str:
    """sha256(token) as bare 64-hex. We commit to the token rather than embedding it
    so the signed intent leaks nothing extra, while still binding a signature to
    exactly ONE invite link (RFC 0003 [H8] — closes signed-intent replay across an
    owner's links)."""
    return sha256_hex(token.encode("utf-8"))


def build_intent(
    *, project_id: str, token: str, application_digest: str,
    public_context_digest: str, context_epoch: int, min_contributors: int,
    expires_at: str,
) -> dict:
    """Construct the canonical invitation intent the owner signs. Digests are
    normalized to bare lowercase 64-hex; ints are coerced; the ``kind`` tag and the
    token commitment are filled in. The result is validated before return, so a
    malformed field is caught at mint time, not at a contributor's machine."""
    intent = {
        "kind": INVITE_KIND,
        "project_id": str(project_id),
        "token_commitment": token_commitment(token),
        "application_digest": normalize_digest(application_digest),
        "public_context_digest": normalize_digest(public_context_digest),
        "context_epoch": int(context_epoch),
        "min_contributors": int(min_contributors),
        "expires_at": str(expires_at),
    }
    validate_intent_shape(intent)
    return intent


def validate_intent_shape(intent: dict) -> None:
    """Enforce the [H10] type discipline BEFORE hashing/verifying. Rejects a wrong
    key set, wrong types, non-64-hex digests, a bad ``kind`` tag, or a non-UTC
    expiry. Fail-closed: any deviation raises VerificationError."""
    if not isinstance(intent, dict):
        raise VerificationError("Invitation intent is not an object")
    keys = set(intent.keys())
    if keys != set(INTENT_FIELDS):
        raise VerificationError(
            f"Invitation intent field set is wrong: {sorted(keys)} != {sorted(INTENT_FIELDS)}")
    if intent["kind"] != INVITE_KIND:
        raise VerificationError(
            f"Invitation intent kind is not {INVITE_KIND!r} (got {intent['kind']!r}) "
            "— refusing to treat it as a blind invitation")
    if not isinstance(intent["project_id"], str) or not intent["project_id"]:
        raise VerificationError("Invitation intent project_id must be a non-empty string")
    for field in ("token_commitment", "application_digest", "public_context_digest"):
        val = intent[field]
        if not isinstance(val, str) or not _HEX64.match(val):
            raise VerificationError(f"Invitation intent {field} must be lowercase 64-hex")
    # bool is an int subclass in Python — reject it explicitly so True/False can't
    # masquerade as a count/epoch.
    for field in ("context_epoch", "min_contributors"):
        val = intent[field]
        if isinstance(val, bool) or not isinstance(val, int):
            raise VerificationError(f"Invitation intent {field} must be an integer")
    if not isinstance(intent["expires_at"], str) or not _ISO_Z.match(intent["expires_at"]):
        raise VerificationError(
            "Invitation intent expires_at must be strict UTC ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)")


def invitation_digest(intent: dict) -> str:
    """Bare 64-hex sha256 over the canonical JSON of a (validated) intent — the
    message that is Ed25519-signed. Mirrors the bundle convention of signing the
    bare 64-hex string, but the bytes hashed here always include the ``kind`` tag."""
    validate_intent_shape(intent)
    return sha256_hex(canonical_json(intent))


# -- sign (owner) / verify (contributor) -----------------------------------------

def owner_sign(private_hex: str, intent: dict) -> str:
    """Sign an invitation intent with the owner's Ed25519 private key. Returns the
    hex signature over ``invitation_digest(intent)`` (the bare 64-hex string)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv_hex = _reject_weak_owner_key(private_hex)
    message = invitation_digest(intent).encode("utf-8")
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv.sign(message).hex()


def verify_invitation(public_hex: str, intent: dict, signature_hex: str) -> bool:
    """Verify that ``signature_hex`` is a valid Ed25519 signature by ``public_hex``
    over ``intent``. Returns True only on success; raises VerificationError if the
    key is weak, the signature is missing/malformed/forged, or the intent is
    malformed. There is NO 'no key → False' path — callers FAIL CLOSED.

    The intent passed here is the SERVER-ECHOED ``signed_intent`` verbatim; verifying
    over its exact canonical bytes means any server tampering (a changed digest, an
    added field) makes the signature fail. Field-vs-reality checks are separate
    (``check_intent_matches_link``)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pub_hex = _reject_weak_owner_key(public_hex)
    if not signature_hex or not isinstance(signature_hex, str):
        raise VerificationError("Invitation carries no owner signature")
    try:
        signature = bytes.fromhex(signature_hex.strip())
    except ValueError as exc:
        raise VerificationError(f"Owner signature is not valid hex: {exc}")
    message = invitation_digest(intent).encode("utf-8")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        pub.verify(signature, message)
    except Exception as exc:
        raise VerificationError(
            "This invite is not genuinely from the keyholder — the owner signature "
            f"does not verify. Do not trust this link. ({exc})")
    return True


def check_intent_matches_link(
    intent: dict, *, token: str, now: datetime | None = None,
    skew_seconds: int = 300, expected_project_id: str | None = None,
    expected_application_digest: str | None = None,
) -> None:
    """After the signature verifies, confirm the (genuinely owner-signed) intent is
    for THIS link, project, application, right now — none of these inputs come from a
    bare server field:

    - ``token_commitment`` == sha256(token from the link)  [binds one link, [H8]]
    - ``expires_at`` is in the future against the LOCAL clock (do not trust the
      server to 404 an expired token) [H9-expiry]
    - ``project_id`` == the id the CLI will upload to, when the caller pins one
    - ``application_digest`` == the bundle the CLI is about to encode with, when the
      caller pins one (so a server can't swap in a different, though platform-signed,
      application than the keyholder authorized)

    Fail-closed: any mismatch raises VerificationError."""
    validate_intent_shape(intent)
    if intent["token_commitment"] != token_commitment(token):
        raise VerificationError(
            "Owner signature is for a different invite link (token commitment "
            "mismatch) — refusing to encrypt.")
    now = now or datetime.now(timezone.utc)
    expires = datetime.strptime(intent["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)
    if now.timestamp() > expires.timestamp() + skew_seconds:
        raise VerificationError(
            f"This signed invitation expired at {intent['expires_at']} — refusing to "
            "encrypt (checked against the local clock, not the server).")
    if expected_project_id is not None and str(expected_project_id) != intent["project_id"]:
        raise VerificationError(
            f"Signed invitation is for project {intent['project_id']}, not "
            f"{expected_project_id} — refusing to encrypt.")
    if expected_application_digest is not None and not digests_match(
            expected_application_digest, intent["application_digest"]):
        raise VerificationError(
            "Signed invitation authorizes a different application than the one the "
            "server served — refusing to encrypt.")


# -- invite link ⟷ owner key (URL fragment) --------------------------------------

def encode_owner_key_fragment(public_hex: str) -> str:
    """Owner PUBLIC key → the ``#k=`` fragment value (unpadded base64url of the raw
    32 bytes) that rides the invite link."""
    pub_hex = _reject_weak_owner_key(public_hex)
    return base64.urlsafe_b64encode(bytes.fromhex(pub_hex)).decode("ascii").rstrip("=")


def decode_owner_key_fragment(fragment_value: str) -> str:
    """The ``#k=`` fragment value → owner PUBLIC key as 64-hex. Raises if it is not a
    32-byte key."""
    v = (fragment_value or "").strip()
    if not v:
        raise VerificationError("Empty owner-key fragment")
    pad = "=" * (-len(v) % 4)
    try:
        raw = base64.urlsafe_b64decode(v + pad)
    except Exception as exc:
        raise VerificationError(f"Owner-key fragment is not valid base64url: {exc}")
    if len(raw) != 32:
        raise VerificationError(
            f"Owner-key fragment decodes to {len(raw)} bytes, expected a 32-byte Ed25519 key")
    return raw.hex()


def build_invite_link(base_link: str, public_hex: str) -> str:
    """Append the owner key to a bare ``…/c/<token>`` link as a ``#k=`` fragment.
    The owner's CLI emits ONLY this fragmented form (RFC 0003 [H4]) so an unsigned
    link is never accidentally distributed."""
    base = (base_link or "").split("#", 1)[0]
    return f"{base}#k={encode_owner_key_fragment(public_hex)}"


def link_token(link: str) -> str:
    """Extract the bearer token from an invite link. Strips a trailing slash, the
    ``#k=`` fragment, and any ``?query`` — the token is the last path segment.
    (Supersedes contributions._invite_token, which did not strip ``#``.)"""
    without_fragment = (link or "").split("#", 1)[0]
    return without_fragment.rstrip("/").split("/")[-1].split("?")[0]


def link_owner_key(link: str) -> str | None:
    """Extract the owner PUBLIC key (64-hex) from an invite link's ``#k=`` fragment,
    or None when the link carries no fragment (a legacy/unsigned link). This value —
    NOT any server response — decides whether verification is MANDATORY (RFC 0003
    [H11]/[H1]), so it is read from the link string before any network call."""
    if "#" not in (link or ""):
        return None
    fragment = link.split("#", 1)[1]
    for part in fragment.split("&"):
        if part.startswith("k="):
            return decode_owner_key_fragment(part[2:])
    return None


def expiry_iso(expires: str = "7d", *, now: datetime | None = None) -> str:
    """Turn a duration (``7d`` / ``48h`` / ``30m`` / bare-number-days) into a strict
    UTC ISO-8601 second-precision timestamp for the signed intent. Capped at the
    7-day server maximum; the owner signs this exact string and the contributor
    checks it against its OWN clock (RFC 0003 [H9-expiry])."""
    now = now or datetime.now(timezone.utc)
    m = re.match(r"^(\d+)\s*([dhm]?)$", (expires or "7d").strip(), re.I)
    amount, unit = (int(m.group(1)), m.group(2).lower()) if m else (7, "d")
    delta = {"h": timedelta(hours=amount), "m": timedelta(minutes=amount)}.get(
        unit, timedelta(days=amount))
    delta = min(delta, timedelta(days=7))
    return (now + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_token() -> str:
    """A fresh high-entropy bearer token (matches the server's urlsafe_base64(24)
    entropy). Generated owner-side so the owner can commit to and sign it in one
    step at mint time."""
    return secrets.token_urlsafe(24)
