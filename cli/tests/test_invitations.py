"""Signed invitations (RFC 0003) — the keyholder-side trust anchor.

These are the crypto-core unit tests: canonical intent, domain separation, sign /
verify (fail-closed), the link-fragment carrier, and the field-vs-link checks. The
adversarial cases here are the unit-layer twins of the red-team findings that shaped
RFC 0003 (downgrade / substitution / replay / domain confusion)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from blind.errors import VerificationError
from blind.hashing import sha256_hex
from blind.invitations import (
    INVITE_KIND,
    build_intent,
    build_invite_link,
    check_intent_matches_link,
    decode_owner_key_fragment,
    encode_owner_key_fragment,
    generate_owner_keypair,
    invitation_digest,
    key_fingerprint,
    link_owner_key,
    link_token,
    new_token,
    owner_sign,
    validate_intent_shape,
    verify_invitation,
)

TOKEN = "test-invitation-token"
FUTURE = "2030-01-01T00:00:00Z"
NOW = datetime(2026, 7, 12, tzinfo=timezone.utc)


def _intent(token=TOKEN, **over):
    base = dict(
        project_id="proj_1",
        token=token,
        application_digest="ab" * 32,
        public_context_digest="cd" * 32,
        context_epoch=1,
        min_contributors=20,
        expires_at=FUTURE,
    )
    base.update(over)
    return build_intent(**base)


# -- keypair ----------------------------------------------------------------------

def test_keypair_is_two_distinct_64hex_keys():
    priv, pub = generate_owner_keypair()
    assert len(priv) == 64 and len(pub) == 64
    assert all(c in "0123456789abcdef" for c in priv + pub)
    priv2, pub2 = generate_owner_keypair()
    assert priv != priv2 and pub != pub2


# -- intent build + canonicalization ---------------------------------------------

def test_build_intent_normalizes_and_commits_token():
    intent = _intent(application_digest="sha256:" + "AB" * 32)
    assert intent["kind"] == INVITE_KIND
    assert intent["application_digest"] == "ab" * 32  # normalized to bare lower hex
    assert intent["token_commitment"] == sha256_hex(TOKEN.encode())
    assert intent["min_contributors"] == 20 and isinstance(intent["min_contributors"], int)


def test_invitation_digest_is_deterministic_and_field_sensitive():
    d1 = invitation_digest(_intent())
    d2 = invitation_digest(_intent())
    assert d1 == d2 and len(d1) == 64
    assert invitation_digest(_intent(public_context_digest="ef" * 32)) != d1
    assert invitation_digest(_intent(context_epoch=2)) != d1
    assert invitation_digest(_intent(token="other-token")) != d1


def test_domain_separation_kind_is_inside_the_signed_digest():
    # The kind tag is part of the signed digest, so a genuine owner signature over an
    # invitation cannot be replayed against an intent whose kind was changed, and an
    # off-kind object is refused outright rather than hashed like a bare digest.
    priv, pub = generate_owner_keypair()
    intent = _intent()
    sig = owner_sign(priv, intent)
    with pytest.raises(VerificationError):
        verify_invitation(pub, dict(intent, kind="blind-bundle-v1"), sig)
    with pytest.raises(VerificationError):
        invitation_digest(dict(intent, kind="blind-bundle-v1"))


# -- sign / verify (fail-closed) --------------------------------------------------

def test_sign_then_verify_roundtrip():
    priv, pub = generate_owner_keypair()
    intent = _intent()
    sig = owner_sign(priv, intent)
    assert verify_invitation(pub, intent, sig) is True


def test_verify_rejects_forged_signature_under_wrong_key():
    priv, _pub = generate_owner_keypair()
    _priv2, attacker_pub = generate_owner_keypair()
    intent = _intent()
    sig = owner_sign(priv, intent)
    # The server serves its OWN key + the owner's-shaped signature: must not verify.
    with pytest.raises(VerificationError):
        verify_invitation(attacker_pub, intent, sig)


def test_verify_rejects_tampered_intent():
    priv, pub = generate_owner_keypair()
    intent = _intent()
    sig = owner_sign(priv, intent)
    substituted = dict(intent, public_context_digest="ef" * 32)  # server swaps the digest
    with pytest.raises(VerificationError):
        verify_invitation(pub, substituted, sig)


def test_verify_rejects_missing_or_malformed_signature():
    _priv, pub = generate_owner_keypair()
    intent = _intent()
    with pytest.raises(VerificationError):
        verify_invitation(pub, intent, "")
    with pytest.raises(VerificationError):
        verify_invitation(pub, intent, "not-hex-zz")


def test_verify_rejects_weak_all_zero_key():
    intent = _intent()
    with pytest.raises(VerificationError):
        owner_sign("0" * 64, intent)
    with pytest.raises(VerificationError):
        verify_invitation("0" * 64, intent, "ab" * 64)


# -- field-vs-link checks (after the signature verifies) --------------------------

def test_check_intent_matches_link_happy_path():
    check_intent_matches_link(_intent(), token=TOKEN, now=NOW, expected_project_id="proj_1")


def test_check_rejects_signature_for_a_different_link():
    # Owner-signed intent for TOKEN, presented under a different token (server remap).
    intent = _intent(token="the-real-token")
    with pytest.raises(VerificationError):
        check_intent_matches_link(intent, token="a-different-token", now=NOW)


def test_check_enforces_expiry_against_local_clock():
    intent = _intent(expires_at="2026-01-01T00:00:00Z")  # already past at NOW
    with pytest.raises(VerificationError):
        check_intent_matches_link(intent, token=TOKEN, now=NOW)


def test_check_rejects_wrong_project():
    with pytest.raises(VerificationError):
        check_intent_matches_link(_intent(), token=TOKEN, now=NOW, expected_project_id="proj_9")


def test_check_rejects_wrong_application():
    intent = _intent()  # application_digest == "ab" * 32
    # matching digest (prefixed or bare) passes
    check_intent_matches_link(intent, token=TOKEN, now=NOW,
                              expected_application_digest="sha256:" + "ab" * 32)
    with pytest.raises(VerificationError):
        check_intent_matches_link(intent, token=TOKEN, now=NOW,
                                  expected_application_digest="cd" * 32)


# -- shape validation -------------------------------------------------------------

def test_validate_intent_shape_rejects_bad_inputs():
    good = _intent()
    validate_intent_shape(good)  # no raise
    with pytest.raises(VerificationError):
        validate_intent_shape(dict(good, extra="x"))  # wrong field set
    with pytest.raises(VerificationError):
        validate_intent_shape({**good, "kind": "nope"})
    with pytest.raises(VerificationError):
        validate_intent_shape({**good, "public_context_digest": "sha256:" + "ab" * 32})  # prefixed, not bare
    with pytest.raises(VerificationError):
        validate_intent_shape({**good, "min_contributors": True})  # bool is not an int here
    with pytest.raises(VerificationError):
        validate_intent_shape({**good, "expires_at": "2030-01-01"})  # not strict UTC ISO


# -- link fragment carrier --------------------------------------------------------

def test_fragment_roundtrip():
    _priv, pub = generate_owner_keypair()
    frag = encode_owner_key_fragment(pub)
    assert "=" not in frag  # unpadded base64url
    assert decode_owner_key_fragment(frag) == pub


def test_fragment_rejects_wrong_length_and_garbage():
    with pytest.raises(VerificationError):
        decode_owner_key_fragment("AAAA")  # decodes to 3 bytes, not a 32-byte key
    with pytest.raises(VerificationError):
        decode_owner_key_fragment("!!!not-base64!!!")
    with pytest.raises(VerificationError):
        decode_owner_key_fragment("")


def test_link_helpers_parse_token_and_key():
    _priv, pub = generate_owner_keypair()
    bare = "https://blindmachine.org/c/tok-XYZ"
    signed = build_invite_link(bare, pub)
    assert signed.startswith(bare + "#k=")
    # token survives the fragment, a trailing slash, and a query
    assert link_token(signed) == "tok-XYZ"
    assert link_token(bare + "/") == "tok-XYZ"
    assert link_token(bare + "?x=1#k=abc") == "tok-XYZ"
    # owner key comes ONLY from the fragment; a bare link has none
    assert link_owner_key(signed) == pub
    assert link_owner_key(bare) is None
    # host-less forms: `blind contribute` accepts just the token/hash (no scheme/host),
    # with the #k= signing fragment optional
    fragment = signed.split("#", 1)[1]                     # "k=<b64url-owner-pub>"
    assert link_token("tok-XYZ") == "tok-XYZ"
    assert link_token(f"tok-XYZ#{fragment}") == "tok-XYZ"
    assert link_owner_key(f"tok-XYZ#{fragment}") == pub    # bare token keeps the signing key
    assert link_owner_key("tok-XYZ") is None               # bare token alone → unsigned


def test_new_token_has_entropy():
    t1, t2 = new_token(), new_token()
    assert t1 != t2 and len(t1) >= 24


def test_key_fingerprint_is_grouped_hex():
    _priv, pub = generate_owner_keypair()
    fp = key_fingerprint(pub)
    assert fp.replace(" ", "") == pub[:16]


# -- the whole client-side gate, end to end (no network) --------------------------

def test_full_verify_gate_accepts_genuine_and_refuses_downgrade():
    priv, pub = generate_owner_keypair()
    token = new_token()
    intent = _intent(token=token)
    sig = owner_sign(priv, intent)

    # genuine: verify under the fragment key, then field-checks pass
    assert verify_invitation(pub, intent, sig) is True
    check_intent_matches_link(intent, token=token, now=NOW, expected_project_id="proj_1")

    # downgrade attempt: a malicious server drops the signature. The link still
    # carries #k=, so the caller MUST treat "no signature" as refuse — verify raises.
    with pytest.raises(VerificationError):
        verify_invitation(pub, intent, "")
