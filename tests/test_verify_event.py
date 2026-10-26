"""Tests for `verify_event` — checking a push notice from the hub.

Real Ed25519 signatures in the hub's exact notice format (RFC 8417
Security Event Token, typ=secevent+jwt); only the JWKS fetch is mocked,
via an httpx MockTransport. No live hub needed."""
from __future__ import annotations

import base64
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clawid_sdk import Claw, EventResult

URI = "https://holdtheleash.id/events/"


def _key(kid="hub-1"):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid,
           "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    return pem, jwk


def _notice(pem, kid="hub-1", *, event="claw.revoked", data=None, aud="tnt_vendor",
            iat=None, typ="secevent+jwt", events=None, iss="claw-hub"):
    now = int(time.time()) if iat is None else iat
    claims = {"iss": iss, "iat": now, "toe": now, "jti": "evt_" + "a" * 32, "aud": aud,
              "events": events if events is not None else
              {URI + event: data if data is not None else {"claw_jti": "clw_1", "cause": "owner"}}}
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"kid": kid, "typ": typ})


def _claw(*jwks):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/jwks.json"
        return httpx.Response(200, json={"keys": list(jwks)})
    return Claw(hub_url="https://hub.test", http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_valid_notice():
    pem, jwk = _key()
    r = _claw(jwk).verify_event(_notice(pem), audience="tnt_vendor")
    assert isinstance(r, EventResult) and r.valid and bool(r)
    assert r.event_type == "claw.revoked"
    assert r.event_id == "evt_" + "a" * 32
    assert r.data == {"claw_jti": "clw_1", "cause": "owner"}
    assert r.audience == "tnt_vendor"


def test_bytes_body_with_whitespace_is_fine():
    pem, jwk = _key()
    body = (_notice(pem, event="hold.created", data={"hold_id": "hld_1"}) + "\n").encode()
    r = _claw(jwk).verify_event(body)
    assert r.valid and r.event_type == "hold.created" and r.data["hold_id"] == "hld_1"


def test_a_claw_is_not_a_notice():
    pem, jwk = _key()
    claw_token = jwt.encode({"iss": "claw-hub", "sub": "agt_1", "jti": "clw_1",
                             "exp": int(time.time()) + 60}, pem, algorithm="EdDSA",
                            headers={"kid": "hub-1"})
    r = _claw(jwk).verify_event(claw_token)
    assert not r.valid and "wrong typ" in r.reason


def test_forged_notice_signed_by_another_key_is_refused():
    pem, jwk = _key()
    attacker_pem, _ = _key()
    r = _claw(jwk).verify_event(_notice(attacker_pem))
    assert not r.valid and "invalid notice" in r.reason


def test_tampered_payload_is_refused():
    pem, jwk = _key()
    head, payload, sig = _notice(pem).split(".")
    claims = jwt.decode(_notice(pem), options={"verify_signature": False})
    claims["events"][URI + "claw.revoked"]["claw_jti"] = "clw_someone_else"
    import json
    forged_payload = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
    r = _claw(jwk).verify_event(f"{head}.{forged_payload}.{sig}")
    assert not r.valid


def test_wrong_audience_is_refused():
    pem, jwk = _key()
    r = _claw(jwk).verify_event(_notice(pem, aud="tnt_other"), audience="tnt_vendor")
    assert not r.valid and "someone else" in r.reason
    # Without an audience check the same notice verifies (caller's choice).
    assert _claw(jwk).verify_event(_notice(pem, aud="tnt_other")).valid


def test_wrong_issuer_is_refused():
    pem, jwk = _key()
    assert not _claw(jwk).verify_event(_notice(pem, iss="someone-else")).valid


def test_unknown_kid_is_refused_after_one_refresh():
    pem, jwk = _key("rotated-away")
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"keys": [jwk]})
    claw = Claw(hub_url="https://hub.test",
                http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    r = claw.verify_event(_notice(pem, kid="hub-1"))
    assert not r.valid and "no key with kid" in r.reason
    assert len(calls) == 2  # cached fetch + one forced refresh


def test_non_clawid_or_multi_event_payloads_are_refused():
    pem, jwk = _key()
    claw = _claw(jwk)
    assert "not a ClawID event" in claw.verify_event(
        _notice(pem, events={"https://evil.example/events/x": {}})).reason
    assert "exactly one" in claw.verify_event(
        _notice(pem, events={URI + "a": {}, URI + "b": {}})).reason
    assert "exactly one" in claw.verify_event(_notice(pem, events={})).reason


def test_age_limits():
    pem, jwk = _key()
    claw = _claw(jwk)
    old = _notice(pem, iat=int(time.time()) - 3600)
    assert claw.verify_event(old).valid
    assert "too old" in claw.verify_event(old, max_age_seconds=600).reason
    future = _notice(pem, iat=int(time.time()) + 3600)
    assert not claw.verify_event(future).valid


@pytest.mark.parametrize("junk", ["", "not-a-jwt", "a.b", b"\xff\xfe"])
def test_garbage_never_raises(junk):
    pem, jwk = _key()
    r = _claw(jwk).verify_event(junk)
    assert not r.valid and r.reason
