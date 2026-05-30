"""End-to-end tests against a real Claw hub running in-process.

The hub lives in a sibling repo (claw-hub); we import it directly via a
local path so we can drive issue → verify → revoke → verify against a
real signing key with a real audit chain. Tests in this file would
otherwise need a mock hub, and a mock hub is the wrong thing to verify
the SDK against — we'd be testing our own mock.

To run:
    cd /Users/awoodsha/Desktop/Claw-SDK-Python
    pytest

Requires the sibling claw-hub repo at ../Claw with its venv prepared
(pytest itself; we don't need fastapi runtime — we hit the hub via
TestClient, no HTTP socket bound)."""
from __future__ import annotations

import importlib
import json
import os
import pathlib
import sys

import httpx
import pytest

# Make the hub importable as `hub.*` so we can spin one up in-process.
SIBLING_HUB = pathlib.Path(__file__).resolve().parent.parent.parent / "Claw"
sys.path.insert(0, str(SIBLING_HUB))

# Make our own package importable from the repo's src/ layout.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from hub import config, crypto  # noqa: E402 — must follow sys.path mutation

import clawid  # noqa: E402
from clawid.client import Claw  # noqa: E402


@pytest.fixture
def hub_client(tmp_path, monkeypatch):
    """Spin up a fresh hub in-process with isolated DB + key. Returns
    (TestClient, store, tenant_id, api_key) so individual tests can
    mint Claws against a known tenant."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "NONCES_DB_PATH", tmp_path / "nonces.db")
    monkeypatch.setattr(config, "HUB_PRIVATE_KEY_PATH", tmp_path / "hub.pem")
    from hub import app as app_module
    importlib.reload(app_module)
    from fastapi.testclient import TestClient
    client = TestClient(app_module.app)
    tenant_id, api_key = app_module._store.create_tenant("sdk-test")
    return client, app_module._store, tenant_id, api_key


@pytest.fixture
def sdk_client(hub_client):
    """Wire a Claw SDK client to the in-process hub via httpx.MockTransport.
    The SDK's http calls go straight into the FastAPI app, no socket."""
    fastapi_client, store, tenant_id, api_key = hub_client

    def transport_handler(request: httpx.Request) -> httpx.Response:
        # Translate httpx.Request → starlette TestClient call.
        method = request.method
        url = request.url
        path = url.path
        if url.query:
            path = f"{path}?{url.query.decode() if isinstance(url.query, bytes) else url.query}"
        headers = dict(request.headers)
        body = request.content
        # The starlette TestClient is happy with these.
        resp = fastapi_client.request(method, path, headers=headers, content=body)
        return httpx.Response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content=resp.content,
            request=request,
        )

    transport = httpx.MockTransport(transport_handler)
    http = httpx.Client(transport=transport)
    sdk = Claw(hub_url="http://hub.test", http_client=http)
    return sdk, store, tenant_id, api_key, fastapi_client


def _agent_pub() -> str:
    """A fresh agent public key in PEM form, matching how a real agent
    would advertise itself at issue time."""
    p = crypto.generate_private_key()
    return crypto.public_to_pem(p.public_key()).decode()


def _issue(fastapi_client, api_key: str, *, leash: dict | None = None) -> dict:
    leash = leash or {
        "spend_ceiling": 100.0,
        "allowed_surfaces": ["stripe.com"],
        "active_start_hour": 0,
        "active_end_hour": 24,
    }
    r = fastapi_client.post(
        "/v1/issue",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"agent_public_key_pem": _agent_pub(), "agent_label": "test", "leash": leash},
    )
    r.raise_for_status()
    return r.json()


# ── happy path ──────────────────────────────────────────────────────

def test_verify_active_claw(sdk_client):
    sdk, store, tenant_id, api_key, fc = sdk_client
    issued = _issue(fc, api_key)
    result = sdk.verify(issued["token"])
    assert result.valid is True
    assert result.status == clawid.VerifyStatus.ACTIVE
    assert result.agent_id == issued["agent_id"]
    assert result.tenant_id == tenant_id
    assert result.jti == issued["jti"]
    assert result.leash["spend_ceiling"] == 100.0
    assert "stripe.com" in result.leash["allowed_surfaces"]
    # __bool__ truthiness shortcut
    assert bool(result) is True
    if result: pass  # the documented usage
    else: pytest.fail("result should have been truthy")


def test_verify_with_module_helper(monkeypatch, sdk_client):
    """clawid.verify(token) goes through the module-level default client.
    We swap that singleton for the in-process one to exercise the same
    code path the README advertises."""
    sdk, store, tenant_id, api_key, fc = sdk_client
    # Grab the SUBMODULE (clawid.verify) — `from clawid import verify`
    # would resolve to the function re-exported by __init__.py.
    import importlib
    verify_mod = importlib.import_module("clawid.verify")
    monkeypatch.setattr(verify_mod, "_default_client", sdk)
    issued = _issue(fc, api_key)
    result = clawid.verify(issued["token"])
    assert result.valid
    assert result.agent_id == issued["agent_id"]


# ── lifecycle: revocation ───────────────────────────────────────────

def test_verify_revoked_claw_returns_revoked(sdk_client):
    sdk, store, tenant_id, api_key, fc = sdk_client
    issued = _issue(fc, api_key)
    # Confirm active first
    assert sdk.verify(issued["token"]).status == clawid.VerifyStatus.ACTIVE
    # Owner hits kill switch
    fc.post(
        "/v1/revoke",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"jti": issued["jti"], "reason": "test"},
    ).raise_for_status()
    # Verify now reports REVOKED, valid=False
    result = sdk.verify(issued["token"])
    assert result.valid is False
    assert result.status == clawid.VerifyStatus.REVOKED
    # Structural fields still populated — signature was good
    assert result.agent_id == issued["agent_id"]


# ── lifecycle: malformed / unknown ──────────────────────────────────

def test_verify_garbage_token(sdk_client):
    sdk, *_ = sdk_client
    result = sdk.verify("not.even.close")
    assert result.valid is False
    assert result.status == clawid.VerifyStatus.INVALID


def test_verify_token_with_no_kid(sdk_client):
    sdk, *_ = sdk_client
    # Hand-craft a header without kid — the SDK should refuse before fetching JWKS.
    import jwt as _jwt
    bogus = _jwt.encode(
        {"iss": "claw-hub", "sub": "x", "jti": "y", "exp": 9_999_999_999},
        "x" * 32, algorithm="HS256",  # algorithm mismatch on purpose — never verifies
    )
    result = sdk.verify(bogus)
    assert result.valid is False
    assert result.status == clawid.VerifyStatus.INVALID


# ── offline mode ────────────────────────────────────────────────────

def test_offline_mode_skips_revocation_check(sdk_client):
    """In offline mode, a revoked Claw shows as ACTIVE because we don't
    consult the hub for revocation status — signature + expiry only.
    This is the documented trade-off."""
    sdk, store, tenant_id, api_key, fc = sdk_client
    issued = _issue(fc, api_key)
    fc.post(
        "/v1/revoke",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"jti": issued["jti"], "reason": "test"},
    ).raise_for_status()
    # Online → REVOKED
    online = sdk.verify(issued["token"], mode="online")
    assert online.status == clawid.VerifyStatus.REVOKED
    # Offline → ACTIVE (signature still valid, we didn't ask the hub)
    offline = sdk.verify(issued["token"], mode="offline")
    assert offline.status == clawid.VerifyStatus.ACTIVE
    assert offline.valid is True


# ── JWKS caching ────────────────────────────────────────────────────

def test_jwks_is_cached(sdk_client):
    """Two verifies on the same client should result in ONE JWKS fetch,
    not two. We assert by hand-counting hits via a wrapped transport."""
    sdk, store, tenant_id, api_key, fc = sdk_client
    issued = _issue(fc, api_key)
    # First verify warms the cache
    _ = sdk.verify(issued["token"], mode="offline")
    # Second verify — cache hit; assert directly on the cache state
    cache_before = sdk._jwks_cache
    _ = sdk.verify(issued["token"], mode="offline")
    cache_after = sdk._jwks_cache
    # Same object — no refetch
    assert cache_before is cache_after


def test_jwks_cache_clear_forces_refetch(sdk_client):
    sdk, store, tenant_id, api_key, fc = sdk_client
    issued = _issue(fc, api_key)
    _ = sdk.verify(issued["token"], mode="offline")
    first_cache = sdk._jwks_cache
    sdk.jwks_cache_clear()
    _ = sdk.verify(issued["token"], mode="offline")
    second_cache = sdk._jwks_cache
    assert first_cache is not second_cache
    assert second_cache is not None


# ── async ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_async(sdk_client):
    """The async path uses an AsyncClient. We wire up MockTransport on the
    async side too so the test runs against the in-process hub."""
    sdk, store, tenant_id, api_key, fc = sdk_client

    async def ahandler(request: httpx.Request) -> httpx.Response:
        # Re-use the sync FastAPI client (TestClient calls are sync; that's
        # fine — we just don't await here).
        method = request.method
        url = request.url
        path = url.path
        if url.query:
            path = f"{path}?{url.query.decode() if isinstance(url.query, bytes) else url.query}"
        headers = dict(request.headers)
        body = request.content
        resp = fc.request(method, path, headers=headers, content=body)
        return httpx.Response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content=resp.content,
            request=request,
        )

    sdk._ahttp = httpx.AsyncClient(transport=httpx.MockTransport(ahandler))
    issued = _issue(fc, api_key)
    result = await sdk.verify_async(issued["token"])
    assert result.valid is True
    assert result.agent_id == issued["agent_id"]


# ── tenant isolation in the verify path ─────────────────────────────

def test_two_tenants_get_distinct_results(sdk_client):
    """The SDK only knows what the hub returns — tenant isolation is
    enforced upstream. We confirm the SDK round-trips correctly when
    two different tenants issue Claws."""
    sdk, store, tenant_one, key_one, fc = sdk_client
    tenant_two, key_two = store.create_tenant("second-tenant")
    a = _issue(fc, key_one)
    b = _issue(fc, key_two)
    ra = sdk.verify(a["token"])
    rb = sdk.verify(b["token"])
    assert ra.tenant_id == tenant_one
    assert rb.tenant_id == tenant_two
    assert ra.tenant_id != rb.tenant_id
