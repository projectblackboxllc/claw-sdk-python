"""ClawID — the client class and result types.

`Claw` is the configurable client object. Use it when you need to point
the SDK at a specific hub (self-hosted, dev, staging) or tune the JWKS
cache TTL. For the common case — verifying against the production
ClawID hub — the module-level `verify(token)` is shorter.

Two verification modes:

  • online (default) — validates the JWS signature offline using cached
    JWKS + makes a `POST /v1/verify` round-trip to the hub to confirm
    the Claw hasn't been revoked. One network call per verify, ~50ms
    typical. This is the right default — it gives you live revocation.

  • offline — JWS signature + expiry only, no revocation check. Zero
    network calls after the JWKS cache is warm. Use when latency
    matters more than seeing revokes immediately. Revocation is NOT
    checked in offline mode — you won't see a revoke until you either
    fall through to online mode for a call, or poll `/v1/verify` for
    the token's `jti` out of band on a schedule you control.

The SDK NEVER sends a Claw it received to anywhere except the configured
hub. The hub's signing key is in cloud KMS; ours is a verify-only client.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
import jwt
from jwt.algorithms import OKPAlgorithm

DEFAULT_HUB_URL = "https://api.holdtheleash.id"
DEFAULT_JWKS_TTL = 300  # 5 minutes; tradeoff between rotation responsiveness and traffic
DEFAULT_TIMEOUT = 5.0   # seconds


class ClawError(Exception):
    """Raised for unrecoverable SDK failures (network down with no cache,
    malformed JWKS response, etc.). Verification failures (bad signature,
    revoked, expired) do NOT raise — they return a VerifyResult with
    `valid=False` and a status that describes what happened. You only
    catch ClawError for infra problems."""


class VerifyStatus(str, Enum):
    """Why a verify returned the result it did.

    ACTIVE     — Claw is valid and live (online mode also confirmed not revoked)
    REVOKED    — owner hit the kill switch; the hub denies all future check-ins
    EXPIRED    — the Claw's `exp` claim is in the past; mint a fresh one
    INVALID    — signature didn't verify, malformed JWT, unknown issuer, etc.
    UNKNOWN    — hub returned a status the SDK version doesn't recognize.
                 Treat as INVALID for safety.
    """
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass
class VerifyResult:
    """Structured result of a `Claw.verify()` call.

    Always populated:
      valid      — True iff the Claw is currently usable (signature good
                   AND not expired AND, in online mode, not revoked).
      status     — VerifyStatus enum. Always set, even when `valid=True`.
      reason     — Human-readable reason; useful for logs.

    Populated when the JWS itself was decodable (so even on REVOKED /
    EXPIRED — the structural data is still trustworthy because the
    signature was good):
      jti, agent_id, tenant_id, leash, agent_pubkey_pem, issued_at, expires_at.

    The leash dict has these keys (any may be absent):
      spend_ceiling, allowed_surfaces, active_start_hour, active_end_hour,
      escalate_over, auto_revoke_off_leash, hold_actions.
    """
    valid: bool
    status: VerifyStatus
    reason: Optional[str] = None
    jti: Optional[str] = None
    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    leash: Optional[dict] = None
    agent_pubkey_pem: Optional[str] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    # Raw decoded payload — included so callers can inspect custom claims
    # in future Claw versions without an SDK upgrade.
    payload: Optional[dict] = field(default=None, repr=False)

    def __bool__(self) -> bool:
        """`if result:` works as a shorthand for `if result.valid:`."""
        return self.valid


EVENT_URI_BASE = "https://holdtheleash.id/events/"
SECURITY_EVENT_TYP = "secevent+jwt"
# Tolerated clock skew for a notice's `iat` landing slightly in the future.
_EVENT_CLOCK_SKEW = 300


@dataclass
class EventResult:
    """Result of `Claw.verify_event()` — one push notice from the hub.

      valid       True iff the signature checks out against the hub's
                  published key, it's a ClawID notice, and (if asked)
                  it's addressed to you and fresh enough.
      reason      Why it was refused, when valid is False.
      event_type  "claw.revoked" | "hold.created" | "hold.resolved" | "ping".
      event_id    Unique per notice. The hub retries, so the same notice
                  can arrive more than once — dedupe on this.
      data        The event body (e.g. claw_jti, agent_id, revoked_at).
      issued_at   When the hub signed it (epoch seconds).
      audience    The tenant_id it was addressed to.
    """
    valid: bool
    reason: Optional[str] = None
    event_type: Optional[str] = None
    event_id: Optional[str] = None
    data: Optional[dict] = None
    issued_at: Optional[int] = None
    audience: Optional[str] = None

    def __bool__(self) -> bool:
        return self.valid


@dataclass
class _JwksEntry:
    """Internal — one cached JWKS response with expiry timestamp."""
    keys: list[dict]
    fetched_at: float

    @property
    def expired(self) -> bool:
        return time.time() - self.fetched_at > self.ttl

    ttl: float = DEFAULT_JWKS_TTL


class Claw:
    """The verify-only client.

    Configure once at process startup; reuse for every verify. Thread-safe
    when the underlying httpx Client / AsyncClient is reused; the JWKS
    cache is read-mostly so contention is negligible.

    >>> client = clawid_sdk.Claw(hub_url="https://api.holdtheleash.id")
    >>> result = client.verify(token)
    >>> if result.valid:
    ...     do_work_for(result.agent_id, result.tenant_id)

    """

    def __init__(
        self,
        hub_url: str = DEFAULT_HUB_URL,
        *,
        jwks_ttl: int = DEFAULT_JWKS_TTL,
        timeout: float = DEFAULT_TIMEOUT,
        http_client: Optional[httpx.Client] = None,
        async_http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.hub_url = hub_url.rstrip("/")
        self.jwks_ttl = jwks_ttl
        self.timeout = timeout
        self._http = http_client
        self._ahttp = async_http_client
        self._jwks_cache: Optional[_JwksEntry] = None

    # ── public surface ────────────────────────────────────────────────

    def verify(self, token: str, *, mode: str = "online") -> VerifyResult:
        """Verify a Claw. Returns a VerifyResult; never raises on verify
        failures. Raises `ClawError` only on infrastructure problems (hub
        unreachable when mode='online' and JWKS not cached, etc.).

        `mode`: "online" (default) checks signature + expiry + revocation.
                "offline" checks signature + expiry only; no network call
                after JWKS is cached.
        """
        # 1. JWS signature + expiry — same path in both modes
        payload = self._verify_jws(token)
        if not payload.ok:
            return payload.result

        # 2. Live revocation check — only in online mode
        if mode == "online":
            return self._check_revocation(token, payload.payload)
        elif mode == "offline":
            return self._success_result(payload.payload, status=VerifyStatus.ACTIVE,
                                        reason="signature + expiry valid (offline mode)")
        else:
            raise ClawError(f"unknown verify mode: {mode!r}")

    async def verify_async(self, token: str, *, mode: str = "online") -> VerifyResult:
        """Async variant. Same semantics as `verify()` — see that docstring."""
        payload = self._verify_jws(token)
        if not payload.ok:
            return payload.result

        if mode == "online":
            return await self._check_revocation_async(token, payload.payload)
        elif mode == "offline":
            return self._success_result(payload.payload, status=VerifyStatus.ACTIVE,
                                        reason="signature + expiry valid (offline mode)")
        else:
            raise ClawError(f"unknown verify mode: {mode!r}")

    def jwks_cache_clear(self) -> None:
        """Force a fresh JWKS fetch on the next verify. Useful when you
        know a key rotation just happened and don't want to wait for the
        TTL to expire."""
        self._jwks_cache = None

    def verify_event(
        self,
        body: str | bytes,
        *,
        audience: Optional[str] = None,
        max_age_seconds: Optional[int] = None,
    ) -> EventResult:
        """Verify a push notice the hub POSTed to your endpoint.

        `body` is the raw request body (a compact JWS, Content-Type
        application/secevent+jwt). Pass `audience=<your tenant_id>` to
        refuse notices addressed to someone else, and `max_age_seconds`
        to refuse old ones. Never raises on a bad notice — check `.valid`.

            result = claw.verify_event(request.body, audience="tnt_…")
            if result and result.event_type == "claw.revoked":
                drop_cached_claw(result.data["claw_jti"])

        The hub retries failed deliveries, so the same notice can arrive
        twice; dedupe on `result.event_id`."""
        token = (body.decode("ascii", "replace") if isinstance(body, bytes) else body or "").strip()
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return EventResult(valid=False, reason="malformed notice")
        if header.get("typ") != SECURITY_EVENT_TYP:
            return EventResult(valid=False, reason="not a ClawID notice (wrong typ)")
        kid = header.get("kid")
        if not kid:
            return EventResult(valid=False, reason="notice missing 'kid' header")

        jwk = self._jwk_for_kid(kid)
        if jwk is None:
            return EventResult(valid=False, reason=f"no key with kid={kid!r} in hub JWKS")
        try:
            public_key = OKPAlgorithm.from_jwk(jwk)
            claims = jwt.decode(
                token, public_key, algorithms=["EdDSA"], issuer="claw-hub",
                audience=audience,
                options={"require": ["iat", "iss", "jti"], "verify_aud": audience is not None},
            )
        except jwt.InvalidAudienceError:
            return EventResult(valid=False, reason="notice is addressed to someone else")
        except jwt.InvalidTokenError as e:
            return EventResult(valid=False, reason=f"invalid notice: {e}")
        except Exception as e:  # noqa: BLE001 — bad key material
            return EventResult(valid=False, reason=f"could not load hub public key: {e}")

        events = claims.get("events")
        if not isinstance(events, dict) or len(events) != 1:
            return EventResult(valid=False, reason="notice must carry exactly one event")
        uri, data = next(iter(events.items()))
        if not uri.startswith(EVENT_URI_BASE) or not isinstance(data, dict):
            return EventResult(valid=False, reason="not a ClawID event")

        now = int(time.time())
        iat = int(claims["iat"])
        if iat > now + _EVENT_CLOCK_SKEW:
            return EventResult(valid=False, reason="notice is dated in the future")
        if max_age_seconds is not None and now - iat > max_age_seconds:
            return EventResult(valid=False, reason="notice is too old")

        return EventResult(
            valid=True,
            event_type=uri[len(EVENT_URI_BASE):],
            event_id=claims["jti"],
            data=data,
            issued_at=iat,
            audience=claims.get("aud"),
        )

    def _jwk_for_kid(self, kid: str) -> Optional[dict]:
        """Find the hub key for `kid`, refetching once if it isn't cached
        (handles a key rotation that landed inside the cache TTL)."""
        jwk = next((k for k in self._fetch_jwks() if k.get("kid") == kid), None)
        if jwk is None:
            self._jwks_cache = None
            jwk = next((k for k in self._fetch_jwks() if k.get("kid") == kid), None)
        return jwk

    # ── internals ─────────────────────────────────────────────────────

    def _http_client(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=self.timeout)
        return self._http

    def _async_http_client(self) -> httpx.AsyncClient:
        if self._ahttp is None:
            self._ahttp = httpx.AsyncClient(timeout=self.timeout)
        return self._ahttp

    def _fetch_jwks(self) -> list[dict]:
        if self._jwks_cache and not self._jwks_cache.expired:
            return self._jwks_cache.keys
        try:
            r = self._http_client().get(f"{self.hub_url}/.well-known/jwks.json")
            r.raise_for_status()
            keys = r.json().get("keys", [])
        except Exception as e:  # noqa: BLE001 — wrap into ClawError
            if self._jwks_cache:
                # Stale cache is better than dead — return what we have
                return self._jwks_cache.keys
            raise ClawError(f"could not fetch JWKS from {self.hub_url}: {e}") from e
        self._jwks_cache = _JwksEntry(keys=keys, fetched_at=time.time(), ttl=self.jwks_ttl)
        return keys

    def _verify_jws(self, token: str) -> "_DecodedOrError":
        """Decode + signature-verify the JWS. Returns the decoded payload
        on success or a wrapped VerifyResult on failure."""
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as e:
            return _DecodedOrError(result=VerifyResult(
                valid=False, status=VerifyStatus.INVALID,
                reason=f"malformed token: {e}",
            ))

        kid = unverified_header.get("kid")
        if not kid:
            return _DecodedOrError(result=VerifyResult(
                valid=False, status=VerifyStatus.INVALID,
                reason="token missing 'kid' header — no way to select a key",
            ))

        # Find the matching JWK
        keys = self._fetch_jwks()
        jwk = next((k for k in keys if k.get("kid") == kid), None)
        if jwk is None:
            # One retry with a forced refresh — handles key rotation
            self._jwks_cache = None
            keys = self._fetch_jwks()
            jwk = next((k for k in keys if k.get("kid") == kid), None)
        if jwk is None:
            return _DecodedOrError(result=VerifyResult(
                valid=False, status=VerifyStatus.INVALID,
                reason=f"no key with kid={kid!r} in hub JWKS",
            ))

        # PyJWT expects the public key in algorithm-specific form; OKPAlgorithm
        # converts the OKP/Ed25519 JWK dict directly.
        try:
            public_key = OKPAlgorithm.from_jwk(jwk)
        except Exception as e:  # noqa: BLE001
            return _DecodedOrError(result=VerifyResult(
                valid=False, status=VerifyStatus.INVALID,
                reason=f"could not load hub public key: {e}",
            ))

        try:
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                issuer="claw-hub",
                options={"require": ["exp", "iss", "sub", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            return _DecodedOrError(result=VerifyResult(
                valid=False, status=VerifyStatus.EXPIRED,
                reason="token expired",
            ))
        except jwt.InvalidTokenError as e:
            return _DecodedOrError(result=VerifyResult(
                valid=False, status=VerifyStatus.INVALID,
                reason=f"invalid token: {e}",
            ))

        return _DecodedOrError(ok=True, payload=payload)

    def _check_revocation(self, token: str, payload: dict) -> VerifyResult:
        """Hit POST /v1/verify for live revocation status."""
        try:
            r = self._http_client().post(f"{self.hub_url}/v1/verify", json={"token": token})
            r.raise_for_status()
            body = r.json()
        except Exception as e:  # noqa: BLE001
            raise ClawError(f"revocation check failed: {e}") from e
        return _result_from_hub_body(body, payload)

    async def _check_revocation_async(self, token: str, payload: dict) -> VerifyResult:
        try:
            r = await self._async_http_client().post(
                f"{self.hub_url}/v1/verify", json={"token": token},
            )
            r.raise_for_status()
            body = r.json()
        except Exception as e:  # noqa: BLE001
            raise ClawError(f"revocation check failed: {e}") from e
        return _result_from_hub_body(body, payload)

    def _success_result(self, payload: dict, *, status: VerifyStatus,
                        reason: Optional[str] = None) -> VerifyResult:
        """Build a VerifyResult from a decoded JWS payload (no hub round-trip)."""
        return VerifyResult(
            valid=(status == VerifyStatus.ACTIVE),
            status=status,
            reason=reason,
            jti=payload.get("jti"),
            agent_id=payload.get("sub"),
            tenant_id=payload.get("tenant"),
            leash=payload.get("leash"),
            agent_pubkey_pem=payload.get("cnf", {}).get("agent_pub"),
            issued_at=payload.get("iat"),
            expires_at=payload.get("exp"),
            payload=payload,
        )


# ── helpers (module-private) ──────────────────────────────────────────

@dataclass
class _DecodedOrError:
    """Two-arm result of _verify_jws — either the decoded payload (ok=True)
    or a pre-built VerifyResult to return verbatim (ok=False)."""
    ok: bool = False
    payload: Optional[dict] = None
    result: Optional[VerifyResult] = None


def _result_from_hub_body(body: dict, payload: dict) -> VerifyResult:
    """Map the hub's /v1/verify response onto our VerifyResult."""
    status_str = (body.get("status") or "unknown").lower()
    try:
        status = VerifyStatus(status_str)
    except ValueError:
        status = VerifyStatus.UNKNOWN
    return VerifyResult(
        valid=bool(body.get("valid")),
        status=status,
        reason=body.get("reason"),
        jti=body.get("jti") or payload.get("jti"),
        agent_id=body.get("agent_id") or payload.get("sub"),
        tenant_id=body.get("tenant_id") or payload.get("tenant"),
        leash=body.get("leash") or payload.get("leash"),
        agent_pubkey_pem=body.get("agent_pubkey_pem")
            or payload.get("cnf", {}).get("agent_pub"),
        issued_at=body.get("issued_at") or payload.get("iat"),
        expires_at=body.get("expires_at") or payload.get("exp"),
        payload=payload,
    )
