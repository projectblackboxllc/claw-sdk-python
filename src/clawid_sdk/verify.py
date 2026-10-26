"""Module-level conveniences — `clawid_sdk.verify(token)`, `clawid_sdk.verify_async(token)`
and `clawid_sdk.verify_event(body)`.

These wrap a process-wide default `Claw` client pointed at the production
hub. Use them for the common case; instantiate `Claw(...)` explicitly
when you need a self-hosted hub URL, a tuned JWKS TTL, or your own
httpx client.
"""
from __future__ import annotations

import os
from typing import Optional

from .client import Claw, EventResult, VerifyResult

_default_client: Optional[Claw] = None


def _client() -> Claw:
    """Lazy singleton. Reads CLAW_HUB_URL from the environment if set;
    otherwise points at the production hub at api.holdtheleash.id."""
    global _default_client
    if _default_client is None:
        hub_url = os.environ.get("CLAW_HUB_URL", "https://api.holdtheleash.id")
        _default_client = Claw(hub_url=hub_url)
    return _default_client


def verify(token: str, *, mode: str = "online") -> VerifyResult:
    """Verify a Claw against the default hub.

    >>> import clawid_sdk
    >>> result = clawid_sdk.verify(token)
    >>> if result.valid:
    ...     print(result.agent_id, "owned by", result.tenant_id)

    See `Claw.verify` for argument and return-value details."""
    return _client().verify(token, mode=mode)


async def verify_async(token: str, *, mode: str = "online") -> VerifyResult:
    """Async equivalent of `verify(token)`."""
    return await _client().verify_async(token, mode=mode)


def verify_event(
    body: str | bytes,
    *,
    audience: Optional[str] = None,
    max_age_seconds: Optional[int] = None,
) -> EventResult:
    """Verify a push notice from the default hub.

    >>> result = clawid_sdk.verify_event(request_body, audience="tnt_...")
    >>> if result and result.event_type == "claw.revoked":
    ...     forget(result.data["claw_jti"])

    See `Claw.verify_event` for details. Dedupe on `result.event_id`."""
    return _client().verify_event(body, audience=audience, max_age_seconds=max_age_seconds)
