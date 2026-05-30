"""Module-level conveniences — `clawid.verify(token)` and `clawid.verify_async(token)`.

These wrap a process-wide default `Claw` client pointed at the production
hub. Use them for the common case; instantiate `Claw(...)` explicitly
when you need a self-hosted hub URL, a tuned JWKS TTL, or your own
httpx client.
"""
from __future__ import annotations

import os
from typing import Optional

from .client import Claw, VerifyResult

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

    >>> import clawid
    >>> result = clawid.verify(token)
    >>> if result.valid:
    ...     print(result.agent_id, "owned by", result.tenant_id)

    See `Claw.verify` for argument and return-value details."""
    return _client().verify(token, mode=mode)


async def verify_async(token: str, *, mode: str = "online") -> VerifyResult:
    """Async equivalent of `verify(token)`."""
    return await _client().verify_async(token, mode=mode)
