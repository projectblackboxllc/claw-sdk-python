"""ClawID — Agent KYC.

The Python SDK for verifying Claws (the credential autonomous AI agents
carry to prove who they are, what their leash permits, and whether the
owner has revoked them).

    >>> import clawid
    >>> result = clawid.verify(token)
    >>> if result.valid:
    ...     print(result.agent_id, "owned by", result.tenant_id)

Three lines. Free forever for verifiers. No key, no contract.

See https://holdtheleash.id for the product, https://github.com/projectblackboxllc/claw-sdk-python
for the source, and the README for the full API surface.
"""
from __future__ import annotations

from .client import Claw, VerifyResult, VerifyStatus, ClawError
from .verify import verify, verify_async

__all__ = [
    "Claw",
    "VerifyResult",
    "VerifyStatus",
    "ClawError",
    "verify",
    "verify_async",
]

__version__ = "0.1.0"
