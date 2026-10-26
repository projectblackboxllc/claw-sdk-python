"""ClawID — Agent KYC.

The Python SDK for verifying Claws (the credential autonomous AI agents
carry to prove who they are, what their leash permits, and whether the
owner has revoked them).

    >>> import clawid_sdk
    >>> result = clawid_sdk.verify(token)
    >>> if result.valid:
    ...     print(result.agent_id, "owned by", result.tenant_id)

Three lines. Free forever for verifiers. No key, no contract.

Push notices (revocations, approval requests) arrive as signed Security
Event Tokens; check one with `clawid_sdk.verify_event(body)`.

See https://holdtheleash.id for the product, https://github.com/projectblackboxllc/claw-sdk-python
for the source, and the README for the full API surface.
"""
from __future__ import annotations

from .client import Claw, VerifyResult, VerifyStatus, ClawError, EventResult
from .verify import verify, verify_async, verify_event
from .verify_receipts import verify_receipts, ReceiptsVerifyResult, RowFailure

__all__ = [
    "Claw",
    "VerifyResult",
    "VerifyStatus",
    "ClawError",
    "verify",
    "verify_async",
    "verify_event",
    "EventResult",
    "verify_receipts",
    "ReceiptsVerifyResult",
    "RowFailure",
]

__version__ = "0.4.0"
