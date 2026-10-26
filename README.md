<p align="center">
  <img src="https://holdtheleash.id/crab-claw-mark.png" width="120" alt="ClawID" />
</p>

<h1 align="center">clawid-sdk</h1>

<p align="center"><strong>Agent KYC. Verify autonomous AI agent credentials in three lines.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/clawid-sdk/"><img src="https://img.shields.io/pypi/v/clawid-sdk.svg" alt="PyPI" /></a>
  <a href="https://github.com/projectblackboxllc/claw-sdk-python/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
  <a href="https://pypi.org/project/clawid-sdk/"><img src="https://img.shields.io/pypi/pyversions/clawid-sdk.svg" alt="Python versions" /></a>
</p>

---

```python
import clawid_sdk_sdk

result = clawid_sdk.verify(token)
if result.valid:
    print(result.agent_id, "owned by", result.tenant_id)
```

That's it. Three lines. **Free forever for verifiers.** No key, no contract.

## What is this?

ClawID is the trust layer for autonomous AI agents and the services they touch. Every agent
carries a **Claw** — a cryptographically signed credential that binds the agent to its
owner, declares the owner's policy (the **leash**), and produces a tamper-evident receipt
of every action. This SDK is what services use to verify a Claw on the way in.

When an AI agent calls your API, you want to know:

- **Who's behind it?** → `result.tenant_id`, `result.agent_id`
- **What did the owner permit?** → `result.leash`
- **Can the owner kill it?** → yes; `result.status` reflects current revocation state
- **Is there a record of the attempt?** → yes; every check-in lands in a hash-chained audit log on both sides

One round-trip, four answers. Free forever for verifiers.

## Install

```bash
pip install clawid-sdk
```

Python 3.10+. Two dependencies: [`httpx`](https://www.python-httpx.org/) and [`pyjwt[crypto]`](https://pyjwt.readthedocs.io/).

## Use

### The common case

```python
import clawid_sdk

result = clawid_sdk.verify(token)

if not result.valid:
    return reject(result.status, result.reason)

# Now you know who this is.
print(f"Agent {result.agent_id} owned by {result.tenant_id}")
print(f"Leash: {result.leash}")
```

### When you want to configure things

```python
from clawid_sdk import Claw

claw = Claw(
    hub_url="https://api.holdtheleash.id",   # defaults to this
    jwks_ttl=300,                             # cache the hub's pubkey for 5 minutes
    timeout=5.0,                              # per-request timeout
)

result = claw.verify(token)
```

### Async

```python
result = await clawid_sdk.verify_async(token)
```

### Offline mode (signature + expiry only, no live revocation check)

```python
result = clawid_sdk.verify(token, mode="offline")
```

Use when latency matters more than seeing revokes immediately. The signature check
still uses the cached JWKS, so signature validity is accurate. Revocation is NOT
checked in offline mode — you won't see a revoke until you either fall through to
online mode for a call, or poll `/v1/verify` for the token's `jti` out of band on a
schedule you control. Suited for very high-throughput verifiers who accept explicit
revocation lag in exchange for zero network round-trips per verify.

### Web-framework integration

The SDK is framework-agnostic by design. A FastAPI middleware looks like:

```python
from fastapi import FastAPI, HTTPException, Request, Depends

import clawid_sdk

app = FastAPI()

def claw_required(request: Request) -> clawid.VerifyResult:
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, "missing Claw")
    result = clawid_sdk.verify(token)
    if not result.valid:
        raise HTTPException(401, f"{result.status.value}: {result.reason}")
    return result

@app.post("/charge")
def charge(amount: float, agent: clawid.VerifyResult = Depends(claw_required)):
    if amount > agent.leash["spend_ceiling"]:
        raise HTTPException(403, "amount exceeds agent's leash")
    return {"agent_id": agent.agent_id, "charged": amount}
```

## Push notices

The hub can POST to your server when something changes — a Claw used on
your service was revoked, or (for owners) an agent is waiting for approval.
Register an endpoint in the dashboard (Settings → Push notices) or with
`POST /v1/webhooks`. Each notice is a signed
[Security Event Token](https://www.rfc-editor.org/rfc/rfc8417) (`Content-Type:
application/secevent+jwt`), checked against the same public key as every Claw:

```python
import clawid_sdk

result = clawid_sdk.verify_event(request_body, audience="tnt_your_tenant_id")
if result and result.event_type == "claw.revoked":
    forget(result.data["claw_jti"])        # stop honoring this Claw now
```

| `event_type` | Who gets it | `data` |
|---|---|---|
| `claw.revoked` | verified vendors the Claw was used on | `claw_jti`, `agent_id`, `tenant_id`, `revoked_at`, `cause` (`owner` / `auto_revoke`) |
| `hold.created` | the owner | `hold_id`, `agent_label`, `surface`, `action`, `amount`, `expires_at`, `approve_url` |
| `hold.resolved` | the owner | `hold_id`, `status` (`approved` / `rejected`), `release_expires_at` |
| `ping` | whoever pressed "Send test" | `endpoint_id`, `sent_at` |

Failed deliveries are retried for about a day and a half, so the same notice
can arrive twice: dedupe on `result.event_id`. Push is a speed-up, not the
source of truth — `verify(token)` in online mode still asks the hub live.

## What the result tells you

`VerifyResult` is a dataclass. `if result:` is shorthand for `if result.valid:`.

```python
@dataclass
class VerifyResult:
    valid: bool                     # True iff the Claw is currently usable
    status: VerifyStatus            # ACTIVE | REVOKED | EXPIRED | INVALID | UNKNOWN
    reason: str | None              # human-readable reason
    jti: str | None                 # JWT id of this Claw (stable receipt key)
    agent_id: str | None            # who the agent is
    tenant_id: str | None           # who owns the agent
    leash: dict | None              # the owner's policy: spend cap, surfaces, hours...
    agent_pubkey_pem: str | None    # for proof-of-possession on signed actions
    issued_at: int | None
    expires_at: int | None
    payload: dict | None            # raw decoded JWS payload, for custom claims
```

`VerifyStatus`:

| Status | Means |
|---|---|
| `ACTIVE` | Claw is valid and live; owner has not revoked it. |
| `REVOKED` | Owner hit the kill switch. Deny the request. |
| `EXPIRED` | The `exp` claim is in the past. Agent needs a fresh Claw. |
| `INVALID` | Signature didn't verify, malformed, unknown issuer, etc. |
| `UNKNOWN` | Hub returned a status this SDK version doesn't recognize. Treat as `INVALID`. |

## What's the leash?

```python
result.leash
# {
#   "spend_ceiling": 50.0,
#   "allowed_surfaces": ["stripe.com", "openai.com"],
#   "active_start_hour": 9,
#   "active_end_hour": 17,
#   "escalate_over": 25.0,
#   "auto_revoke_off_leash": True,
#   "hold_actions": ["transfer"],   # always need owner approval
# }
```

You can use the leash to short-circuit policy decisions on your side — for example,
refuse the request if `amount > leash["spend_ceiling"]` before doing any expensive work.

## How the verify path works

```
                        clawid_sdk.verify(token)
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
       Offline (JWS)                       Online (revocation)
       │                                   │
       1. Fetch JWKS from                  1. POST /v1/verify
          /.well-known/jwks.json              with the token
          (cached for jwks_ttl)            2. Hub responds with
       2. Verify EdDSA signature              live revocation status
       3. Check exp / iss / required          + structural detail
          claims

       If signature is bad → INVALID
       If exp in past     → EXPIRED
       Otherwise:                          status: ACTIVE / REVOKED
       online mode → run the right path
       offline mode → return ACTIVE
```

The hub's signing key is in cloud KMS. We never see your verify traffic if you stay in
offline mode after the first JWKS fetch.

## Errors

`ClawError` is raised only for infrastructure problems (the hub is unreachable, JWKS is
malformed). Verification failures — bad signature, expired, revoked — never raise; they
return a `VerifyResult` with `valid=False` and a `status` that describes what happened.

```python
import clawid_sdk

try:
    result = clawid_sdk.verify(token)
except clawid_sdk.ClawError as e:
    # Hub is down or JWKS is unreachable. Decide based on your trust posture
    # — typically: fail closed.
    return reject_with_503(str(e))

if not result.valid:
    # Bad/expired/revoked Claw. Tell the agent's owner why.
    return reject_with_401(result.status, result.reason)
```

## Vendor onboarding

Verification is permissionless. You don't need a key, an account, or a contract to call
`clawid_sdk.verify(...)`. **It's free forever.** That's the whole network effect.

If you want to appear in the [Verified Vendors directory](https://holdtheleash.id) — and
get the matching audit-chain visibility on your side of every check-in to your domain —
apply at [holdtheleash.id/vendors](https://holdtheleash.id) (KYB-gated: entity + domain
ownership + live service + signed TOS). Listing is free; promotional placement is a
separate paid surface.

## Versioning

`clawid-sdk` follows [SemVer](https://semver.org/). The `VerifyResult` shape is stable within
a major; new optional fields are minor; field removals or behavior changes are major.
`payload` always carries the full decoded JWS for forward-compatibility with new claims.

## License

[Apache License 2.0](LICENSE). Copyright © 2026 Project Black Box LLC.

## Links

- **Product**: [holdtheleash.id](https://holdtheleash.id)
- **Dashboard**: [app.holdtheleash.id](https://app.holdtheleash.id)
- **Issues**: [github.com/projectblackboxllc/claw-sdk-python/issues](https://github.com/projectblackboxllc/claw-sdk-python/issues)
- **JS SDK**: [github.com/projectblackboxllc/claw-sdk-js](https://github.com/projectblackboxllc/claw-sdk-js) *(coming alongside this one)*
- **Spec**: [github.com/projectblackboxllc/claw-spec](https://github.com/projectblackboxllc/claw-spec) *(coming next)*
