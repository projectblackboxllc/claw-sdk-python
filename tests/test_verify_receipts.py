"""Tests for `clawid.verify_receipts` — the offline JSONL chain verifier.

We assemble fake-but-canonical receipts files in-memory by directly
emulating the hub's hash chain (SHA-256 over canonical-JSON over the
documented set of fields). That way we don't need network access or a
live hub, and the verifier is tested against the SAME contract a real
external auditor would write."""
from __future__ import annotations

import hashlib
import io
import json
from typing import Iterator

import pytest

from clawid_sdk import verify_receipts, ReceiptsVerifyResult
from clawid_sdk.verify_receipts import RowFailure


# ── canonical-form helpers (mirror the hub) ────────────────────────────


def _canonical(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def _entry_hash(*, seq: int, ts: int, jti: str, surface: str, action: str,
                amount: float, decision: str, reason: str, tenant_id: str,
                prev_hash: str) -> str:
    e = {
        "seq": seq, "ts": ts, "jti": jti, "surface": surface, "action": action,
        "amount": amount, "decision": decision, "reason": reason,
        "tenant_id": tenant_id, "prev_hash": prev_hash,
    }
    return hashlib.sha256(_canonical(e).encode("utf-8")).hexdigest()


def _build_jsonl(rows_specs: list[dict], *, tenant_id: str = "tnt_test",
                 first_prev_hash: str = "GENESIS",
                 starting_local_seq: int = 1) -> tuple[str, str]:
    """Return (jsonl_text, final_entry_hash) — convenience for tests.

    Each row spec is a dict with keys: ts, jti, surface, action, amount,
    decision, reason. We compute prev_hash + entry_hash + local_seq."""
    out_lines = []
    prev_hash = first_prev_hash
    local_seq = starting_local_seq
    final = None
    for i, spec in enumerate(rows_specs):
        eh = _entry_hash(seq=local_seq, tenant_id=tenant_id, prev_hash=prev_hash, **spec)
        row = {
            "seq": local_seq + 100,  # arbitrary global serial — verifier ignores it
            "tenant_id": tenant_id,
            "prev_hash": prev_hash,
            "entry_hash": eh,
            "local_seq": local_seq,
            **spec,
        }
        out_lines.append(json.dumps(row, separators=(",", ":")))
        prev_hash = eh
        local_seq += 1
        final = eh

    header = {
        "_meta": "claw-receipts-jsonl/v2",
        "tenant_id": tenant_id,
        "agent_id": None,
        "exported_at": 1_780_000_000,
        "window": {"since_ts": 0, "until_ts": 1_780_000_000},
        "chain_head_at_export": {
            "latest_seq": local_seq - 1,
            "latest_hash": final,
        },
        "verifier_note": "test fixture",
        "warning": "test data",
    }
    text = json.dumps(header, separators=(",", ":")) + "\n" + "\n".join(out_lines) + "\n"
    return text, final


def _three_good_rows() -> list[dict]:
    return [
        {"ts": 1_780_000_100, "jti": "clw_a", "surface": "api.stripe.com",
         "action": "charge", "amount": 1.25, "decision": "ALLOW", "reason": "within leash"},
        {"ts": 1_780_000_101, "jti": "clw_a", "surface": "api.openai.com",
         "action": "complete", "amount": 0.50, "decision": "ALLOW", "reason": "within leash"},
        {"ts": 1_780_000_102, "jti": "clw_a", "surface": "evil.example.com",
         "action": "exfil", "amount": 0.01, "decision": "DENY", "reason": "off-leash surface"},
    ]


# ── tests ──────────────────────────────────────────────────────────────


def test_clean_chain_verifies_end_to_end():
    text, _ = _build_jsonl(_three_good_rows())
    r = verify_receipts(io.StringIO(text))
    assert r.ok
    assert r.rows_checked == 3
    assert r.chain_head_match
    assert not r.row_failures


def test_tampered_amount_caught():
    rows = _three_good_rows()
    text, _ = _build_jsonl(rows)
    # Mutate the amount on the middle row without recomputing entry_hash.
    lines = text.splitlines()
    middle = json.loads(lines[2])
    middle["amount"] = 999.99
    lines[2] = json.dumps(middle, separators=(",", ":"))
    tampered = "\n".join(lines)

    r = verify_receipts(io.StringIO(tampered))
    assert not r.ok
    assert any("entry_hash mismatch" in f.reason for f in r.row_failures)


def test_broken_chain_link_caught():
    rows = _three_good_rows()
    text, _ = _build_jsonl(rows)
    lines = text.splitlines()
    # Mutate prev_hash on row 2 so the chain link is broken (but entry_hash
    # may still be self-consistent depending on whether we recompute it).
    row2 = json.loads(lines[2])
    row2["prev_hash"] = "0" * 64
    lines[2] = json.dumps(row2, separators=(",", ":"))
    tampered = "\n".join(lines)

    r = verify_receipts(io.StringIO(tampered))
    assert not r.ok
    # At minimum, the row's entry_hash will fail (we recompute using the
    # tampered prev_hash) OR the chain link check will. Either is a
    # caught failure.
    assert r.row_failures


def test_truncated_chain_caught_via_chain_head_mismatch():
    rows = _three_good_rows()
    text, _ = _build_jsonl(rows)
    lines = text.splitlines()
    # Drop the last row but keep the header (which still declares the
    # original chain head). Truncation simulates someone removing
    # incriminating entries from the end.
    truncated = "\n".join(lines[:-1])

    r = verify_receipts(io.StringIO(truncated))
    assert not r.ok
    assert not r.chain_head_match
    assert "chain_head_at_export.latest_hash" in r.message or "anchor" in r.message


def test_v1_format_rejected_as_unverifiable():
    rows = _three_good_rows()
    text, _ = _build_jsonl(rows)
    lines = text.splitlines()
    # Strip local_seq from every row — simulates the old v1 format.
    new_lines = [lines[0]]
    for ln in lines[1:]:
        d = json.loads(ln)
        d.pop("local_seq", None)
        new_lines.append(json.dumps(d, separators=(",", ":")))
    text = "\n".join(new_lines)

    r = verify_receipts(io.StringIO(text))
    assert not r.ok
    assert any("local_seq" in f.reason for f in r.row_failures)


def test_require_genesis_start_anchors_at_GENESIS():
    rows = _three_good_rows()
    text, _ = _build_jsonl(rows, first_prev_hash="GENESIS", starting_local_seq=1)
    r = verify_receipts(io.StringIO(text), require_genesis_start=True)
    assert r.ok


def test_require_genesis_start_rejects_partial_export():
    rows = _three_good_rows()
    text, _ = _build_jsonl(
        rows,
        first_prev_hash="abc123" * 10,  # 60 chars, plausibly real
        starting_local_seq=42,
    )
    r = verify_receipts(io.StringIO(text), require_genesis_start=True)
    assert not r.ok
    assert any("require_genesis_start" in f.reason for f in r.row_failures)


def test_partial_export_without_genesis_requirement_verifies():
    rows = _three_good_rows()
    fake_anchor = "ab" * 32
    text, _ = _build_jsonl(rows, first_prev_hash=fake_anchor, starting_local_seq=42)
    r = verify_receipts(io.StringIO(text))
    assert r.ok
    assert r.rows_checked == 3


def test_empty_file_is_failure():
    r = verify_receipts(io.StringIO(""))
    assert not r.ok
    assert "empty" in r.message


def test_garbage_header_is_failure():
    r = verify_receipts(io.StringIO("not json at all\n"))
    assert not r.ok
    assert "not valid JSON" in r.message


def test_wrong_format_is_failure():
    r = verify_receipts(io.StringIO('{"_meta":"some-other-format/v1"}\n'))
    assert not r.ok
    assert "unrecognized format" in r.message


def test_bool_coerce_works():
    text, _ = _build_jsonl(_three_good_rows())
    assert bool(verify_receipts(io.StringIO(text))) is True
