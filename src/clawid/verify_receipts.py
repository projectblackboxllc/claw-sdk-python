"""Offline chain verification for ClawID JSONL receipt exports.

A ClawID receipts file is a tamper-evident hash chain. Each row's
`entry_hash` is sha256 over the canonical-JSON of:
    {seq=local_seq, ts, jti, surface, action, amount, decision, reason,
     tenant_id, prev_hash}
where `prev_hash` is the previous row's `entry_hash` (the first row's
prev_hash is "GENESIS" for whole-chain exports, or the entry_hash of
whatever the chain's earlier state was for partial / sliced exports).

This module verifies that property end-to-end from the file alone. It
needs nothing from the hub — no API call, no key, no account. Standard
library only (hashlib + json).

    >>> from clawid import verify_receipts
    >>> r = verify_receipts("receipts.jsonl")
    >>> if r.ok:
    ...     print("verified", r.rows_checked, "rows")
    ... else:
    ...     print("FAILED:", r.message)

Or from the command line:

    $ clawid verify-receipts receipts.jsonl
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Union


@dataclass(frozen=True)
class RowFailure:
    """A single row that failed verification."""
    row_index: int            # 1-based position in the file (excluding header)
    local_seq: int | None     # the row's chain position, if present
    reason: str               # human-readable failure cause


@dataclass(frozen=True)
class ReceiptsVerifyResult:
    ok: bool
    rows_checked: int
    chain_head_match: bool          # final row entry_hash == header's chain_head latest_hash
    header: dict = field(default_factory=dict)
    row_failures: tuple[RowFailure, ...] = ()
    message: str = ""

    def __bool__(self) -> bool:
        return self.ok


def _canonical(obj: dict) -> str:
    """Canonical JSON — same shape the hub uses to compute entry_hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def verify_receipts(
    source: Union[str, Path, IO[str]],
    *,
    require_genesis_start: bool = False,
) -> ReceiptsVerifyResult:
    """Verify a ClawID JSONL receipts export end-to-end.

    Args:
        source: path string, ``pathlib.Path``, or text-mode file-like.
        require_genesis_start: if True, the first row's ``prev_hash`` must
            equal ``"GENESIS"`` (i.e. the export covers the entire chain
            from the beginning). Default False — partial/windowed exports
            anchor on whatever the chain state was before the window.

    Returns a :class:`ReceiptsVerifyResult`. The bool-coerce / ``.ok``
    flag tells you if the chain held. ``row_failures`` lists every row
    that failed and why; ``chain_head_match`` indicates whether the file
    ends at the header's declared latest_hash.

    Does NOT raise on bad data — invalid JSON, missing fields, broken
    hashes all become ``ok=False`` results with diagnostic messages.
    The one exception is when ``source`` itself can't be read (file not
    found, etc.); that propagates the OS error.
    """
    # Read all lines into memory. Receipts files are small (max 72 hours
    # of activity for the default retention window) — typically dozens to
    # low-thousands of rows. No need to stream.
    if hasattr(source, "read"):
        text = source.read()
    else:
        text = Path(source).read_text()

    raw_lines = [ln for ln in text.splitlines() if ln.strip()]
    if not raw_lines:
        return ReceiptsVerifyResult(
            ok=False, rows_checked=0, chain_head_match=False,
            message="file is empty",
        )

    # Parse header
    try:
        header = json.loads(raw_lines[0])
    except json.JSONDecodeError as e:
        return ReceiptsVerifyResult(
            ok=False, rows_checked=0, chain_head_match=False,
            message=f"first line is not valid JSON: {e}",
        )
    if not isinstance(header, dict) or "_meta" not in header:
        return ReceiptsVerifyResult(
            ok=False, rows_checked=0, chain_head_match=False, header=header if isinstance(header, dict) else {},
            message="first line is not a ClawID receipts header (missing _meta)",
        )

    fmt = header.get("_meta", "")
    if not fmt.startswith("claw-receipts-jsonl/"):
        return ReceiptsVerifyResult(
            ok=False, rows_checked=0, chain_head_match=False, header=header,
            message=f"unrecognized format: {fmt!r}",
        )

    declared_head = header.get("chain_head_at_export", {}) or {}
    declared_latest_hash = declared_head.get("latest_hash")

    # Walk rows
    failures: list[RowFailure] = []
    prev_hash = "GENESIS"
    last_entry_hash: str | None = None
    rows_seen = 0

    for idx, line in enumerate(raw_lines[1:], 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            failures.append(RowFailure(idx, None, f"invalid JSON: {e}"))
            continue
        rows_seen += 1

        # local_seq is required to recompute the entry hash. v2 exports
        # include it on every row; v1 exports don't — they require row-
        # ordinal reconstruction starting at 1 (or chain offset), which
        # this verifier doesn't attempt (v1 is deprecated).
        local_seq = row.get("local_seq")
        if local_seq is None:
            failures.append(RowFailure(idx, None,
                "row is missing local_seq — only v2+ exports are externally verifiable; "
                "this file looks like the older v1 format"))
            continue

        # First-row anchor check
        if idx == 1 and require_genesis_start and row.get("prev_hash") != "GENESIS":
            failures.append(RowFailure(idx, local_seq,
                f"require_genesis_start=True but first row prev_hash is {row.get('prev_hash')!r}"))

        # On the very first row of a partial export, we adopt that row's
        # declared prev_hash as our starting anchor. The chain proves
        # itself forward from there. The reader trusts the anchor or
        # cross-checks it against a separately-known chain state.
        if idx == 1:
            prev_hash = row.get("prev_hash", "GENESIS")

        # Chain linkage
        row_prev = row.get("prev_hash")
        if row_prev != prev_hash:
            failures.append(RowFailure(idx, local_seq,
                f"prev_hash mismatch: row says {str(row_prev)[:24]}…, "
                f"expected {prev_hash[:24]}…"))

        # Recompute entry_hash from canonical fields
        try:
            canonical_entry = {
                "seq":       local_seq,
                "ts":        row["ts"],
                "jti":       row["jti"],
                "surface":   row["surface"],
                "action":    row["action"],
                "amount":    row["amount"],
                "decision":  row["decision"],
                "reason":    row["reason"],
                "tenant_id": row["tenant_id"],
                "prev_hash": row_prev,
            }
        except KeyError as e:
            failures.append(RowFailure(idx, local_seq, f"missing canonical field: {e}"))
            prev_hash = row.get("entry_hash") or prev_hash
            last_entry_hash = row.get("entry_hash") or last_entry_hash
            continue

        computed_hash = hashlib.sha256(_canonical(canonical_entry).encode("utf-8")).hexdigest()
        if computed_hash != row.get("entry_hash"):
            failures.append(RowFailure(idx, local_seq,
                f"entry_hash mismatch: computed {computed_hash[:24]}…, "
                f"row says {(row.get('entry_hash') or '')[:24]}… "
                "(this row's contents or hash has been tampered with)"))

        prev_hash = row.get("entry_hash") or prev_hash
        last_entry_hash = row.get("entry_hash")

    chain_head_match = (
        declared_latest_hash is not None
        and last_entry_hash is not None
        and declared_latest_hash == last_entry_hash
    )

    if failures:
        msg = f"{len(failures)} row(s) failed verification; chain is NOT intact"
    elif not chain_head_match and declared_latest_hash is not None:
        msg = ("all rows verified individually but the final row's entry_hash does NOT "
               "match the chain_head_at_export.latest_hash declared in the header — "
               "rows may have been removed from the end of the file")
    elif not chain_head_match:
        msg = "rows verified; no chain_head_at_export declared in header to cross-check"
    else:
        msg = f"verified {rows_seen} rows end-to-end; chain head matches declared anchor"

    # We treat "no chain_head_at_export to compare" as ok=True (we did
    # everything we could). If a chain head IS declared and doesn't match,
    # that's a failure — the file may have been truncated.
    chain_head_ok = (declared_latest_hash is None) or chain_head_match
    ok = (not failures) and chain_head_ok

    return ReceiptsVerifyResult(
        ok=ok,
        rows_checked=rows_seen,
        chain_head_match=chain_head_match,
        header=header,
        row_failures=tuple(failures),
        message=msg,
    )


__all__ = ["verify_receipts", "ReceiptsVerifyResult", "RowFailure"]
