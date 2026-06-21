"""Command-line interface for the clawid-sdk package.

    $ clawid verify-receipts receipts.jsonl

Designed for piping into shell scripts and CI:

  - Exit 0 → chain verified
  - Exit 1 → chain broken (tampered, truncated, missing rows)
  - Exit 2 → usage error (bad arguments, file not found)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .verify_receipts import verify_receipts


_GREEN = "\033[1;32m"
_RED   = "\033[1;31m"
_DIM   = "\033[2m"
_BOLD  = "\033[1m"
_RESET = "\033[0m"


def _cmd_verify_receipts(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"clawid: {path}: file not found", file=sys.stderr)
        return 2

    result = verify_receipts(path, require_genesis_start=args.require_genesis)
    header = result.header
    fmt = header.get("_meta", "?")
    tenant = header.get("tenant_id", "?")

    quiet = args.quiet
    if not quiet:
        print(f"{_BOLD}clawid verify-receipts{_RESET}  {_DIM}{path}{_RESET}")
        print(f"  format:        {fmt}")
        print(f"  tenant:        {tenant}")
        print(f"  rows checked:  {result.rows_checked}")
        head = header.get("chain_head_at_export", {})
        if head:
            print(f"  declared head: latest_seq={head.get('latest_seq')}, "
                  f"latest_hash={(head.get('latest_hash') or '')[:24]}…")
        print()

    if result.ok:
        if not quiet:
            print(f"{_GREEN}OK {result.message}{_RESET}")
        return 0

    if not quiet:
        print(f"{_RED}FAIL {result.message}{_RESET}")
        if result.row_failures:
            print()
            for f in result.row_failures[:20]:
                seq_part = f"seq={f.local_seq}" if f.local_seq is not None else "seq=?"
                print(f"  row {f.row_index} ({seq_part}): {f.reason}")
            if len(result.row_failures) > 20:
                print(f"  … and {len(result.row_failures) - 20} more")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="clawid",
        description="ClawID SDK command-line tools.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    vr = sub.add_parser(
        "verify-receipts",
        help="Verify a ClawID JSONL receipts export end-to-end (offline; no hub access).",
        description=(
            "Verify the hash chain in a ClawID receipts JSONL file. Uses only the "
            "file's contents and Python's standard library — no API calls, no keys. "
            "Exit code is 0 if the chain is intact, 1 if any row failed or the chain "
            "head doesn't match, 2 for usage errors."
        ),
    )
    vr.add_argument("path", help="Path to the .jsonl receipts file.")
    vr.add_argument("--quiet", "-q", action="store_true",
                    help="Suppress output; rely on exit code only.")
    vr.add_argument("--require-genesis", action="store_true",
                    help="Require the file to cover the chain from the beginning "
                         "(first row's prev_hash must equal 'GENESIS').")
    vr.set_defaults(func=_cmd_verify_receipts)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
