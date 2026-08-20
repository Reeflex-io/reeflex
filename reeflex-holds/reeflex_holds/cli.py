"""
cli.py -- the real, human-typable `reeflex-holds` terminal commands.

RFX-42: before this module existed, `reeflex-holds list` (and `approve`,
`--help`, any argv at all) fell straight into server.py's `mcp.run(transport=
"stdio")`, which ignores argv entirely. Run from a terminal (stdin not a
live MCP client), it just exits -- 0, no output -- as soon as stdin hits
EOF. An operator reasonably reads silence as "no pending holds"; that is a
tool answering a question it was never asked, which is worse than no tool
at all. This module is the fix: real argparse subcommands that call the
same client.py functions the MCP tools call, print an unambiguous result or
error, and exit non-zero on failure -- never silently.

Subcommands: list, approve, reject. Same 4-eyes and REEFLEX_PRINCIPAL rules
as every other surface (see server.py, client.py): the resolving identity is
never a CLI argument, only ever the server's own REEFLEX_PRINCIPAL env var,
so a resolution made from this CLI is indistinguishable in core's evidence
from one made through the MCP tool or the dashboard -- same endpoint, same
principal plumbing, same reeflex-core validation chain.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import client, config

# Exit codes (mirrors reeflex-verify's convention): 0 success, 1 core
# rejected the request (a real answer, just not the one asked for), 2 local
# setup/connection problem (nothing reached core, or REEFLEX_PRINCIPAL unset).
EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_SETUP_ERROR = 2


def _print_hold_line(hold: dict[str, Any]) -> None:
    envelope = hold.get("envelope") or {}
    action = envelope.get("action") or {}
    ability = action.get("ability") or action.get("verb") or "?"
    magnitude = (envelope.get("magnitude") or {}).get("count")
    size = f" x{magnitude}" if magnitude is not None else ""
    print(
        f"{hold.get('id', '?')}  {hold.get('status', '?'):<9} "
        f"{hold.get('rule_id', '?'):<45} {ability}{size}"
    )
    print(
        f"    created {hold.get('created_ts', '?')}  expires {hold.get('expires_ts', '?')}"
    )


def cmd_list(args: argparse.Namespace) -> int:
    try:
        result = client.list_holds(status=args.status)
    except client.HoldsConnectionError as exc:
        print(f"Cannot reach reeflex-core: {exc}", file=sys.stderr)
        return EXIT_SETUP_ERROR
    except client.HoldsAPIError as exc:
        print(f"reeflex-core rejected the request: {exc}", file=sys.stderr)
        return EXIT_REJECTED

    if args.json:
        print(json.dumps(result))
        return EXIT_OK

    items = result.get("items", [])
    if not items:
        label = args.status or "any status"
        print(f"No holds found ({label}).")
        return EXIT_OK

    print(f"{len(items)} hold(s):")
    for hold in items:
        _print_hold_line(hold)
    if result.get("next_cursor"):
        print(f"... more available (next_cursor={result['next_cursor']!r}).")
    return EXIT_OK


def _resolve(args: argparse.Namespace, decision: str) -> int:
    try:
        result = client.resolve_hold(args.id, decision, reason=args.reason)
    except config.ConfigError as exc:
        print(f"Cannot resolve: {exc}", file=sys.stderr)
        return EXIT_SETUP_ERROR
    except client.HoldsConnectionError as exc:
        print(f"Cannot reach reeflex-core: {exc}", file=sys.stderr)
        return EXIT_SETUP_ERROR
    except client.HoldsAPIError as exc:
        print(f"reeflex-core refused to {decision} hold {args.id}: {exc}", file=sys.stderr)
        return EXIT_REJECTED

    if args.json:
        print(json.dumps(result))
    else:
        print(
            f"Hold {result.get('id', args.id)} is now {result.get('status', '?')} "
            f"(decided_by={result.get('decided_by', '?')}, decided_ts={result.get('decided_ts', '?')})."
        )
    return EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    return _resolve(args, "approve")


def cmd_reject(args: argparse.Namespace) -> int:
    return _resolve(args, "reject")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reeflex-holds",
        description=(
            "List, approve, and reject Reeflex governance holds from a terminal "
            "-- no wp-admin, no dashboard, no hand-written HTTP call. Calls the "
            "same reeflex-core /v1/holds API as the MCP tools this package also "
            "exposes. Run with NO arguments to start the stdio MCP server instead "
            "(see README)."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    list_p = sub.add_parser("list", help="List Reeflex holds.")
    list_p.add_argument(
        "--status",
        choices=("pending", "approved", "rejected", "expired", "consumed"),
        default=None,
        help="Filter by status (default: no filter, core's most-recent-first order).",
    )
    list_p.add_argument("--json", action="store_true", help="Print raw JSON instead of a table.")
    list_p.set_defaults(func=cmd_list)

    approve_p = sub.add_parser("approve", help="Approve a pending hold.")
    approve_p.add_argument("id", help="The hold id (see `reeflex-holds list`).")
    approve_p.add_argument("--reason", default=None, help="Optional free-text reason, recorded on the hold.")
    approve_p.add_argument("--json", action="store_true", help="Print raw JSON instead of a summary line.")
    approve_p.set_defaults(func=cmd_approve)

    reject_p = sub.add_parser("reject", help="Reject a pending hold.")
    reject_p.add_argument("id", help="The hold id (see `reeflex-holds list`).")
    reject_p.add_argument("--reason", default=None, help="Optional free-text reason, recorded on the hold.")
    reject_p.add_argument("--json", action="store_true", help="Print raw JSON instead of a summary line.")
    reject_p.set_defaults(func=cmd_reject)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_SETUP_ERROR
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
