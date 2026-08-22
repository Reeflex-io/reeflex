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
never a CLI argument, only ever the server's own REEFLEX_PRINCIPAL env var
-- same endpoint, same principal plumbing, same reeflex-core validation
chain as the MCP tool and the dashboard.

RFX-149: what that plumbing CANNOT promise is that the identity was
verified. Since core gained `decided_by_verified` / `principal_source`
(RFX-84), a resolution is recorded as either
  principal_source "credential"  -> the approver came from the bearer token
                                    it is BOUND to (REEFLEX_RESOLVER_TOKENS)
  principal_source "asserted"    -> the approver is whatever REEFLEX_PRINCIPAL
                                    said, unverified; core warns on ITS OWN
                                    stderr, which the operator never sees
and core's whole point in adding those fields was that "an unverified claim
is no longer indistinguishable from a real human decision". This module used
to print one identical success sentence for both, so at the only surface a
human actually reads, it stayed exactly indistinguishable. Every human-
readable line that names a decider now names how that decider was
established, on the resolve path AND on `list` (where a reviewer looking at
an already-approved hold previously saw no approver at all).
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


def _provenance(hold: dict[str, Any]) -> str:
    """Render how the approver on this hold record was established.

    Reads core's additive RFX-84 fields. Three cases, all of which a human
    reading a decision needs told apart:

      credential  -> the approver came from the bearer token it is bound to.
      asserted    -> the approver is an unverified claim. Said plainly, in
                     the same breath as the identity, because the operator
                     has no other way to find out: core's warning goes to
                     core's stderr, on the other side of the wire.
      absent      -> a core too old to carry the fields (pre-RFX-84). Not
                     reported as verified and not reported as unverified --
                     this build cannot tell us, and saying either would be
                     inventing evidence.
    """
    if "decided_by_verified" not in hold and "principal_source" not in hold:
        return "verification not reported by this core"
    if hold.get("decided_by_verified") is True:
        return f"VERIFIED via {hold.get('principal_source') or 'credential'}"
    return (
        f"UNVERIFIED ({hold.get('principal_source') or 'asserted'}) -- core accepted "
        "this identity as claimed and did not confirm it"
    )


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
    # A hold someone already decided is the one a reviewer most needs the
    # decider for; printing only id/rule/timestamps made `list --status
    # approved` a list of approvals with no approver (RFX-149).
    if hold.get("decided_by"):
        print(
            f"    decided {hold.get('decided_ts', '?')} by {hold['decided_by']} "
            f"[{_provenance(hold)}]"
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
        # The identity above is only as good as the way core established it,
        # and the operator who just typed `approve` is the last person who
        # can still act on that (RFX-149). stderr, not stdout: the success
        # line is the result, this is the caveat on it, and a caller piping
        # stdout should not have its output shape changed by a config it
        # does not control.
        print(f"  approver: {_provenance(result)}", file=sys.stderr)
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
