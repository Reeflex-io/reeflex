"""
cli.py -- operator-facing commands for the gateway seat.

  reeflex-litellm normalize     read tool calls on stdin, print how each one
                                normalizes and what the classifier prices it as.
                                NO NETWORK -- use it to check a tool map before
                                pointing the proxy at anything.
  reeflex-litellm decide        the same, but POST each envelope to core and
                                print the verdict.  This is the command that
                                reproduces a verdict outside the proxy.
  reeflex-litellm envelope      print the Action Envelope for each tool call.
  reeflex-litellm version       print the package version.

stdin for all three: either a bare list of OpenAI tool_call objects, or a whole
chat-completion response (the tool calls are read off `choices[*].message`).
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import core as _core
from . import enforce as _enforce
from . import envelope as _envelope
from . import normalize as _normalize
from . import response as _response


def _read_tool_calls(raw_text: str) -> list:
    payload = json.loads(raw_text)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and payload.get("choices"):
        out = []
        for choice in _response.get_choices(payload):
            out.extend(_response.get_tool_calls(choice))
        return out
    if isinstance(payload, dict) and payload.get("function"):
        return [payload]
    raise ValueError(
        "stdin must be a list of tool_call objects, a single tool_call object, "
        "or a chat-completion response carrying choices[].message.tool_calls")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="reeflex-litellm",
        description="Reeflex governance seat for an LLM gateway: rule on the "
                    "tool calls a model proposes.")
    parser.add_argument("--version", action="version",
                        version="reeflex-litellm " + __version__)
    sub = parser.add_subparsers(dest="command")

    p_norm = sub.add_parser(
        "normalize",
        help="show how each tool call normalizes and how it is priced (no network)")
    p_norm.add_argument("--session", default="cli", help="session id to use")
    p_norm.add_argument("--model", default="cli", help="model name to record")

    p_env = sub.add_parser("envelope", help="print the Action Envelope per tool call")
    p_env.add_argument("--session", default="cli")
    p_env.add_argument("--model", default="cli")

    p_dec = sub.add_parser("decide", help="POST each envelope to core, print the verdict")
    p_dec.add_argument("--session", default="cli")
    p_dec.add_argument("--model", default="cli")
    p_dec.add_argument("--hold-wait", type=float, default=0.0,
                       help="seconds to await a hold resolution (default 0: "
                            "do not wait, report the hold)")

    sub.add_parser("version", help="print the package version")

    args = parser.parse_args(argv)

    if args.command in (None,):
        parser.print_help()
        return 2

    if args.command == "version":
        print(__version__)
        return 0

    try:
        calls_raw = _read_tool_calls(sys.stdin.read())
    except Exception as exc:
        print("could not read tool calls from stdin: %s" % exc, file=sys.stderr)
        return 2

    calls = [_normalize.normalize_tool_call(c) for c in calls_raw]

    if args.command == "normalize":
        from reeflex_claude import classify as _classify
        for c in calls:
            cls = _classify.classify(c.tool_name, c.tool_input)
            print(json.dumps({
                "tool_call_id": c.call_id,
                "gateway_tool": c.gateway_tool,
                "classifier_tool": c.tool_name,
                "mapped": c.mapped,
                "mapping_source": c.mapping_source,
                "arguments_parsed": c.arguments_ok,
                "verb": cls["verb"],
                "axes": {"reversibility": cls["reversibility"],
                         "blast_radius": cls["blast_radius"],
                         "externality": cls["externality"]},
                "classification_tier": cls["classification_tier"],
                "danger_signature": cls["danger_signature"],
            }, sort_keys=True))
        return 0

    if args.command == "envelope":
        for c in calls:
            print(json.dumps(_envelope.build_gateway_envelope(
                session_id=args.session, model=args.model, call=c),
                sort_keys=True, indent=2))
        return 0

    # decide
    print("core: %s" % _core.core_url(), file=sys.stderr)
    worst = 0
    for c in calls:
        outcome = _enforce.rule_one_call(
            c, session_id=args.session, model=args.model,
            hold_wait=args.hold_wait)
        print(json.dumps({
            "tool_call_id": c.call_id,
            "gateway_tool": c.gateway_tool,
            "allowed": outcome.allowed,
            "hold_id": outcome.hold_id,
            "released_after_approval": outcome.released_after_approval,
            "rule": outcome.verdict.rule if outcome.verdict else None,
            "core_reachable": outcome.verdict.core_reachable if outcome.verdict else None,
            "refusal": outcome.refusal,
        }, sort_keys=True))
        if not outcome.allowed:
            worst = 1
    return worst


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
