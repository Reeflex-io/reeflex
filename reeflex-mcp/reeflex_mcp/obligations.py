"""
obligations.py -- Track 5.1 (design doc ADDENDUM v1.5 section 25): SPEC
section 5's Decision.obligations, honored, not ignored.

SPEC section 5: "obligations are mandatory side-effects (e.g. redact:pii,
rate_limit). An adapter that ignores an obligation is non-conformant."
Conformance-verifier found this gap: nothing in reeflex_mcp read
`decision["obligations"]` at all -- latent (the base policy pack emits `[]`
today) but structural, and a release blocker per SPEC section 7 minimum #5.

THE MECHANISM (this module) -- a small, deterministic, string-keyed dispatch
table: `register(obligation_string, handler)`. No LLM, no free-text
interpretation anywhere in this file: an obligation is either a string this
module has a registered handler for, or it isn't -- there is no fuzzy/
semantic matching, no "best effort" guess at an unrecognized one.

THE POLICY (gateway.py, NOT this module) -- what happens when an obligation
IS or ISN'T known differs by gateway mode (design doc section 25):
  enforce: known -> apply its handler, then forward. unknown -> BLOCK
           (isError, fail closed) -- never silently forward past an
           obligation the gateway cannot honor.
  observe: RECORDED (logged as "would-honor"), never applied, never blocks
           -- observe must never enforce anything, but recording (not
           silently dropping) is what keeps it from "ignoring" the
           obligation in SPEC section 5's sense.
This module deliberately does NOT know about gateway modes at all -- it only
answers "is this obligation known, and if so, what does honoring it do" as a
pure lookup; gateway.py owns the enforce-vs-observe branching (see its
_apply_enforce_obligations()/_record_observed_obligations()).

V1 KNOWN-SET (design doc section 25: "may be empty/minimal for v1"): ONE
example handler ships -- `audit:full`, the exact obligation string SPEC
section 5's own Decision example uses, and the one
reeflex-spec/ADAPTER-EXAMPLES.md section C's shared Rego rule emits
alongside a require_approval verdict. Shipping a real, SPEC-referenced
obligation (rather than nothing) proves the mechanism end-to-end without
inventing a fictitious one -- the same "don't invent, use what's real"
discipline Track 4's starter mappings followed for tool names.

EXTENSION POINT: call `register(name, handler)` to add support for another
obligation string -- see the README's "How to add an obligation handler"
section for a worked example. `handler` receives one `ObligationContext` and
returns nothing; it may do local I/O (e.g. logging) but must never call an
LLM, make a network decision call, or otherwise re-decide anything --
SPEC's zero-LLM-in-the-decision-path invariant extends to this extension
point too.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ObligationContext:
    """Everything a handler might need to honor one obligation for one call.
    Read-only by convention: a handler observes/records, it does not mutate
    the envelope, the decision, or the eventual dispatch -- if an obligation
    someday needs to actually TRANSFORM the call (e.g. `redact:pii` editing
    arguments), that is a deliberate future extension of this contract, not
    something a handler should attempt by mutating this dataclass today
    (it's frozen specifically to make that intent explicit)."""

    obligation: str
    envelope: dict[str, Any]
    decision: dict[str, Any]
    gateway_correlation_id: str
    upstream_name: str
    tool_name: str


ObligationHandler = Callable[[ObligationContext], None]

_HANDLERS: dict[str, ObligationHandler] = {}


class UnknownObligationError(Exception):
    """Raised by apply_known() when `obligation` has no registered handler.
    gateway.py maps this to a fail-closed block in enforce mode (design doc
    section 25) -- this module itself does not decide what "unknown" should
    DO, only reports that it IS unknown."""

    def __init__(self, obligation: str):
        self.obligation = obligation
        super().__init__(f"unsupported obligation {obligation!r} -- no registered handler")


def register(obligation: str, handler: ObligationHandler) -> None:
    """Register (or replace) the handler for one obligation string. Last
    registration wins -- same idiom as this project's other registries
    (e.g. mappings.py's per-tool entries). Intended to be called at import
    time for the shipped v1 known-set below, or by an operator's own
    extension module loaded before the gateway starts (README "How to add
    an obligation handler")."""
    if not isinstance(obligation, str) or not obligation:
        raise ValueError("obligation must be a non-empty string")
    _HANDLERS[obligation] = handler


def known_obligations() -> frozenset[str]:
    """Every obligation string with a registered handler right now."""
    return frozenset(_HANDLERS.keys())


def apply_known(obligation: str, ctx: ObligationContext) -> None:
    """Apply the registered handler for `obligation`. Deterministic
    string-dispatch ONLY -- no LLM, no interpretation, no partial/fuzzy
    match. Raises UnknownObligationError if nothing is registered for this
    EXACT string."""
    handler = _HANDLERS.get(obligation)
    if handler is None:
        raise UnknownObligationError(obligation)
    handler(ctx)


# ---------------------------------------------------------------------------
# v1 known-set -- see module docstring for why `audit:full` specifically.
# ---------------------------------------------------------------------------


def _handle_audit_full(ctx: ObligationContext) -> None:
    """'audit:full' -- log the full envelope (not just a summary) to stderr
    for local operator visibility, tagged with the correlation id so it can
    be joined to the result the client sees.

    HONEST SCOPE NOTE: reeflex-core ALREADY writes a full, unconditional
    audit record on every /v1/decide call regardless of any obligation
    (SPEC section 6's AUDIT responsibility lives in core, not this gateway,
    for the decision itself). This handler is the gateway's OWN, additive
    acknowledgement that full-detail logging was specifically requested for
    THIS call -- it does not replace or duplicate core's audit trail, and it
    is deliberately side-effect-free beyond a log line (no network I/O, no
    state mutation) so it can never itself become a new failure mode on the
    dispatch path.
    """
    print(
        f"[reeflex-mcp] OBLIGATION 'audit:full' honored for "
        f"{ctx.upstream_name}__{ctx.tool_name} (gateway_correlation_id={ctx.gateway_correlation_id}): "
        f"envelope={ctx.envelope}",
        file=sys.stderr,
    )


register("audit:full", _handle_audit_full)
