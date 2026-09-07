"""
test_decision_totality.py -- `decision` must produce EXACTLY ONE value for
every envelope in the pack's own input space.

WHY THIS FILE EXISTS
====================
`decision` in reeflex.rego is a Rego COMPLETE rule with one body per rule id.
OPA's contract for a complete rule is that at most one body may produce a
value; two bodies producing DIFFERENT values is an `eval_conflict_error`, which
app/opa.py raises as OpaEvalError and decide.py turns into

    HTTP 500  {"decision": "deny", "rule": "reeflex.core/fail_closed"}

-- so for that envelope the canon answers nothing at all. It fails CLOSED,
which is the right direction, and it is still a total loss of the decision.

Every rule id added to the pack must therefore be guarded against every other
rule id that can fire on the same envelope. That obligation lives in prose
today: each `decision` body carries its own hand-written list of `not rN_...`
guards. Nothing checked the list was complete, and nothing could -- a missing
guard is invisible until an envelope satisfies both rules at once.

THE MEASURED CASE THAT MOTIVATED THIS FILE (RFX-225, dev-1 round 056)
=====================================================================
`reeflex.policy/irreversible_protected_asset_prod` (R6, RFX-153, PR #100) and
`reeflex.policy/authority_change_prod` (R7, RFX-128, PR #118) were written
against the same main, in different branches, weeks apart. Each is correct
alone. Both bodies end with a hand-written guard list, and neither list can
name the other rule, because when each was written the other did not exist:

    tree                       decision for ability `ssh/revoke-key`,
                               ref /srv/prod/ssh/authorized_keys,
                               irreversible + single + production
    -------------------------  -----------------------------------------
    main                       allow / default_allow     <- the defect both
                                                            PRs exist to fix
    main + R6 only             require_approval / irreversible_protected_asset_prod
    main + R7 only             require_approval / authority_change_prod
    main + BOTH                *** eval_conflict_error -> HTTP 500 ***

R6's own test file states the claim "R6 sits LAST among the holds, so it can
only ever convert an ALLOW into a hold". That was true when it was written.
R7 also sits last. Two rules cannot both be last.

WHAT WAS GREEN OVER IT, measured on the 20-PR merge:
  * `opa check reeflex-core/policy/`            exit 0
  * `opa test reeflex-core/policy/`             PASS 71/71
  * `python -m unittest discover` (core)        OK
The instruments are not broken -- `opa test` DOES exit 2 when a test touches a
conflicting envelope. Nothing in the pack's own suite touched one. That is the
gap this file closes.

WHY PYTHON AND NOT A `_test.rego`
=================================
A Rego version was written first and rejected on measurement. `opa test`
imposes a 5-second budget PER TEST RULE, and a grid wide enough to be worth
having exceeds it on a pack that has protected.rego in it. The result is
`eval_cancel_error: context deadline exceeded` -- a RED suite that names no
policy defect, on trees whose policy is fine (measured: green on main, timeout
on #100-alone and on #118-alone). A tripwire that reddens for its own runtime
is worse than no tripwire. One bulk `opa eval` from Python has no such cap,
takes ~1 subprocess, and -- the real reason -- can BISECT and print the exact
envelope, which `eval_conflict_error at reeflex.rego:331` cannot.

WHAT THIS FILE DOES NOT CLAIM
=============================
It is a grid, not a proof. An envelope shape outside the grid -- a rule keyed
on a field no dimension here varies -- can still collide unseen. When you add a
rule that reads a NEW input field, add that field as a DIMENSION below; the
grid is the thing to extend, not a list of cases to append to.

It also says nothing about WHICH rule should win a genuine tie. That is a
precedence decision for whoever owns the two rules. This file only insists that
the pack picks one.

Run:
  cd reeflex-core
  python -m unittest tests.test_decision_totality -v
"""

from __future__ import annotations

import itertools
import json
import os
import pathlib
import subprocess
import sys
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.opa import _opa_bin, _policy_dir  # noqa: E402  -- same resolution as core itself

#: The three verdicts SPEC defines. A rule answering anything else is a wire
#: contract break, not a precedence question.
SPEC_VERDICTS = {"allow", "deny", "require_approval"}

# ---------------------------------------------------------------------------
# The grid dimensions. ADD A DIMENSION when you add a rule reading a new field.
# ---------------------------------------------------------------------------

REVERSIBILITY = ["irreversible", "reversible"]
BLAST_RADIUS = ["single", "broad", "systemic"]
EXTERNALITY = ["internal", "outbound"]
ENVIRONMENT = ["production", "staging"]
VERB = ["read", "delete"]

#: One ability per signal family in authority.rego (R7), plus a control that
#: must match no family at all. Keep this in step with authority.rego's lists:
#: a family with no representative here is a family this grid cannot see.
ABILITY = [
    "ssh/revoke-key",     # credential_signals + authority_signals
    "iam/delete-role",    # authority_signals
    "secrets/purge",      # credential_signals
    "plugin/uninstall",   # executable_signals
    "files/remove",       # CONTROL -- matches no signal family
]

#: Refs on both sides of protected.rego's `protected_assets` prefix list (R6),
#: including the empty ref, which the strict posture treats as unknown rather
#: than safe.
REF = [
    "/srv/prod/db.sqlite",   # protected
    "/tmp/scratch.txt",      # not protected
    "",                      # absent / unknown
]

#: 2 * 3 * 2 * 2 * 2 * 5 * 3
EXPECTED_GRID_SIZE = 720


def _envelope(rev, blast, ext, env, verb, ability, ref, i):
    """An Action Envelope in the shape the reference adapters emit."""
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:totality-grid",
            "on_behalf_of": "user:synthetic",
            # One session per point. A shared session_id would let R5's
            # cumulative budgets trip partway through the grid and silently
            # change which rule is under test.
            "session_id": f"totality_grid_{i:05d}",
        },
        "action": {"namespace": "grid", "verb": verb, "ability": ability},
        "target": {"kind": "command", "ref": ref, "environment": env},
        "params": {},
        "magnitude": {"count": 1},
        "axes": {"reversibility": rev, "blast_radius": blast, "externality": ext},
        "approval": {"present": False},
        "context": {},
        "meta": {
            "timestamp": "2026-09-07T00:00:00Z",
            "nonce": f"grid{i:05d}",
            "signature": "ed25519:grid_placeholder",
        },
    }


def _grid():
    return [
        _envelope(rev, blast, ext, env, verb, ability, ref, i)
        for i, (rev, blast, ext, env, verb, ability, ref) in enumerate(
            itertools.product(
                REVERSIBILITY, BLAST_RADIUS, EXTERNALITY, ENVIRONMENT, VERB, ABILITY, REF
            )
        )
    ]


#: Collect a decision for every envelope POSITIVELY. The negated formulation
#: (`not data.reeflex.policy.decision`) SWALLOWS an eval_conflict_error and
#: returns a false green -- pinned in
#: test_the_negated_formulation_is_vacuous below. Do not "simplify" this.
_QUERY = (
    "out := [d | some e in input.grid; d := data.reeflex.policy.decision with input as e]"
)

_NEGATED_QUERY = (
    "out := [i | some i, e in input.grid; not data.reeflex.policy.decision with input as e]"
)


def _eval(envelopes, query=_QUERY):
    """One `opa eval` over a list of envelopes.

    Returns (ok, payload). ok is False when OPA reported an error -- payload is
    then the error list, which is what an eval_conflict_error arrives as.
    """
    proc = subprocess.run(
        [
            _opa_bin(), "eval",
            "--data", _policy_dir(),
            "--stdin-input",
            "--format", "json",
            query,
        ],
        input=json.dumps({"grid": envelopes}),
        capture_output=True,
        text=True,
        timeout=300,
    )
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:  # pragma: no cover -- opa itself broke
        raise AssertionError(
            f"opa eval produced no JSON. rc={proc.returncode} "
            f"stdout={proc.stdout[:400]!r} stderr={proc.stderr[:400]!r}"
        )
    if payload.get("errors"):
        return False, payload["errors"]
    results = payload.get("result") or []
    if not results:
        return True, []
    return True, results[0]["bindings"]["out"]


def _bisect_to_one(envelopes):
    """Narrow a failing set to a single offending envelope.

    ~log2(n) extra `opa eval` calls. The point of this function is the error
    message: `eval_conflict_error at reeflex.rego:331` names a line, not an
    envelope, and the line is the same for every collision in the pack.
    """
    lo = list(envelopes)
    while len(lo) > 1:
        mid = len(lo) // 2
        left, right = lo[:mid], lo[mid:]
        if not _eval(left)[0]:
            lo = left
            continue
        if not _eval(right)[0]:
            lo = right
            continue
        # Neither half fails alone: the failure is not per-envelope (it would
        # be a pack that only breaks on some ordering). Report the pair.
        break
    return lo


class TestDecisionTotality(unittest.TestCase):
    """The pack must answer exactly one decision for every envelope."""

    def test_the_grid_is_not_vacuous(self) -> None:
        """A coverage assertion over an empty set is green forever (RFX-217)."""
        grid = _grid()
        self.assertEqual(len(grid), EXPECTED_GRID_SIZE)
        self.assertEqual(
            len({json.dumps(e, sort_keys=True) for e in grid}),
            EXPECTED_GRID_SIZE,
            "grid contains duplicate points -- a dimension is not varying",
        )

    def test_every_envelope_yields_exactly_one_decision(self) -> None:
        """THE assertion. A missing precedence guard fails here and nowhere else."""
        grid = _grid()
        ok, payload = _eval(grid)
        if not ok:
            offenders = _bisect_to_one(grid)
            detail = "\n".join(json.dumps(e, indent=2, sort_keys=True) for e in offenders)
            self.fail(
                "reeflex.policy/decision did not resolve to a single value for "
                f"{len(grid)} probed envelopes.\n"
                f"OPA reported: {json.dumps(payload)[:600]}\n\n"
                "A complete rule with two satisfiable bodies is an "
                "eval_conflict_error, which core serves as HTTP 500 / "
                "reeflex.core/fail_closed -- no decision at all for this shape.\n"
                "Every `decision` body must guard against every other rule that "
                "can fire on the same envelope.\n\n"
                f"Narrowed to {len(offenders)} envelope(s):\n{detail}"
            )
        self.assertEqual(
            len(payload), len(grid),
            f"{len(grid) - len(payload)} of {len(grid)} envelopes produced no "
            "well-formed decision",
        )

    def test_every_decision_is_a_spec_verdict_under_a_namespaced_rule(self) -> None:
        """Shape of what the grid produced -- runs off the same single eval."""
        grid = _grid()
        ok, decisions = _eval(grid)
        self.assertTrue(ok, f"pack did not evaluate: {json.dumps(decisions)[:400]}")
        verdicts = {d["decision"] for d in decisions}
        self.assertEqual(
            verdicts - SPEC_VERDICTS, set(),
            f"rule(s) answered a verdict SPEC does not define: {verdicts}",
        )
        for d in decisions:
            self.assertTrue(
                d["rule"].startswith("reeflex.policy/"),
                f"rule id is not namespaced: {d['rule']!r}",
            )
            self.assertTrue(d["reason"], f"rule {d['rule']!r} carries an empty reason")

    def test_the_negated_formulation_is_vacuous(self) -> None:
        """Pin the trap, so the next person sees it measured rather than argued.

        `not data.reeflex.policy.decision` returns an EMPTY set both on a total
        pack and on one with a genuine eval_conflict_error -- the error is
        swallowed by the negation. Measured on the R6xR7 merge: this query said
        "nothing wrong" while the positive query above ERRORed on the same
        input. This test asserts only that the negated query is silent; it must
        never be used as the totality check.
        """
        ok, payload = _eval(_grid()[:2], query=_NEGATED_QUERY)
        self.assertTrue(ok, f"negated query itself errored: {payload}")
        self.assertEqual(
            payload, [],
            "the negated formulation reported something -- if this ever fails, "
            "re-measure the claim in this docstring before trusting it",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
