"""
test_agent_identity_rfx138.py -- two Claude Code agents are two actors.

WHY THIS EXISTS
===============
reeflex-core refuses a hold resubmission whose actor differs from the actor
the hold was raised for: it compares the ORDERED pair
(agent.id, agent.on_behalf_of) -- SPEC section 5.1, condition 3.

`agent.id` used to be the module constant "agent:claude-code", the same string
in every Claude Code process anywhere.  With `REEFLEX_CLAUDE_PRINCIPAL` unset
(the default) that made the pair identical for every agent this adapter
governs, so core's comparison had nothing to compare and an approval a human
granted to one agent could be spent by another.  Measured over HTTP against a
real core, not argued: with the constant the substitution was ALLOWED; with a
per-session id it is denied `reeflex_hold_actor_mismatch`.

WHAT THIS FILE CAN AND CANNOT SEE
=================================
It grades the ENVELOPE this adapter emits.  It does not run core, so it cannot
show the refusal itself -- that is
reeflex-core/tests/test_approval_actor_binding_rfx138.py, and end to end it is
the round's probe.  What it CAN do is keep the input to that refusal honest,
which is the half that was wrong.

The comparison below is written out here rather than imported from core: this
package does not depend on reeflex-core, and the pair it compares is stated
normatively in SPEC section 5.1 rather than being an implementation detail.
reeflex-core/tests/test_adapter_actor_identity_rfx138.py runs the real
`approval_actor_key` over this same builder, so the two stay joined.
"""

from __future__ import annotations

import os
import sys
import unittest

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude.classify import classify
from reeflex_claude.envelope import build_envelope


def _envelope(session_id: str) -> dict:
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /srv/prod/data"},
        "cwd": "/srv/prod",
    }
    return build_envelope(payload, classify(payload["tool_name"],
                                            payload["tool_input"]))


def _actor_pair(env: dict) -> tuple:
    """The pair SPEC section 5.1 condition 3 binds an approval to."""
    agent = env["agent"]
    return (agent.get("id"), agent.get("on_behalf_of"))


class TestTwoAgentsAreTwoActors(unittest.TestCase):

    def setUp(self):
        self._saved = os.environ.pop("REEFLEX_CLAUDE_PRINCIPAL", None)

    def tearDown(self):
        os.environ.pop("REEFLEX_CLAUDE_PRINCIPAL", None)
        if self._saved is not None:
            os.environ["REEFLEX_CLAUDE_PRINCIPAL"] = self._saved

    def test_two_sessions_produce_different_actor_pairs(self):
        """The defect, at the layer that caused it."""
        alpha = _actor_pair(_envelope("alpha-session-uuid"))
        beta = _actor_pair(_envelope("beta-session-uuid"))
        self.assertNotEqual(
            alpha, beta,
            "two Claude Code agents emit the same actor pair %r, so core "
            "cannot tell them apart and either can spend the other's "
            "approval (RFX-138)" % (alpha,),
        )

    def test_the_same_session_is_the_same_actor(self):
        """THE FLOOR, and it is not optional.

        An id that varied per CALL would satisfy the test above and deny the
        agent a human actually approved -- a wrong deny on the one path where
        a human explicitly said yes, which is a worse product than the bug.
        """
        self.assertEqual(_actor_pair(_envelope("one-session-uuid")),
                         _actor_pair(_envelope("one-session-uuid")))

    def test_the_id_still_names_the_kind_and_joins_the_session(self):
        """An auditor must still see WHAT acted, and be able to join the two
        identity fields on one value."""
        env = _envelope("joinable-uuid")
        self.assertTrue(env["agent"]["id"].startswith("agent:claude-code/"),
                        env["agent"]["id"])
        self.assertIn("joinable-uuid", env["agent"]["id"])
        self.assertIn("joinable-uuid", env["agent"]["session_id"])

    def test_principal_still_reaches_on_behalf_of(self):
        """The other half of the pair is unchanged by this fix."""
        os.environ["REEFLEX_CLAUDE_PRINCIPAL"] = "user:alice@customer.test"
        env = _envelope("obo-session-uuid")
        self.assertEqual(env["agent"]["on_behalf_of"], "user:alice@customer.test")

    def test_no_hold_is_ever_resubmitted_by_this_adapter(self):
        """The reason deriving the id from the session costs nothing HERE.

        Core deliberately leaves agent.session_id out of the actor key when
        the agent is named, so that an agent restarting inside a hold's 4h TTL
        is not wrongly denied.  A session-derived id opts this adapter out of
        that tolerance.  That is free only for as long as this adapter never
        re-submits a held action -- so the claim is asserted, not trusted:
        `approval.present` is hard-false and there is no hold_id path.

        If this test ever fails, the identity decision above has to be
        revisited together with the restart case.
        """
        env = _envelope("no-resubmit-uuid")
        self.assertFalse(env["approval"]["present"])
        self.assertIsNone(env["approval"].get("hold_id"))

        # And not only for THIS envelope: no module in the package builds a
        # dict that puts a non-null hold_id or a true `present` in an
        # approval block.  ast, not grep -- `"hold_id": None` is exactly the
        # line that proves the opposite, so a substring scan would read the
        # evidence as the defect.
        import ast
        src_dir = os.path.join(_PARENT, "reeflex_claude")
        offenders = []
        for name in sorted(os.listdir(src_dir)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(src_dir, name)
            with open(path) as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Dict):
                    continue
                for key, value in zip(node.keys, node.values):
                    if not (isinstance(key, ast.Constant)
                            and key.value in ("hold_id", "present")):
                        continue
                    is_null_or_false = (isinstance(value, ast.Constant)
                                        and value.value in (None, False))
                    if not is_null_or_false:
                        offenders.append("%s:%d %s" % (name, key.lineno,
                                                       key.value))
        self.assertEqual(
            offenders, [],
            "this adapter now builds an approval block with %s -- if it has "
            "grown a resubmission path, a session-derived agent.id turns an "
            "agent restart into a wrong DENY (RFX-138)" % offenders,
        )


if __name__ == "__main__":
    unittest.main()
