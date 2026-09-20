"""RFX-371 — a shipped demo must not pin a CONSTANT agent.id.

THE DEFECT THIS GUARDS
======================
Core binds a human's approval to the actor: `principal.approval_actor_key()`
folds `(agent.id, agent.on_behalf_of)` and `decide.py` check 8 refuses a
resubmission whose key differs from the held envelope's
(`reeflex_hold_actor_mismatch`).  `agent.session_id` is deliberately NOT in
that key when the agent is named — a hold lives hours and an agent that
restarts before resubmitting gets a new session, so binding it would deny an
action a human already approved.

The consequence, which is the whole of RFX-371: two parties carrying the SAME
`agent.id` are, to core, one agent that restarted.  Every importer of a demo
that pins a constant `agent.id` therefore shares one actor key, and the check
that exists to stop agent B spending agent A's approval cannot see a
difference.  Measured on main e175e4e through core's own `decide.process()`
over the real OPA pack, agent ids read out of the shipped workflow JSON:

    two importers, the shipped constant agent.id
      B resubmits A's approved hold  -> allow  reeflex.policy/approved_resubmission
      A then retries its own hold    -> deny   reeflex_hold_consumed
    the same two with a per-run agent id
      B resubmits A's approved hold  -> deny   reeflex_hold_actor_mismatch
      A restarts and resubmits       -> allow  reeflex.policy/approved_resubmission

So it is not only that the wrong importer is allowed; the importer the human
actually approved is then locked out, which is RFX-138's second half arriving
through the artefact rather than through the node default.

WHY THE EXISTING RFX-138 GUARD DID NOT COVER IT
===============================================
`scripts/repro-rfx138-adapter-actor-identity.py` reads the NODE DEFAULT
(`ReeflexGate.node.ts`, `agentId.default`), and that default is correct — it is
`=agent:n8n/{{$execution.id}}`.  An explicit value in an imported workflow
BEATS the node default (RFX-359's finding), and all five shipped demos set one.
A guard covers only what it reads: this one reads the demos.

ENUMERATED FROM THE DIRECTORY, NOT FROM A TABLE
===============================================
The subject set is `glob("demo*.workflow.json")`, so a sixth demo is a subject
the day it is added rather than the day someone remembers to list it.  A table
would make the sixth demo silently unscored, which is the RFX-359 shape.

Written as unittest TestCases: this root is run by
`unittest discover -s scripts/tests -t scripts` (gate.yml), where bare
pytest-style functions would collect zero tests and pass forever.
"""

import json
import os
import re
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEMOS = os.path.join(_REPO, "n8n-nodes-reeflex", "examples", "n8n")
_NODE_TS = os.path.join(
    _REPO, "n8n-nodes-reeflex", "nodes", "ReeflexGate", "ReeflexGate.node.ts")

_GATE_TYPE = "n8n-nodes-reeflex.reeflexGate"

#: n8n expression tokens that vary per run or per import. `$execution.id` is
#: the scope the node default already uses for agentId and the one the node's
#: own comment argues for ("budgets per workflow, approvals per execution").
#: `$workflow.id` and `$json.*` are accepted because a demo may legitimately
#: derive identity upstream, as demo2 does for its session id.
_PER_RUN_TOKENS = ("$execution.id", "$workflow.id", "$json.", "$runIndex")


def _gate_nodes(path):
    with open(path, encoding="utf-8") as fh:
        wf = json.load(fh)
    return [n for n in wf.get("nodes", []) if n.get("type") == _GATE_TYPE]


def _demo_files():
    return sorted(
        os.path.join(_DEMOS, n) for n in os.listdir(_DEMOS)
        if n.startswith("demo") and n.endswith(".workflow.json"))


class TestTheSubjectSetIsNotEmpty(unittest.TestCase):
    """A green run must mean 'every demo was scored', never 'no demo was found'.

    Both halves matter: zero demo files, or a demo file carrying no gate node,
    would make every assertion below vacuously true.
    """

    def test_there_are_demo_workflows_to_score(self):
        self.assertTrue(os.path.isdir(_DEMOS), "%s is not a directory" % _DEMOS)
        files = _demo_files()
        self.assertGreaterEqual(
            len(files), 5,
            "expected at least the five shipped demos, found %d in %s"
            % (len(files), _DEMOS))

    def test_every_demo_carries_at_least_one_gate_node(self):
        for path in _demo_files():
            with self.subTest(demo=os.path.basename(path)):
                self.assertTrue(
                    _gate_nodes(path),
                    "%s contains no %s node, so its agent identity is scored by "
                    "nothing" % (os.path.basename(path), _GATE_TYPE))


class TestNoDemoPinsAConstantAgentId(unittest.TestCase):
    """The property RFX-371 is about."""

    def test_every_gate_node_agent_id_varies_per_run(self):
        for path in _demo_files():
            demo = os.path.basename(path)
            for node in _gate_nodes(path):
                agent_id = (node.get("parameters") or {}).get("agentId")
                with self.subTest(demo=demo, node=node.get("name")):
                    self.assertIsNotNone(
                        agent_id,
                        "%s / %s sets no agentId, so it takes the node default "
                        "— fine, but say so explicitly rather than by omission"
                        % (demo, node.get("name")))
                    self.assertTrue(
                        agent_id.startswith("="),
                        "%s / %s pins the CONSTANT agent.id %r. Every importer "
                        "of this demo then shares one actor key, so core cannot "
                        "tell importer B from importer A restarting and B can "
                        "spend the approval a human granted A "
                        "(measured: allow / reeflex.policy/approved_resubmission). "
                        "Suffix it with a per-run token, e.g. "
                        "'=%s/{{$execution.id}}'."
                        % (demo, node.get("name"), agent_id, agent_id))
                    self.assertTrue(
                        any(tok in agent_id for tok in _PER_RUN_TOKENS),
                        "%s / %s sets agentId %r, which is an expression but "
                        "contains none of the per-run tokens %s — an expression "
                        "that evaluates to the same string for every importer "
                        "is the same defect wearing a '=' prefix."
                        % (demo, node.get("name"), agent_id,
                           list(_PER_RUN_TOKENS)))

    def test_the_session_id_is_still_workflow_scoped(self):
        """The over-block control, as a property rather than a comment.

        RFX-180..184 put Session ID at `={{$workflow.id}}` on purpose: the
        cumulative budgets accumulate per `agent.session_id`, so narrowing it to
        the execution would reset every budget on every run and demo1/demo2
        would stop demonstrating R5 at all. Fixing the agent id must not drag
        the session id along with it, and this is what would notice.
        """
        for path in _demo_files():
            demo = os.path.basename(path)
            for node in _gate_nodes(path):
                session_id = (node.get("parameters") or {}).get("sessionId")
                if session_id is None:
                    continue
                with self.subTest(demo=demo, node=node.get("name")):
                    self.assertNotIn(
                        "$execution.id", session_id,
                        "%s / %s narrowed sessionId to %r. The cumulative "
                        "budgets key on agent.session_id, so an execution-scoped "
                        "session resets them on every run."
                        % (demo, node.get("name"), session_id))


class TestTheNodeDefaultIsStillPerRun(unittest.TestCase):
    """The other plane, kept next to this one so the pair is visible.

    repro-rfx138-adapter-actor-identity.py already reads this default. It is
    re-read here for one reason: RFX-371 exists because the default and the
    shipped overrides were guarded by different things, and only one of them
    was guarded at all. If the default ever regresses to a constant, the demos
    that now take a per-run value would still pass the test above while every
    OTHER n8n user shared one actor key.
    """

    def test_the_agent_id_default_is_an_expression(self):
        with open(_NODE_TS, encoding="utf-8") as fh:
            src = fh.read()
        block = re.search(
            r"name:\s*'agentId'.*?default:\s*'([^']*)'", src, re.S)
        self.assertIsNotNone(
            block, "could not find the agentId default in %s — this test has "
                   "stopped measuring the node and must be repaired, not "
                   "deleted" % _NODE_TS)
        default = block.group(1)
        self.assertTrue(
            default.startswith("="),
            "the agentId default is the constant %r" % default)
        self.assertTrue(
            any(tok in default for tok in _PER_RUN_TOKENS),
            "the agentId default %r contains no per-run token %s"
            % (default, list(_PER_RUN_TOKENS)))


if __name__ == "__main__":
    unittest.main()
