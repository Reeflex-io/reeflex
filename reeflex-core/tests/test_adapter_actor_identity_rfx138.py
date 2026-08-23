"""
test_adapter_actor_identity_rfx138.py — check 8 is only worth what the
adapters put in `agent.id`.

WHY THIS LIVES IN CORE'S SUITE
==============================
It is core's guard that goes vacuous, and core's suite is the one CI runs
(.github/workflows/ci.yml runs `python -m unittest discover` over
reeflex-core/tests and nothing else; the adapter suites run under gate.py).
A rule that only the gate can see is a rule that a PR can merge past.

THE DEFECT THIS PINS
====================
RFX-138 closed with check 8: a resubmission is refused
`reeflex_hold_actor_mismatch` when `approval_actor_key(envelope)` — the
ordered pair `(agent.id, agent.on_behalf_of)` — differs from the key of the
envelope the hold stored.  Every test that proved it, including
tests/test_approval_actor_binding_rfx138.py next door, HAND-WROTE two distinct
`agent.id` values.  The shipped adapters did not:

  reeflex-claude     agent.id = "agent:claude-code"   (module constant)
  reeflex-mcp        agent.id = "agent:mcp-client"    (all three anonymous
                                                       branches)
  n8n-nodes-reeflex  agent.id default 'agent:n8n'     (node parameter)

So for two agents of the same kind behind one gate the key compared EQUAL,
check 8 could not separate them, and agent B spent the approval a human
granted to agent A.  Measured over HTTP against a core built from 759b83f:
the substitution was ALLOWED for reeflex-claude and for reeflex-mcp, and the
same two sessions with `agent.id` REMOVED were denied
`reeflex_hold_actor_mismatch` — core's session fallback binding correctly on
its own.  The constant was the whole cause.

WHAT EACH TEST CAN AND CANNOT SEE — stated, because the instrument is the
thing that failed last time (RFX-139, RFX-217):

  reeflex-claude   VALUE-level.  Its envelope builder is stdlib-only, so this
                   suite can import it and compare the real keys.
  reeflex-mcp      STRUCTURE-level only.  reeflex_mcp.gateway imports
                   `mcp.server.fastmcp`, which core's CI job does not install,
                   so this file asserts that no anonymous branch RETURNS A
                   BARE CONSTANT as agent_id.  That cannot see the value.  The
                   value-level test is reeflex-mcp/tests/
                   test_agent_identity_rfx138.py, which gate.py runs in that
                   package's own venv.
  n8n              STRUCTURE-level only, over the .ts source: n8n is not
                   running here.  The behaviour is asserted by that package's
                   own vitest suite.

Run:
  cd reeflex-core
  python -m unittest tests.test_adapter_actor_identity_rfx138 -v
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import sys
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.principal import approval_actor_key

#: The monorepo root — this file lives at <root>/reeflex-core/tests/.
_MONOREPO = _repo_root.parent

_CLAUDE_ENVELOPE_PY = _MONOREPO / "reeflex-claude" / "reeflex_claude" / "envelope.py"
_MCP_GATEWAY_PY = _MONOREPO / "reeflex-mcp" / "reeflex_mcp" / "gateway.py"
_N8N_NODE_TS = (_MONOREPO / "n8n-nodes-reeflex" / "nodes" / "ReeflexGate"
                / "ReeflexGate.node.ts")

#: What classify.py would return.  Hand-built ON PURPOSE: the agent block does
#: not read any of it, and building it here keeps this test free of a second
#: adapter module.  If the agent block ever starts depending on the
#: classification, this dict is the thing that has to grow.
_CLS = {
    "verb": "delete",
    "reversibility": "irreversible",
    "blast_radius": "broad",
    "externality": "internal",
    "magnitude_count": 901,
    "target_kind": "file",
    "target_ref": "/srv/prod/data",
    "danger_signature": None,
    "classification_tier": "explicit",
    "command_preview": "rm -rf /srv/prod/data",
    "file_path": None,
}


def _load_by_path(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _claude_envelope(session_id: str) -> dict:
    """An envelope from the SHIPPED reeflex-claude builder, by path.

    By path and not by import name: the shared venv on a dev box can carry an
    editable install pointing at a different worktree, and then this test would
    grade somebody else's checkout (RFX-172).
    """
    mod = _load_by_path(_CLAUDE_ENVELOPE_PY, "_rfx138_claude_envelope")
    return mod.build_envelope(
        {"session_id": session_id, "tool_name": "Bash",
         "tool_input": {"command": "rm -rf /srv/prod/data"}, "cwd": "/srv/prod"},
        _CLS,
    )


def _mcp_derivation_returns() -> list[ast.expr]:
    """The agent_id expression of every `return` in _derive_session_and_agent.

    The documented contract of that method is
    `(session_id, agent_id, on_behalf_of)`, so element 1 is the agent id.
    """
    src = _MCP_GATEWAY_PY.read_text()
    fn = None
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == "_derive_session_and_agent":
            fn = node
    assert fn is not None, "_derive_session_and_agent not found in gateway.py"
    out = []
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Tuple):
            if len(sub.value.elts) == 3:
                out.append(sub.value.elts[1])
    return out


class TestTheFilesAreWhereThisTestThinks(unittest.TestCase):
    """A missing adapter must FAIL, never skip.

    Every file this suite grades is tracked in this repo.  A skip on a missing
    path is how a census quietly starts covering nothing — RFX-217's shape, and
    the reason the count is asserted rather than assumed.
    """

    def test_every_graded_adapter_source_exists(self):
        for path in (_CLAUDE_ENVELOPE_PY, _MCP_GATEWAY_PY, _N8N_NODE_TS):
            self.assertTrue(path.is_file(), "graded source is missing: %s" % path)


class TestTheComparisonCanFail(unittest.TestCase):
    """NON-VACUITY, first, because this whole file is a comparison.

    If `approval_actor_key` ever stopped distinguishing anything — or started
    distinguishing everything — the tests below would pass while measuring
    nothing.  Both directions are pinned here against fixtures, not adapters.
    """

    def test_a_shared_constant_id_compares_EQUAL(self):
        """The exact defect shape.  If this ever fails, the tests below are
        no longer evidence about anything."""
        a = {"agent": {"id": "agent:some-kind", "session_id": "sess-a"}}
        b = {"agent": {"id": "agent:some-kind", "session_id": "sess-b"}}
        self.assertEqual(approval_actor_key(a), approval_actor_key(b))

    def test_two_distinct_ids_compare_DIFFERENT(self):
        a = {"agent": {"id": "agent:kind/one", "session_id": "sess-a"}}
        b = {"agent": {"id": "agent:kind/two", "session_id": "sess-a"}}
        self.assertNotEqual(approval_actor_key(a), approval_actor_key(b))


class TestClaudeAdapterActorIdentity(unittest.TestCase):
    """VALUE-level: the real builder, the real key function."""

    def test_two_sessions_are_two_actors(self):
        alpha = _claude_envelope("alpha-session-uuid")
        beta = _claude_envelope("beta-session-uuid")
        self.assertNotEqual(
            approval_actor_key(alpha), approval_actor_key(beta),
            "two Claude Code agents produce the SAME actor key %r — check 8 "
            "cannot separate them, so either can spend the other's approval "
            "(RFX-138)" % (approval_actor_key(alpha),),
        )

    def test_the_same_session_is_the_same_actor(self):
        """The floor.  An id that changed per CALL would pass the test above
        and deny the agent a human actually approved — worse than the bug."""
        first = _claude_envelope("one-session-uuid")
        second = _claude_envelope("one-session-uuid")
        self.assertEqual(approval_actor_key(first), approval_actor_key(second))

    def test_the_kind_is_still_readable_in_the_id(self):
        """An auditor must still be able to see WHAT acted, not only which
        instance; and agent.id must visibly join agent.session_id."""
        env = _claude_envelope("joinable-session-uuid")
        self.assertTrue(env["agent"]["id"].startswith("agent:claude-code/"))
        self.assertIn("joinable-session-uuid", env["agent"]["id"])
        self.assertIn("joinable-session-uuid", env["agent"]["session_id"])


class TestMcpAdapterActorIdentity(unittest.TestCase):
    """STRUCTURE-level.  See the module docstring for what this cannot see."""

    def test_no_anonymous_branch_returns_a_bare_constant(self):
        returns = _mcp_derivation_returns()
        self.assertGreaterEqual(
            len(returns), 3,
            "expected at least the stdio / transport-session / unmapped "
            "branches; found %d — the shape this test reads has changed and "
            "the assertion below may be grading nothing" % len(returns),
        )
        constants = [r.value for r in returns if isinstance(r, ast.Constant)]
        self.assertEqual(
            constants, [],
            "gateway._derive_session_and_agent() returns a CONSTANT agent_id "
            "%r. Every anonymous front client would then share one actor key "
            "and check 8 could not separate them (RFX-138). Derive it from "
            "the session that branch already computes." % (constants,),
        )


class TestN8nNodeActorIdentity(unittest.TestCase):
    """STRUCTURE-level.  n8n is not running here."""

    def test_the_agent_id_default_is_per_execution(self):
        src = _N8N_NODE_TS.read_text()
        m = re.search(r"name:\s*'agentId'.*?default:\s*'([^']*)'", src, re.S)
        self.assertIsNotNone(m, "the Agent ID node parameter was not found")
        default = m.group(1)
        self.assertTrue(
            default.startswith("="),
            "the Agent ID default %r is a plain constant: every execution of "
            "every workflow would share one actor key (RFX-138). Session ID "
            "on the same node already defaults to '={{$execution.id}}'."
            % default,
        )
        self.assertIn("$execution.id", default)


if __name__ == "__main__":
    unittest.main()
