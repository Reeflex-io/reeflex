"""
test_agent_identity_rfx138.py -- two anonymous front clients are two actors.

WHY THIS EXISTS
===============
reeflex-core refuses a hold resubmission whose actor differs from the actor
the hold was raised for: it compares the ORDERED pair
(agent.id, agent.on_behalf_of) against the held envelope -- SPEC section 5.1,
condition 3.

`_derive_session_and_agent()` used to return the bare constant
"agent:mcp-client" on all three anonymous branches (stdio, HTTP with a
transport session, HTTP with none).  `on_behalf_of` is None on all three.  So
every anonymous client this gateway serves presented the identical pair, core
had nothing to compare, and an approval a human granted to client A could be
spent by client B.  Measured over HTTP against a real core: with the constant
the substitution was ALLOWED; with a per-session id it is denied
`reeflex_hold_actor_mismatch`.

This adapter is the one that matters most for that defect, because it is the
one that RESUBMITS: enforce mode attaches `approval.present=true` and a
`hold_id` from `pending_holds` and re-decides (gateway.py, enforce mode).

WHAT IS NOT CHANGED, AND WHY
============================
The configured-bearer branch (`clients:` in registry.py) still uses the mapped
identity for both fields.  That identity is durable across reconnects, which
is the case core's actor key is built for -- it excludes session_id when the
agent is named precisely so a client that restarts inside a hold's TTL is not
wrongly denied.  The anonymous branches have no such durability to protect:
`pending_holds` is keyed on the session and held in memory, so a reconnect has
already lost the hold.  test_configured_identity_is_unchanged pins that.
"""

from __future__ import annotations

import unittest

from reeflex_mcp.gateway import Gateway
from reeflex_mcp.normalize import build_envelope


class _NoRequestContext:
    @property
    def request_context(self):
        raise LookupError


class _StdioMcp:
    _mcp_server = _NoRequestContext()


def _http_mcp(headers: dict):
    class _Request:
        pass

    _Request.headers = headers

    class _Ctx:
        request = _Request

    class _Srv:
        request_context = _Ctx()

    class _HttpMcp:
        _mcp_server = _Srv()

    return _HttpMcp()


class _StubGateway:
    """Only the three attributes the derivation touches.

    The real method is called unbound off the real class, so what runs is the
    shipped code, not a copy of it.
    """

    def __init__(self, mcp, stdio_session_id="stdio:stub", gw_config=None):
        self.mcp = mcp
        self._stdio_session_id = stdio_session_id
        self.gw_config = gw_config


def _derive(stub):
    return Gateway._derive_session_and_agent(stub)


def _actor_pair(session_id, agent_id, on_behalf_of):
    """The pair SPEC section 5.1 condition 3 binds an approval to, taken off a
    real envelope so the test grades what actually goes on the wire."""
    env = build_envelope(
        session_id=session_id,
        agent_id=agent_id,
        on_behalf_of=on_behalf_of,
        upstream_name="wp",
        target_system="wordpress",
        target_environment="production",
        tool_name="delete_posts",
        arguments={"ids": [1, 2, 3]},
    )
    return (env["agent"]["id"], env["agent"]["on_behalf_of"])


class TestAnonymousFrontClientsAreDistinguishable(unittest.TestCase):

    def test_two_http_clients_are_two_actors(self):
        """The defect: two front clients on ONE gateway, separated only by the
        transport session."""
        a = _derive(_StubGateway(_http_mcp({"authorization": "",
                                            "mcp-session-id": "transport-alpha"})))
        b = _derive(_StubGateway(_http_mcp({"authorization": "",
                                            "mcp-session-id": "transport-beta"})))
        self.assertNotEqual(
            _actor_pair(*a), _actor_pair(*b),
            "two anonymous front clients emit the same actor pair %r, so core "
            "cannot tell them apart and either can spend the other's approval "
            "(RFX-138)" % (_actor_pair(*a),),
        )

    def test_two_stdio_gateways_are_two_actors(self):
        a = _derive(_StubGateway(_StdioMcp(), stdio_session_id="stdio:proc-a"))
        b = _derive(_StubGateway(_StdioMcp(), stdio_session_id="stdio:proc-b"))
        self.assertNotEqual(_actor_pair(*a), _actor_pair(*b))

    def test_the_unmapped_branch_is_distinguishable_too(self):
        """No Mcp-Session-Id at all: the branch that mints a random session.
        It was the third caller of the same constant."""
        a = _derive(_StubGateway(_http_mcp({"authorization": "",
                                            "mcp-session-id": ""})))
        b = _derive(_StubGateway(_http_mcp({"authorization": "",
                                            "mcp-session-id": ""})))
        self.assertNotEqual(_actor_pair(*a), _actor_pair(*b))

    def test_the_same_client_is_the_same_actor(self):
        """THE FLOOR.  An id that varied per CALL would satisfy every test
        above and deny the client a human actually approved -- and this is the
        adapter that resubmits, so that wrong deny would be reachable."""
        headers = {"authorization": "", "mcp-session-id": "transport-stable"}
        a = _derive(_StubGateway(_http_mcp(headers)))
        b = _derive(_StubGateway(_http_mcp(headers)))
        self.assertEqual(_actor_pair(*a), _actor_pair(*b))

    def test_the_kind_is_still_readable_and_joins_the_session(self):
        session_id, agent_id, _ = _derive(_StubGateway(
            _http_mcp({"authorization": "", "mcp-session-id": "readable"})))
        self.assertTrue(agent_id.startswith("agent:mcp-client/"), agent_id)
        self.assertIn(session_id, agent_id)

    def test_configured_identity_is_unchanged(self):
        """A `clients:` bearer identity is durable, so it keeps core's restart
        tolerance: id and session are the mapped value, exactly as before."""
        import reeflex_mcp.gateway as gw_mod

        original = gw_mod.regcfg.session_id_for_token
        gw_mod.regcfg.session_id_for_token = lambda cfg, bearer: "client:team-a"
        try:
            session_id, agent_id, obo = _derive(_StubGateway(_http_mcp(
                {"authorization": "Bearer tok", "mcp-session-id": "ignored"})))
        finally:
            gw_mod.regcfg.session_id_for_token = original
        self.assertEqual((session_id, agent_id, obo),
                         ("client:team-a", "client:team-a", None))


if __name__ == "__main__":
    unittest.main()
