"""The mapping, scored on ActionEvents the real SDK built (tests/fixtures).

Each row asserts the classifier tool the event was routed to AND the axes the
envelope ends up with, so a routing change and a pricing change both show.
"""

from __future__ import annotations

import pytest

from reeflex_openhands import mapping

# (index in the fixture, classifier tool, verb, reversibility, blast, externality, overlays)
EXPECTED = [
    (0, "Bash", "delete", "irreversible", "broad", "internal", []),            # rm -rf ./build
    (1, "Bash", "emit", "irreversible", "broad", "outbound", []),             # git push --force
    (2, "Bash", "execute", "recoverable", "scoped", "outbound", ["network_shell:outbound"]),  # curl
    (3, "Bash", "read", "reversible", "single", "internal", []),               # ls -la
    (4, "Write", "create", "recoverable", "single", "internal", []),           # file_editor create
    (5, "Edit", "update", "recoverable", "single", "internal", []),            # str_replace
    (6, "Read", "read", "reversible", "single", "internal", []),               # view
    (7, "WebFetch", "read", "reversible", "single", "outbound", []),           # browser_navigate
    (8, "openhands__browser_click", "execute", "irreversible", "broad", "outbound", []),
    (9, "WebFetch", "read", "reversible", "single", "outbound", []),           # browser_get_content
]


@pytest.mark.parametrize("idx,tool,verb,rev,blast,ext,overlays", EXPECTED)
def test_recorded_sdk_event_maps_and_prices(recorded_events, shim, idx, tool, verb, rev,
                                           blast, ext, overlays):
    ev = shim(recorded_events["events"][idx])
    m = mapping.map_action(ev)
    assert m.classifier_tool == tool
    assert (m.cls["verb"], m.cls["reversibility"], m.cls["blast_radius"],
            m.cls["externality"]) == (verb, rev, blast, ext)
    assert m.overlays == overlays


def test_the_curl_overlay_is_needed_the_classifier_alone_says_internal():
    """Control for row 2: without the overlay the shared classifier prices a
    plain GET to an unknown host as `internal`.  If this ever fails, the
    classifier learned it and the overlay is redundant (harmless, tighten-only)."""
    from reeflex_claude.classify import classify
    assert classify("Bash", {"command": "curl https://unknown.example/"})["externality"] == "internal"


def test_mcp_events_carry_annotations_and_only_tighten(recorded_events, shim):
    anns = recorded_events["mcp_annotations"]
    events = {e["tool_name"]: e for e in recorded_events["events"][10:]}

    delete = mapping.map_action(shim(events["delete_records"]), annotations=anns["delete_records"])
    assert delete.classifier_tool == "mcp__openhands__delete_records"
    assert delete.cls["verb"] == "delete"
    assert delete.cls["reversibility"] == "irreversible"
    assert delete.mcp_annotations["destructiveHint"] is True

    # readOnlyHint is IGNORED unless trusted (RFX-173): the price stays the floor.
    search = mapping.map_action(shim(events["search_docs"]), annotations=anns["search_docs"])
    assert search.cls["reversibility"] == "irreversible"
    assert search.cls["verb"] != "read"
    trusted = mapping.map_action(shim(events["search_docs"]), annotations=anns["search_docs"],
                                 trust_mcp_annotations=True)
    assert (trusted.cls["verb"], trusted.cls["externality"]) == ("read", "outbound")
    assert "mcp_annotation:read_only(trusted)" in trusted.overlays

    bare = mapping.map_action(shim(events["sync_partner"]), annotations=None)
    assert bare.cls["externality"] == "outbound"
    assert bare.mcp_annotations is None


def test_destructive_hint_raises_a_price_the_classifier_set_low():
    class Ev:
        tool_name = "get_and_purge"
        id = "x"
        from openhands.sdk.mcp.definition import MCPToolAction
        action = MCPToolAction(data={})
    base = mapping.map_action(Ev())
    m = mapping.map_action(Ev(), annotations={"destructiveHint": True, "readOnlyHint": False})
    order = ("single", "scoped", "broad", "systemic")
    assert order.index(m.cls["blast_radius"]) >= order.index("broad")
    assert m.cls["reversibility"] == "irreversible"
    assert order.index(m.cls["blast_radius"]) >= order.index(base.cls["blast_radius"])


def test_terminal_input_goes_to_the_unknown_path_not_the_bash_classifier():
    class Ev:
        tool_name = "terminal"
        id = "x"
        action = type("A", (), {"model_dump": lambda self, mode="json": {
            "command": "y", "is_input": True}})()
    m = mapping.map_action(Ev())
    assert m.classifier_tool == "openhands__terminal_input"
    assert m.mapping_source == "unmapped"


def test_operator_tool_map_wins_and_rejects_unknown_targets():
    class Ev:
        tool_name = "acme_runner"
        id = "x"
        action = type("A", (), {"model_dump": lambda self, mode="json": {"cmd": "ls"}})()
    assert mapping.map_action(Ev(), tool_map={"acme_runner": "Bash"}).cls["verb"] == "read"
    m = mapping.map_action(Ev(), tool_map={"acme_runner": "NotAClassifierTool"})
    assert m.mapping_source == "unmapped"


@pytest.mark.parametrize("command,expect", [
    ("curl https://x.example", True), ("wget -q http://x", True), ("ssh host ls", True),
    ("git clone https://github.com/a/b", True), ("/usr/bin/curl x", True),
    ("ls -la", False), ("python curly.py", False), ("echo curling", False),
    ("cat ./sshd_config", False),
])
def test_network_shell_detector(command, expect):
    assert mapping.shell_touches_network(command) is expect


def test_envelope_shape_and_session_bound_agent_id(recorded_events, shim):
    m = mapping.map_action(shim(recorded_events["events"][0]))
    env = mapping.build_envelope(m, session_id="conv-1", agent_id="openhands",
                                 environment="production", cwd="/workspace", org_id="acme")
    assert env["agent"] == {"id": "agent:openhands/openhands/conv-1", "on_behalf_of": None,
                            "session_id": "openhands:conv-1"}
    assert env["action"] == {"namespace": "openhands", "verb": "delete",
                             "ability": "openhands/terminal"}
    assert env["target"]["environment"] == "production"
    assert env["context"]["command_preview"] == "rm -rf ./build"
    assert env["context"]["cwd"] == "/workspace"
    assert env["approval"]["present"] is False
    with pytest.raises(ValueError):
        mapping.build_envelope(m, session_id="", agent_id="a", environment="production")
    with pytest.raises(ValueError):
        mapping.build_envelope(m, session_id="s", agent_id="a", environment="prod")


def test_fixture_round_trips_through_the_real_sdk_models(recorded_events):
    """The fixture is SDK output, not hand-written: every row validates back
    into a real ActionEvent with its concrete action class."""
    pytest.importorskip("openhands.tools.terminal")
    import openhands.tools.browser_use  # noqa: F401  (registers the action kinds)
    import openhands.tools.file_editor  # noqa: F401
    import openhands.tools.terminal  # noqa: F401
    from openhands.sdk.event.llm_convertible import ActionEvent

    import copy
    for raw in recorded_events["events"]:
        kind = raw["action"]["kind"]
        ev = ActionEvent.model_validate(copy.deepcopy(raw))  # the validator pops `kind`
        assert ev.tool_name == raw["tool_name"]
        assert type(ev.action).__name__ == kind
        m = mapping.map_action(ev)
        assert m.cls["verb"]
