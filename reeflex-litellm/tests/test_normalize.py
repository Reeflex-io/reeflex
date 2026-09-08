"""NORMALIZE: a gateway tool call expressed in the classifier's vocabulary."""

from __future__ import annotations

import json

from reeflex_claude import classify

from reeflex_litellm import normalize

import stubcore


def n(name, args, call_id="call_1"):
    return normalize.normalize_tool_call(stubcore.tool_call(call_id, name, args))


# -- the faithful mappings ---------------------------------------------------

def test_a_shell_tool_under_any_name_maps_to_bash_and_keeps_the_command():
    for name in ("run_shell", "execute_command", "bash_tool", "terminal",
                 "acme_exec", "run_code"):
        c = n(name, {"command": "rm -rf /var/lib/data"})
        assert c.tool_name == "Bash", name
        assert c.mapped is True
        assert c.tool_input["command"] == "rm -rf /var/lib/data", name
        # The gateway's own name survives -- it is what reaches action.ability.
        assert c.gateway_tool == name


def test_the_command_argument_is_accepted_under_its_common_aliases():
    for key in ("command", "cmd", "shell_command", "script", "code"):
        c = n("run_shell", {key: "rm -rf /var/lib/data"})
        assert c.tool_name == "Bash", key
        assert c.tool_input["command"] == "rm -rf /var/lib/data", key


def test_an_argument_that_is_a_command_maps_even_under_an_opaque_tool_name():
    c = n("acme_infra_runner", {"cmd": "rm -rf /"})
    assert c.tool_name == "Bash"
    assert c.mapping_source == "name_and_shape"
    assert c.tool_input["command"] == "rm -rf /"


def test_write_edit_read_fetch_and_search_map_on_name_plus_shape():
    cases = [
        ("write_file", {"path": "/etc/nginx/nginx.conf", "text": "x"}, "Write"),
        ("apply_diff", {"file_path": "/srv/app/main.py"}, "Edit"),
        ("read_file", {"path": "/etc/hosts"}, "Read"),
        ("fetch_url", {"url": "https://example.test/x"}, "WebFetch"),
        ("web_search", {"q": "reeflex"}, "WebSearch"),
    ]
    for name, args, expected in cases:
        c = n(name, args)
        assert c.tool_name == expected, (name, c.tool_name)
        assert c.mapped is True


def test_the_projected_keys_are_the_ones_the_classifier_reads():
    c = n("write_file", {"path": "/etc/passwd", "text": "root:x"})
    assert c.tool_input["file_path"] == "/etc/passwd"
    assert c.tool_input["content"] == "root:x"
    # and nothing was dropped
    assert c.tool_input["path"] == "/etc/passwd"


# -- the conservative refusals to guess -------------------------------------

def test_a_shell_name_with_no_command_argument_is_NOT_mapped_to_bash():
    """Name and shape must agree. `run_shell(target="db")` is not a command."""
    c = n("run_shell", {"target": "db"})
    assert c.mapped is False
    assert c.mapping_source == "unmapped"
    assert c.tool_name == "run_shell"


def test_a_delete_tool_is_left_unmapped_rather_than_turned_into_a_fake_rm():
    """RFX-144/145/146: price the action, not a command we invented for it.

    `delete_file(path=...)` carries no command string, so mapping it to Bash
    would mean SYNTHESIZING `rm -- <path>` and putting a command the model never
    proposed into context.command_preview -- i.e. into the line a human reads in
    the audit record. It goes down the unknown path instead, which asks a human.
    """
    c = n("delete_file", {"path": "/srv/data/customers.db"})
    assert c.mapped is False
    assert c.tool_name == "delete_file"
    cls = classify.classify(c.tool_name, c.tool_input)
    # The unknown-tool path, which is a refusal-or-hold shape, never an allow.
    assert cls["reversibility"] == "irreversible"
    assert cls["blast_radius"] in ("broad", "systemic")


def test_a_tool_call_with_unparseable_arguments_is_still_ruled_on():
    """Skipping a call the adapter cannot read is the fail-open. It is refused
    the same way any other unknown action is: by being ruled on."""
    raw = {"id": "call_9", "type": "function",
           "function": {"name": "run_shell", "arguments": "{not json"}}
    c = normalize.normalize_tool_call(raw)
    assert c.arguments_ok is False
    assert c.mapped is False
    assert c.tool_name == "run_shell"


def test_a_non_object_arguments_payload_is_not_readable():
    raw = {"id": "call_9", "type": "function",
           "function": {"name": "run_shell", "arguments": json.dumps("rm -rf /")}}
    c = normalize.normalize_tool_call(raw)
    assert c.arguments_ok is False


def test_an_argument_less_tool_call_is_readable_and_not_an_error():
    raw = {"id": "call_9", "type": "function",
           "function": {"name": "get_time", "arguments": ""}}
    c = normalize.normalize_tool_call(raw)
    assert c.arguments_ok is True
    assert c.mapped is False


def test_a_malformed_tool_call_object_still_yields_a_normalized_call():
    for raw in ({}, {"function": None}, {"id": None}, None):
        c = normalize.normalize_tool_call(raw)
        assert c.gateway_tool  # never empty -- "unknown" at worst
        assert c.mapped is False


# -- the operator map --------------------------------------------------------

def test_the_operator_map_beats_every_heuristic(monkeypatch):
    monkeypatch.setenv("REEFLEX_LITELLM_TOOL_MAP",
                       json.dumps({"acme_runner": "Bash"}))
    c = n("acme_runner", {"payload": "rm -rf /"})
    assert c.tool_name == "Bash"
    assert c.mapping_source == "operator_map"


def test_the_operator_map_can_be_a_file_path(tmp_path, monkeypatch):
    p = tmp_path / "toolmap.json"
    p.write_text(json.dumps({"acme_runner": "Read"}))
    monkeypatch.setenv("REEFLEX_LITELLM_TOOL_MAP", str(p))
    assert n("acme_runner", {"x": 1}).tool_name == "Read"


def test_a_map_naming_a_tool_the_classifier_does_not_know_is_ignored(monkeypatch):
    """An unknown value must not become a mapping that LOOKS deliberate."""
    monkeypatch.setenv("REEFLEX_LITELLM_TOOL_MAP",
                       json.dumps({"acme_runner": "Teleport"}))
    c = n("acme_runner", {"x": 1})
    assert c.mapped is False
    assert c.mapping_source == "unmapped"


def test_a_malformed_map_is_ignored_and_does_not_take_the_seat_offline(monkeypatch):
    monkeypatch.setenv("REEFLEX_LITELLM_TOOL_MAP", "{ this is not json")
    c = n("run_shell", {"command": "ls"})
    assert c.tool_name == "Bash"  # heuristics still work
    assert normalize.operator_tool_map() == {}


def test_the_map_is_reread_so_an_edit_needs_no_proxy_restart(tmp_path, monkeypatch):
    p = tmp_path / "toolmap.json"
    p.write_text(json.dumps({"acme_runner": "Read"}))
    monkeypatch.setenv("REEFLEX_LITELLM_TOOL_MAP", str(p))
    assert n("acme_runner", {"x": 1}).tool_name == "Read"
    p.write_text(json.dumps({"acme_runner": "Write"}))
    assert n("acme_runner", {"x": 1}).tool_name == "Write"


# -- shape tolerance --------------------------------------------------------

class _Fn:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _Call:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = _Fn(name, arguments)


def test_an_object_shaped_tool_call_reads_the_same_as_a_dict_shaped_one():
    """LiteLLM hands the hook pydantic models in-process and plain dicts on the
    wire. One code path has to read both, or the suite tests a shape the proxy
    never produces."""
    obj = normalize.normalize_tool_call(
        _Call("call_1", "run_shell", json.dumps({"command": "rm -rf /"})))
    dct = n("run_shell", {"command": "rm -rf /"})
    assert (obj.tool_name, obj.tool_input["command"], obj.call_id) == \
           (dct.tool_name, dct.tool_input["command"], dct.call_id)


def test_normalize_tool_calls_preserves_order():
    calls = [stubcore.tool_call("a", "read_file", {"path": "/etc/hosts"}),
             stubcore.tool_call("b", "run_shell", {"command": "rm -rf /"})]
    out = normalize.normalize_tool_calls(calls)
    assert [c.call_id for c in out] == ["a", "b"]
