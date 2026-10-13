"""
RFX-428 -- physical-impact mapping schema (PHYSICAL-IMPACT-SPEC draft
2026-10-13 section 1) and the two shipped OT packs, opcua.yaml and
homeassistant.yaml.

What is pinned here:
  * the schema: the five physical verbs, `safety_function`,
    `safety_function_when`, `cases`, `magnitude.physical`, and what the loader
    refuses;
  * the extractor arithmetic, to 3 decimals, for every basis it can report
    (current / worst_case / midpoint / outside_range / fail_closed);
  * that build_envelope carries `target.safety_function` and
    `magnitude.physical` unchanged, and adds neither for a mapping that
    declares neither;
  * every tool of both packs, against the envelope the pack's header claims,
    and the tool-name set against the list quoted from each server's source.
"""

from __future__ import annotations

import os
import pathlib
import tempfile
import unittest

from reeflex_mcp import canonical, mappings, normalize


def _registry(yaml_text: str, system: str = "plant") -> mappings.MappingRegistry:
    d = tempfile.mkdtemp()
    with open(os.path.join(d, f"{system}.yaml"), "w", encoding="utf-8") as fh:
        fh.write(yaml_text)
    return mappings.load_mappings_dir(d)


def _refuses(yaml_text: str) -> str:
    try:
        _registry(yaml_text)
    except mappings.MappingError as exc:
        return str(exc)
    raise AssertionError("the loader accepted a mapping it must refuse:\n" + yaml_text)


def _envelope(reg, system, tool, arguments, environment="production"):
    return normalize.build_envelope(
        session_id="s-rfx428",
        agent_id="agent-rfx428",
        on_behalf_of=None,
        upstream_name=system,
        target_system=system,
        target_environment=environment,
        tool_name=tool,
        arguments=arguments,
        mapping_registry=reg,
    )


_SETPOINT = """\
tools:
  write_setpoint:
    verb: set
    axes: { reversibility: recoverable, blast_radius: single, externality: physical }
    magnitude:
      physical:
        value_arg: value
        current_arg: current
        range: [20, 90]
        unit: degC
  write_setpoint_mid:
    verb: set
    axes: { reversibility: recoverable, blast_radius: single, externality: physical }
    magnitude:
      physical:
        value_arg: value
        range: [20, 90]
        when_current_absent: midpoint
  write_dynamic:
    verb: set
    axes: { reversibility: recoverable, blast_radius: single, externality: physical }
    magnitude:
      physical:
        value_arg: value
        min_arg: lo
        max_arg: hi
  write_batch:
    verb: set
    axes: { reversibility: recoverable, blast_radius: scoped, externality: physical }
    safety_function_when: { arg: "nodes[].node_id", matches: '^ns=2;s=Safety\\.' }
    magnitude:
      physical:
        each: nodes
        select:
          - when: { arg: node_id, matches: '^ns=2;s=Oven\\.' }
            value_arg: value
            range: [20, 250]
          - when: { arg: node_id, matches: '^ns=2;s=Valve\\.' }
            value_arg: value
            range: [0, 100]
            unit: "%"
  plain_update:
    verb: update
    axes: { reversibility: recoverable, blast_radius: single, externality: internal }
"""


class TestSchemaRefusals(unittest.TestCase):
    def test_physical_verbs_load(self) -> None:
        for verb in ("set", "mode", "override", "actuate", "flash"):
            reg = _registry(
                f"tools:\n  t:\n    verb: {verb}\n    axes: {{ externality: physical }}\n"
            )
            cls, _ = reg.classify("plant", "t", {})
            self.assertEqual(cls["verb"], verb)

    def test_physical_verb_without_declared_externality_is_refused(self) -> None:
        msg = _refuses("tools:\n  t:\n    verb: set\n    axes: { reversibility: recoverable }\n")
        self.assertIn("axes.externality", msg)

    def test_safety_flag_without_declared_externality_is_refused(self) -> None:
        _refuses("tools:\n  t:\n    verb: update\n    safety_function: true\n")

    def test_static_range_min_not_below_max_is_refused(self) -> None:
        for rng in ("[90, 20]", "[50, 50]"):
            msg = _refuses(
                "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
                f"    magnitude:\n      physical:\n        value_arg: v\n        range: {rng}\n"
            )
            self.assertIn("must be below max", msg)

    def test_range_and_min_arg_together_are_refused(self) -> None:
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    magnitude:\n      physical:\n        value_arg: v\n        range: [0, 1]\n        min_arg: lo\n"
        )

    def test_no_range_at_all_is_refused(self) -> None:
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    magnitude:\n      physical:\n        value_arg: v\n"
        )

    def test_boolean_range_bound_is_refused(self) -> None:
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    magnitude:\n      physical:\n        value_arg: v\n        range: [false, 10]\n"
        )

    def test_bad_regex_is_refused(self) -> None:
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    safety_function_when: { arg: node_id, matches: '(' }\n"
        )

    def test_unknown_keys_are_refused(self) -> None:
        _refuses("tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n    safety: true\n")
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    magnitude:\n      physical:\n        value_arg: v\n        range: [0, 1]\n        units: C\n"
        )
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    magnitude:\n      count: 3\n"
        )

    def test_case_that_overrides_nothing_is_refused(self) -> None:
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    cases:\n      - when: { arg: a, matches: x }\n"
        )

    def test_unknown_when_current_absent_rule_is_refused(self) -> None:
        _refuses(
            "tools:\n  t:\n    verb: set\n    axes: { externality: physical }\n"
            "    magnitude:\n      physical:\n        value_arg: v\n        range: [0, 1]\n"
            "        when_current_absent: guess\n"
        )

    def test_x_keys_are_inert_but_other_unknown_top_keys_still_refused(self) -> None:
        _registry("x-anything: { a: 1 }\ntools:\n  t:\n    verb: read\n")
        _refuses("anything: { a: 1 }\ntools:\n  t:\n    verb: read\n")


class TestExtractorArithmetic(unittest.TestCase):
    """envelope_fraction to 3 decimals, for every basis."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reg = _registry(_SETPOINT)

    def _phys(self, tool, args):
        cls_, _ = self.reg.classify("plant", tool, args)
        return cls_, cls_["physical"]

    def test_current_known_is_the_step(self) -> None:
        _, a = self._phys("write_setpoint", {"value": 62, "current": 55})
        self.assertEqual(a.basis, "current")
        self.assertAlmostEqual(a.physical["envelope_fraction"], 0.1, places=3)
        self.assertEqual(a.physical["unit"], "degC")
        self.assertEqual(a.physical["requested"], 62.0)
        self.assertEqual(a.physical["range"], [20.0, 90.0])

    def test_full_range_step_is_one(self) -> None:
        _, a = self._phys("write_setpoint", {"value": 90, "current": 20})
        self.assertAlmostEqual(a.physical["envelope_fraction"], 1.0, places=3)

    def test_numeric_strings_are_numbers(self) -> None:
        _, a = self._phys("write_setpoint", {"value": "62.0", "current": "55"})
        self.assertAlmostEqual(a.physical["envelope_fraction"], 0.1, places=3)

    def test_out_of_range_request_is_above_one_even_when_the_step_is_small(self) -> None:
        # The spec's own formula gives |92-85|/70 = 0.1 here.
        _, a = self._phys("write_setpoint", {"value": 92, "current": 85})
        self.assertEqual(a.basis, "outside_range")
        self.assertAlmostEqual(a.physical["envelope_fraction"], 1.029, places=3)
        self.assertGreater(a.physical["envelope_fraction"], 1.0)

    def test_in_range_request_from_an_out_of_range_plant_is_capped_at_one(self) -> None:
        # current 200 is outside [20, 90]; moving back to 60 is not "outside
        # the operating envelope".
        _, a = self._phys("write_setpoint", {"value": 60, "current": 200})
        self.assertEqual(a.basis, "current")
        self.assertEqual(a.physical["envelope_fraction"], 1.0)

    def test_current_absent_defaults_to_the_worst_case_step(self) -> None:
        _, a = self._phys("write_setpoint", {"value": 62})
        self.assertEqual(a.basis, "worst_case")
        self.assertAlmostEqual(a.physical["envelope_fraction"], 0.6, places=3)  # max(42, 28)/70

    def test_worst_case_is_never_below_the_true_step(self) -> None:
        for current in (20, 37.5, 55, 72.5, 90):
            for requested in (20, 33, 55, 61, 90):
                _, a = self._phys("write_setpoint", {"value": requested})
                true_step = abs(requested - current) / 70
                self.assertGreaterEqual(a.physical["envelope_fraction"] + 1e-12, true_step)

    def test_midpoint_rule_is_opt_in_and_reads_a_full_sweep_as_half(self) -> None:
        _, a = self._phys("write_setpoint_mid", {"value": 62})
        self.assertEqual(a.basis, "midpoint")
        self.assertAlmostEqual(a.physical["envelope_fraction"], 0.1, places=3)  # |62-55|/70
        # min -> max is a 1.0 step; midpoint cannot see more than 0.5.
        _, a = self._phys("write_setpoint_mid", {"value": 90})
        self.assertAlmostEqual(a.physical["envelope_fraction"], 0.5, places=3)

    def test_range_from_arguments(self) -> None:
        _, a = self._phys("write_dynamic", {"value": 30, "lo": 0, "hi": 40})
        self.assertAlmostEqual(a.physical["envelope_fraction"], 0.75, places=3)  # max(30, 10)/40
        self.assertEqual(a.physical["range"], [0.0, 40.0])
        self.assertNotIn("unit", a.physical)

    def test_batch_reports_the_largest_element_and_skips_unselected_ones(self) -> None:
        cls_, a = self._phys(
            "write_batch",
            {
                "nodes": [
                    {"node_id": "ns=2;s=Oven.Zone1", "value": 135},  # 0.5
                    {"node_id": "ns=2;s=Valve.V7", "value": 90},  # 0.9
                    {"node_id": "ns=2;s=Lamp.L1", "value": "on"},  # not selected
                ]
            },
        )
        self.assertAlmostEqual(a.physical["envelope_fraction"], 0.9, places=3)
        self.assertEqual(a.physical["unit"], "%")
        self.assertFalse(cls_["safety_function"])

    def test_batch_with_no_selected_element_has_no_physical(self) -> None:
        cls_, a = self._phys("write_batch", {"nodes": [{"node_id": "ns=2;s=Lamp.L1", "value": "on"}]})
        self.assertIsNone(a.physical)
        self.assertIsNone(a.error)
        self.assertEqual(cls_["reversibility"], "recoverable")

    def test_safety_function_when_fires_on_any_element(self) -> None:
        cls_, _ = self._phys(
            "write_batch",
            {"nodes": [{"node_id": "ns=2;s=Oven.Zone1", "value": 100}, {"node_id": "ns=2;s=Safety.TripTemp", "value": 1}]},
        )
        self.assertTrue(cls_["safety_function"])


class TestFailClosed(unittest.TestCase):
    """Malformed arguments -> envelope_fraction 2.0 + the most restrictive
    axes + a stated reason. Never silently 0."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.reg = _registry(_SETPOINT)

    def _assert_failed_closed(self, tool, args, reason_fragment):
        cls_, _ = self.reg.classify("plant", tool, args)
        a = cls_["physical"]
        self.assertEqual(a.basis, "fail_closed")
        self.assertEqual(a.physical, {"envelope_fraction": 2.0})
        self.assertIn(reason_fragment, a.error)
        for axis, value in mappings.FAIL_CLOSED_AXES.items():
            self.assertEqual(cls_[axis], value, axis)

    def test_non_numeric_value(self) -> None:
        self._assert_failed_closed("write_setpoint", {"value": "hot", "current": 50}, "not numeric")

    def test_boolean_value(self) -> None:
        self._assert_failed_closed("write_setpoint", {"value": True}, "boolean")

    def test_non_finite_value(self) -> None:
        self._assert_failed_closed("write_setpoint", {"value": "nan"}, "not finite")
        self._assert_failed_closed("write_setpoint", {"value": float("inf")}, "not finite")

    def test_missing_value(self) -> None:
        self._assert_failed_closed("write_setpoint", {"current": 50}, "absent")

    def test_non_numeric_current(self) -> None:
        self._assert_failed_closed("write_setpoint", {"value": 50, "current": "unknown"}, "current")

    def test_min_not_below_max_from_arguments(self) -> None:
        self._assert_failed_closed("write_dynamic", {"value": 5, "lo": 10, "hi": 10}, "min 10.0 >= max 10.0")
        self._assert_failed_closed("write_dynamic", {"value": 5, "lo": 40, "hi": 0}, ">= max")

    def test_missing_bound_argument(self) -> None:
        self._assert_failed_closed("write_dynamic", {"value": 5, "lo": 0}, "max argument 'hi' is absent")

    def test_each_that_is_not_a_list(self) -> None:
        self._assert_failed_closed("write_batch", {"nodes": {"node_id": "ns=2;s=Oven.Z"}}, "not a list")

    def test_one_bad_element_fails_the_whole_batch(self) -> None:
        self._assert_failed_closed(
            "write_batch",
            {"nodes": [{"node_id": "ns=2;s=Oven.Z", "value": 100}, {"node_id": "ns=2;s=Valve.V", "value": "open"}]},
            "nodes[1]",
        )

    def test_envelope_says_why_and_stderr_logs_it(self) -> None:
        import contextlib
        import io

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            env = _envelope(self.reg, "plant", "write_setpoint", {"value": "hot"})
        self.assertEqual(env["magnitude"]["physical"], {"envelope_fraction": 2.0})
        self.assertEqual(env["context"]["physical_basis"], "fail_closed")
        self.assertIn("not numeric", env["context"]["physical_error"])
        self.assertEqual(env["axes"], mappings.FAIL_CLOSED_AXES)
        self.assertIn("FAILED CLOSED", err.getvalue())


class TestEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reg = _registry(_SETPOINT)

    def test_physical_and_safety_reach_the_envelope_unchanged(self) -> None:
        env = _envelope(
            self.reg, "plant", "write_batch", {"nodes": [{"node_id": "ns=2;s=Safety.Hi", "value": 1}, {"node_id": "ns=2;s=Oven.Z", "value": 135}]}
        )
        self.assertIs(env["target"]["safety_function"], True)
        self.assertEqual(env["action"]["verb"], "set")
        self.assertEqual(env["axes"]["externality"], "physical")
        self.assertEqual(
            env["magnitude"],
            {"count": 1, "physical": {"envelope_fraction": 0.5, "requested": 135.0, "range": [20.0, 250.0]}},
        )
        self.assertEqual(env["context"]["physical_basis"], "worst_case")

    def test_a_mapping_without_the_new_keys_emits_neither(self) -> None:
        env = _envelope(self.reg, "plant", "plain_update", {"x": 1})
        self.assertNotIn("safety_function", env["target"])
        self.assertEqual(env["magnitude"], {"count": 1})
        self.assertNotIn("physical_basis", env["context"])

    def test_the_hash_binds_the_step_and_the_safety_flag(self) -> None:
        # The gateway's hold matching uses the same projection as core: an
        # approval for a 0.4 step is not the hash of a 0.9 step, and a
        # non-safety tag is not the hash of a safety tag.
        small = _envelope(self.reg, "plant", "write_setpoint", {"value": 48, "current": 20})
        big = _envelope(self.reg, "plant", "write_setpoint", {"value": 83, "current": 20})
        self.assertNotEqual(canonical.canonical_hash(small), canonical.canonical_hash(big))
        plain = _envelope(self.reg, "plant", "write_batch", {"nodes": [{"node_id": "ns=2;s=Oven.Z", "value": 1}]})
        safety = _envelope(self.reg, "plant", "write_batch", {"nodes": [{"node_id": "ns=2;s=Safety.Z", "value": 1}]})
        self.assertNotEqual(canonical.canonical_hash(plain), canonical.canonical_hash(safety))


# ---------------------------------------------------------------------------
# The shipped packs
# ---------------------------------------------------------------------------

# contract/tools.json @ IndustriAgents/OPCUA-MCP 7e6cc3702123aed472da6785d5e42505e3d00aa9
_OPCUA_SOURCE_TOOLS = frozenset({
    "read_opcua_nodes", "browse_opcua_nodes", "read_opcua_history", "read_event_history",
    "get_server_status", "list_subscriptions", "list_active_alarms", "write_opcua_nodes",
    "call_opcua_method", "subscribe_opcua_nodes", "unsubscribe_opcua_nodes", "subscribe_events",
    "read_events", "acknowledge_alarm", "act_on_alarm",
})

# home-assistant/core de7e90f494ebab3dc624d68776a5d3231c1dd29f: intent/llm.py
# LLM_INTENTS, climate/llm.py LLM_INTENTS, mcp_server/server.py
# LIVE_CONTEXT_TOOL_NAME. The pack maps this subset; see its header.
_HA_MAPPED_TOOLS = frozenset({
    "homeassistant__GetLiveContext", "intent__HassTurnOn", "intent__HassTurnOff",
    "intent__HassSetPosition", "intent__HassStopMoving", "intent__HassCancelAllTimers",
    "climate__HassClimateSetTemperature",
})

_OVEN = "ns=2;s=Line1.Oven.TempSP"

# (tool, arguments, verb, reversibility, blast_radius, externality,
#  safety_function [None = key absent], envelope_fraction [None = no physical], basis)
_OPCUA_CASES = [
    ("read_opcua_nodes", {"node_ids": ["ns=2;i=2"]}, "read", "reversible", "scoped", "internal", None, None, None),
    ("browse_opcua_nodes", {"node_id": "ns=0;i=85"}, "read", "reversible", "scoped", "internal", None, None, None),
    ("read_opcua_history", {"node_id": _OVEN}, "read", "reversible", "single", "internal", None, None, None),
    ("read_event_history", {"node_id": "ns=0;i=2253"}, "read", "reversible", "single", "internal", None, None, None),
    ("get_server_status", {}, "read", "reversible", "single", "internal", None, None, None),
    ("list_subscriptions", {}, "read", "reversible", "single", "internal", None, None, None),
    ("list_active_alarms", {}, "read", "reversible", "single", "internal", None, None, None),
    ("subscribe_opcua_nodes", {"node_ids": [_OVEN]}, "create", "recoverable", "scoped", "internal", None, None, None),
    ("subscribe_events", {"node_id": "ns=0;i=2253"}, "create", "recoverable", "single", "internal", None, None, None),
    ("unsubscribe_opcua_nodes", {"subscription_ids": ["s1"]}, "delete", "recoverable", "scoped", "internal", None, None, None),
    ("read_events", {"node_id": "ns=0;i=2253"}, "update", "recoverable", "single", "internal", None, None, None),
    # process setpoint, in range: worst case of 135 in [20, 250] = 115/230
    ("write_opcua_nodes", {"nodes": [{"node_id": _OVEN, "value": 135}]}, "set", "recoverable", "scoped", "physical", False, 0.5, "worst_case"),
    ("write_opcua_nodes", {"nodes": [{"node_id": _OVEN, "value": "240"}]}, "set", "recoverable", "scoped", "physical", False, 0.957, "worst_case"),
    # out of range: 1 + 10/230
    ("write_opcua_nodes", {"nodes": [{"node_id": _OVEN, "value": 260}]}, "set", "recoverable", "scoped", "physical", False, 1.043, "outside_range"),
    # safety tag (the brief's own example prefix and the interlock family)
    ("write_opcua_nodes", {"nodes": [{"node_id": "ns=2;s=Safety.Oven.HiHi", "value": 300}]}, "set", "recoverable", "scoped", "physical", True, None, None),
    ("write_opcua_nodes", {"nodes": [{"node_id": "ns=3;s=Line1.Oven.Interlock.Bypass", "value": True}]}, "set", "recoverable", "scoped", "physical", True, None, None),
    # an unlisted tag: physical, no magnitude.physical
    ("write_opcua_nodes", {"nodes": [{"node_id": "ns=2;s=Line1.Conveyor.Speed", "value": 3}]}, "set", "recoverable", "scoped", "physical", False, None, None),
    # fail closed: a numeric tag given a label
    ("write_opcua_nodes", {"nodes": [{"node_id": _OVEN, "value": "Hot"}]}, "set", "irreversible", "systemic", "physical", False, 2.0, "fail_closed"),
    ("call_opcua_method", {"object_node_id": "ns=2;s=Line1.Mixer", "method_node_id": "ns=2;s=Line1.Mixer.Start"}, "actuate", "irreversible", "scoped", "physical", False, None, None),
    ("call_opcua_method", {"object_node_id": "ns=2;s=Line1.Oven", "method_node_id": "ns=2;s=Line1.Oven.Interlock.Reset"}, "override", "irreversible", "scoped", "physical", True, None, None),
    ("call_opcua_method", {"object_node_id": "ns=2;s=Line1.ESD", "method_node_id": "ns=2;s=Line1.ESD.Test"}, "override", "irreversible", "scoped", "physical", True, None, None),
    ("acknowledge_alarm", {"event_id": "AAE="}, "update", "recoverable", "single", "internal", None, None, None),
    ("act_on_alarm", {"event_id": "AAE=", "action": "shelve"}, "override", "recoverable", "single", "physical", True, None, None),
    ("act_on_alarm", {"event_id": "AAE=", "action": "shelveFor", "shelve_duration_ms": 60000}, "override", "recoverable", "single", "physical", True, None, None),
    ("act_on_alarm", {"event_id": "AAE=", "action": "comment", "comment": "seen"}, "update", "recoverable", "single", "internal", False, None, None),
    ("act_on_alarm", {"event_id": "AAE=", "action": "unshelve"}, "update", "recoverable", "single", "internal", False, None, None),
    ("act_on_alarm", {"event_id": "AAE="}, "override", "recoverable", "single", "physical", True, None, None),
]

_HA_CASES = [
    ("homeassistant__GetLiveContext", {}, "read", "reversible", "scoped", "internal", None, None, None),
    # no domain -> the most restrictive reading
    ("intent__HassTurnOn", {"name": "Garage Door"}, "actuate", "irreversible", "scoped", "physical", None, None, None),
    ("intent__HassTurnOn", {"name": "Kitchen", "domain": "light"}, "mode", "recoverable", "scoped", "physical", None, None, None),
    ("intent__HassTurnOn", {"name": "Kitchen", "domain": ["light", "fan"]}, "mode", "recoverable", "scoped", "physical", None, None, None),
    ("intent__HassTurnOn", {"name": "x", "domain": ["light", "switch"]}, "actuate", "irreversible", "scoped", "physical", None, None, None),
    ("intent__HassTurnOn", {"name": "Heater plug", "domain": ["switch"]}, "actuate", "irreversible", "scoped", "physical", None, None, None),
    ("intent__HassTurnOn", {"name": "Front Door", "domain": ["lock"]}, "actuate", "recoverable", "single", "physical", None, None, None),
    ("intent__HassTurnOff", {"name": "Front Door", "domain": ["lock"]}, "actuate", "irreversible", "scoped", "physical", None, None, None),
    ("intent__HassTurnOff", {"name": "Garage", "domain": ["cover"], "device_class": ["garage"]}, "actuate", "irreversible", "scoped", "physical", None, None, None),
    ("intent__HassTurnOff", {"name": "Garage", "domain": ["cover"]}, "actuate", "irreversible", "scoped", "physical", None, None, None),
    ("intent__HassTurnOff", {"name": "Bedroom", "domain": ["cover"], "device_class": ["blind"]}, "actuate", "recoverable", "scoped", "physical", None, None, None),
    ("intent__HassTurnOn", {"name": "Bedroom", "domain": "cover", "device_class": "shade"}, "actuate", "recoverable", "scoped", "physical", None, None, None),
    ("intent__HassTurnOn", {"name": "Main", "domain": ["valve"]}, "actuate", "irreversible", "scoped", "physical", None, None, None),
    ("intent__HassTurnOff", {"name": "Lamp", "domain": "light"}, "mode", "recoverable", "scoped", "physical", None, None, None),
    # position 40 of [0, 100]: worst case max(40, 60)/100
    ("intent__HassSetPosition", {"name": "Bedroom", "position": 40, "domain": "cover", "device_class": "blind"}, "set", "recoverable", "scoped", "physical", None, 0.6, "worst_case"),
    ("intent__HassSetPosition", {"name": "Garage", "position": 100}, "set", "irreversible", "scoped", "physical", None, 1.0, "worst_case"),
    ("intent__HassSetPosition", {"name": "Garage", "position": 150}, "set", "irreversible", "scoped", "physical", None, 1.5, "outside_range"),
    ("intent__HassStopMoving", {"name": "Garage"}, "actuate", "recoverable", "scoped", "physical", None, None, None),
    ("intent__HassCancelAllTimers", {}, "update", "recoverable", "scoped", "internal", None, None, None),
    # 21 degC of [7, 35]: max(14, 14)/28
    ("climate__HassClimateSetTemperature", {"name": "Living Room", "temperature": 21}, "set", "recoverable", "single", "physical", None, 0.5, "worst_case"),
    ("climate__HassClimateSetTemperature", {"area": "Bedroom", "temperature": 30}, "set", "recoverable", "single", "physical", None, 0.821, "worst_case"),
    # a Fahrenheit instance's 70: 1 + 35/28
    ("climate__HassClimateSetTemperature", {"name": "Living Room", "temperature": 70}, "set", "recoverable", "single", "physical", None, 2.25, "outside_range"),
    ("climate__HassClimateSetTemperature", {"name": "Living Room"}, "set", "irreversible", "systemic", "physical", None, 2.0, "fail_closed"),
]


class TestShippedPacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reg = mappings.load_mappings_dir()

    def test_packs_are_bundled(self) -> None:
        self.assertTrue({"opcua", "homeassistant"} <= self.reg.systems)
        bundled = pathlib.Path(mappings.DEFAULT_MAPPINGS_DIR)
        self.assertTrue((bundled / "opcua.yaml").is_file())
        self.assertTrue((bundled / "homeassistant.yaml").is_file())

    def test_opcua_maps_every_tool_the_server_declares_and_no_other(self) -> None:
        self.assertEqual(self.reg.tool_names("opcua"), _OPCUA_SOURCE_TOOLS)

    def test_homeassistant_maps_exactly_the_documented_subset(self) -> None:
        self.assertEqual(self.reg.tool_names("homeassistant"), _HA_MAPPED_TOOLS)

    def test_every_case_table_tool_is_in_its_pack(self) -> None:
        self.assertEqual({c[0] for c in _OPCUA_CASES}, _OPCUA_SOURCE_TOOLS)
        self.assertEqual({c[0] for c in _HA_CASES}, _HA_MAPPED_TOOLS)

    def _check(self, system, rows) -> None:
        for tool, args, verb, rev, blast, ext, safety, fraction, basis in rows:
            with self.subTest(system=system, tool=tool, args=args):
                env = _envelope(self.reg, system, tool, args)
                self.assertEqual(env["context"]["classification_source"], "mapping")
                self.assertEqual(env["action"]["verb"], verb)
                self.assertEqual(
                    env["axes"], {"reversibility": rev, "blast_radius": blast, "externality": ext}
                )
                if safety is None:
                    self.assertNotIn("safety_function", env["target"])
                else:
                    self.assertIs(env["target"]["safety_function"], safety)
                if fraction is None:
                    self.assertNotIn("physical", env["magnitude"])
                else:
                    self.assertEqual(round(env["magnitude"]["physical"]["envelope_fraction"], 3), fraction)
                self.assertEqual(env["context"].get("physical_basis"), basis)

    def test_opcua_envelopes(self) -> None:
        self._check("opcua", _OPCUA_CASES)

    def test_homeassistant_envelopes(self) -> None:
        self._check("homeassistant", _HA_CASES)

    def test_opcua_batch_counts_every_node_for_physical_writes(self) -> None:
        env = _envelope(
            self.reg, "opcua", "write_opcua_nodes",
            {"nodes": [{"node_id": _OVEN, "value": 100 + i} for i in range(12)]},
        )
        self.assertEqual(env["magnitude"]["count"], 12)


if __name__ == "__main__":
    unittest.main()
