"""
mappings.py -- Track 4: declarative per-server mappings (design doc section 8).

Loads `mappings/<system>.yaml` files, each providing per-TOOL verb + axes
overrides (+ an optional `magnitude.from_arg` rule) that take precedence,
for the tools they name explicitly, over the Track-2 name-heuristic
(normalize.classify()). See normalize.py's `classify_call()` for the full
3-tier resolution this module is the front slot of:

  1. declarative mapping (THIS module)        -- source tag "mapping"
  2. name-heuristic (normalize.classify)        -- source tag "heuristic:<bucket>"
  3. conservative default (the heuristic's OWN catch-all bucket, fired when
     no name-prefix matches)                    -- source tag "heuristic:default"

PARTIAL AXES (design doc section 8 item 2): a mapping entry may specify only
SOME of the three axes. Whichever axis it does NOT specify is filled with
`CORE_AXIS_DEFAULTS` -- deliberately the EXACT SAME restrictive floor
reeflex-core's own `app/envelope.py` `_AXIS_DEFAULTS` applies to a genuinely
missing axis value (irreversible / systemic / outbound). This is NOT a
different, gateway-invented "conservative" guess -- it is chosen specifically
so an operator's partial mapping behaves predictably: an axis you don't set
here ends up exactly where core would have coerced it anyway, no surprises.

The externality entry was `physical` until RFX-129, on both sides. That is the
one enum member no rule in the shipped policy pack reads, so a partial mapping
that omitted `externality` produced an envelope core charged against NOTHING --
and because THIS module fills the axis before the envelope is sent, core saw
the value as affirmatively DECLARED and its own coercion never got a look in.
A gateway that fills an axis owns that axis: the mirror is not decoration, it
is the only thing standing between a partial mapping and an uncharged budget.

GIGO honesty (design doc section 8, verbatim): "Mapping quality is adapter
quality. A tool the gateway maps wrong is governed wrong. The starter
mappings are a floor you can read and correct, not a guarantee -- the same
candor we apply to what the base policy does not catch."

PHYSICAL IMPACT (RFX-428, PHYSICAL-IMPACT-SPEC draft 2026-10-13 section 1).
Additive; a mapping that uses none of it loads and classifies exactly as it
did before. Per tool:

  verb: set | mode | override | actuate | flash   (on top of the SPEC verbs)
  safety_function: true|false                     -> target.safety_function
  safety_function_when: {arg, matches} | [...]    -> true when ANY value the
                                                     path reaches matches
  cases: [{when, verb?, axes?, safety_function?}] -> first case whose
                                                     conditions (a list is AND)
                                                     hold for EVERY value the
                                                     path reaches
                                                     overrides verb/axes
  magnitude: {physical: <extractor>}              -> magnitude.physical

Why argument matching exists at all: on a real PLC one `write` tool reaches
both a process setpoint and an interlock, and on Home Assistant one
`HassTurnOn` reaches both a lamp and a garage door. Only the arguments tell
them apart, so the asymmetry is deliberate: a condition that makes the call
HEAVIER (`safety_function_when`) fires on any value; a condition that picks a
`case` must hold for every value, and the tool's own top-level verb/axes --
which a pack writes as its most restrictive reading -- apply otherwise.

`arg` is a path into the call's arguments: `node_id`, `a.b`, and `nodes[]`
(every element of a list) -- `nodes[].node_id`. A value that is itself a list
(Home Assistant's `domain: ["lock"]`) is matched element by element.

A tool that declares a physical verb, a safety flag or a physical extractor
must declare `axes.externality` explicitly: the spec's rules arm only on
`physical`, and the fill below would otherwise say `outbound` and arm none of
them. That is refused at load, not guessed.

The extractor and the fail-closed rule live in `assess_physical()` below.

This module is pure config loading: no network, no MCP SDK. Malformed YAML
inside an EXISTING mappings directory is a hard MappingError (refuse to
boot, matching registry.py's ConfigError philosophy) -- silently ignoring a
broken mapping file would leave an operator believing a tool is governed by
their mapping when it silently is not. A directory that does not exist at
all is NOT an error: it just means no declarative mappings are configured,
and every call falls through to the heuristic (still SPEC-conformant).
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# The five physical verbs are PHYSICAL-IMPACT-SPEC section 1, additive to SPEC
# section 3. Until reeflex-core ships them, core canonicalises `set` to
# `update` and an unaliased one by its reversibility axis (app/envelope.py
# _VERB_CANON) -- the gateway sends them anyway, because the spec fixes them.
PHYSICAL_VERBS = frozenset({"set", "mode", "override", "actuate", "flash"})
_VALID_VERBS = frozenset({"read", "create", "update", "delete", "execute", "transact", "emit"}) | PHYSICAL_VERBS

# What a physical extractor emits when it cannot compute an honest fraction
# (non-numeric value, min >= max from the arguments, a missing value): never
# 0, which would read as "no movement". 2.0 is past R10a's 1.0, and the axes
# are the most restrictive the enum has, so in production the call is denied
# by more than one rule and in `dev` it is still charged.
FAIL_CLOSED_ENVELOPE_FRACTION = 2.0
FAIL_CLOSED_AXES: dict[str, str] = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "physical",
}
_CURRENT_ABSENT_RULES = frozenset({"worst_case", "midpoint"})

_AXIS_ALLOWED: dict[str, frozenset[str]] = {
    "reversibility": frozenset({"reversible", "recoverable", "irreversible"}),
    "blast_radius": frozenset({"single", "scoped", "broad", "systemic"}),
    "externality": frozenset({"internal", "outbound", "physical"}),
}

# MUST match reeflex-core/app/envelope.py `_AXIS_DEFAULTS` exactly. That is now
# CHECKED against core's source rather than asserted here -- see
# tests/test_mappings.py::test_core_axis_defaults_match_core_envelope_py, whose
# predecessor compared this dict to a literal in its own file and so could not
# have detected the drift its docstring promised to catch.
CORE_AXIS_DEFAULTS: dict[str, str] = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "outbound",
}

# The package's own bundled starter mappings (filesystem/github/postgres).
DEFAULT_MAPPINGS_DIR: Path = Path(__file__).resolve().parent / "mappings"


class MappingError(Exception):
    """A mappings/<system>.yaml file is malformed. Refuse to boot -- same
    fail-closed-at-config-time spirit as registry.ConfigError."""


@dataclass(frozen=True)
class Condition:
    """`{arg: <path>, matches: <regex>}` -- `re.search`, so anchor it."""

    arg: str
    pattern: re.Pattern

    def matches_any(self, arguments: Any) -> bool:
        return any(_scalar_matches(self.pattern, v) for v in _resolve_flat(arguments, self.arg))

    def matches_all(self, arguments: Any) -> bool:
        values = _resolve_flat(arguments, self.arg)
        return bool(values) and all(_scalar_matches(self.pattern, v) for v in values)


@dataclass(frozen=True)
class Case:
    when: tuple[Condition, ...]  # all must hold
    verb: str | None
    axes: dict[str, str]
    safety_function: bool | None = None


@dataclass(frozen=True)
class PhysicalExtractor:
    when: Condition | None
    value_arg: str
    range: tuple[float, float] | None  # static; else min_arg/max_arg
    min_arg: str | None
    max_arg: str | None
    current_arg: str | None
    unit: str | None
    when_current_absent: str


@dataclass(frozen=True)
class PhysicalRule:
    each: str | None  # path to a list argument; every element is assessed
    select: tuple[PhysicalExtractor, ...]


@dataclass(frozen=True)
class PhysicalAssessment:
    """What `assess_physical()` found. `physical` is the envelope's
    `magnitude.physical` (None = emit none, today's behaviour); `error` is
    set exactly when the extractor failed closed."""

    physical: dict[str, Any] | None
    basis: str | None
    error: str | None = None


@dataclass(frozen=True)
class ToolMapping:
    verb: str
    axes: dict[str, str]  # only the axis keys this entry actually specified
    safety_function: bool | None = None  # None = the entry declared nothing
    safety_function_when: tuple[Condition, ...] = ()
    cases: tuple[Case, ...] = ()
    physical: PhysicalRule | None = None


@dataclass(frozen=True)
class SystemMapping:
    system: str
    tools: dict[str, ToolMapping]
    magnitude_from_arg: str | None
    source_path: str


class MappingRegistry:
    """Loaded declarative mappings, keyed by `target.system`. A system with
    no `mappings/<system>.yaml` present simply has no entry here -- every
    call for it falls straight through to the heuristic (tier 2/3)."""

    def __init__(self, systems: dict[str, SystemMapping]):
        self._systems = systems

    def classify(self, system: str, tool_name: str, arguments: dict) -> tuple[dict[str, str], int] | None:
        """Return (classification, magnitude_count) if `system`+`tool_name`
        has a declarative entry, else None (caller falls through to the
        heuristic). `classification` has keys verb/reversibility/
        blast_radius/externality -- the same shape normalize.classify()
        produces -- with any axis the entry did not specify filled from
        CORE_AXIS_DEFAULTS (an axis is NEVER omitted -- SPEC section 2).

        RFX-428: an entry that declares a safety flag adds `safety_function`
        (bool), and one that declares a physical extractor adds
        `physical` (a PhysicalAssessment). When the assessment failed closed
        the axes are replaced by FAIL_CLOSED_AXES. An entry that declares
        neither returns the four keys and nothing else, as before.
        """
        sysmap = self._systems.get(system)
        if sysmap is None:
            return None
        tool = sysmap.tools.get(tool_name)
        if tool is None:
            return None
        verb = tool.verb
        axes = dict(CORE_AXIS_DEFAULTS)
        axes.update(tool.axes)
        safety_function = tool.safety_function
        for case in tool.cases:
            if all(c.matches_all(arguments) for c in case.when):
                verb = case.verb or verb
                axes.update(case.axes)
                if case.safety_function is not None:
                    safety_function = case.safety_function
                break
        count = _magnitude_from_arg(arguments, sysmap.magnitude_from_arg)
        cls: dict[str, Any] = {"verb": verb, **axes}

        # A case may clear a static flag (an alarm COMMENT is not a shelve);
        # nothing clears a `safety_function_when` match.
        if safety_function is not None or tool.safety_function_when:
            cls["safety_function"] = bool(safety_function) or any(
                c.matches_any(arguments) for c in tool.safety_function_when
            )
        if tool.physical is not None:
            assessment = assess_physical(tool.physical, arguments)
            cls["physical"] = assessment
            if assessment.error is not None:
                cls.update(FAIL_CLOSED_AXES)
        return cls, count

    @property
    def systems(self) -> frozenset[str]:
        return frozenset(self._systems.keys())

    def tool_names(self, system: str) -> frozenset[str]:
        sysmap = self._systems.get(system)
        return frozenset(sysmap.tools.keys()) if sysmap is not None else frozenset()


def _magnitude_from_arg(arguments: Any, arg_name: str | None) -> int:
    """count = len(args[arg_name]) if it's a list, else 1 (design doc
    section 8's literal semantics). No rule configured, arg absent, or not a
    list -> 1."""
    if arg_name and isinstance(arguments, dict):
        value = arguments.get(arg_name)
        if isinstance(value, list):
            return max(len(value), 1)
    return 1


# ---------------------------------------------------------------------------
# Argument paths and conditions
# ---------------------------------------------------------------------------


def _resolve(arguments: Any, path: str) -> list[Any]:
    """Every value `path` reaches in `arguments`. `a.b` descends into
    mappings; a segment ending in `[]` fans out over a list. A segment that
    does not exist reaches nothing -- an absent argument is not a value."""
    values = [arguments]
    for segment in path.split("."):
        fan_out = segment.endswith("[]")
        key = segment[:-2] if fan_out else segment
        reached = []
        for value in values:
            if not isinstance(value, dict) or key not in value:
                continue
            child = value[key]
            if fan_out:
                if isinstance(child, list):
                    reached.extend(child)
            else:
                reached.append(child)
        values = reached
    return values


def _resolve_flat(arguments: Any, path: str) -> list[Any]:
    """`_resolve`, with a list VALUE matched element by element (Home
    Assistant's `domain` slot is `EnsureList`: "lock" and ["lock"] are the
    same request)."""
    flat: list[Any] = []
    for value in _resolve(arguments, path):
        flat.extend(value if isinstance(value, list) else [value])
    return flat


def _scalar_matches(pattern: re.Pattern, value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return False
    return pattern.search(str(value)) is not None


# ---------------------------------------------------------------------------
# magnitude.physical
# ---------------------------------------------------------------------------


class _Malformed(Exception):
    """An argument the extractor needs is not something it can measure."""


def _number(value: Any, what: str) -> float:
    if isinstance(value, bool):
        raise _Malformed(f"{what} is a boolean ({value!r}), not a number")
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            raise _Malformed(f"{what} is not numeric ({value!r})") from None
    else:
        raise _Malformed(f"{what} is a {type(value).__name__}, not a number")
    if not math.isfinite(number):
        raise _Malformed(f"{what} is not finite ({value!r})")
    return number


def _single(element: Any, path: str, what: str, *, required: bool) -> Any:
    values = _resolve(element, path)
    if not values:
        if required:
            raise _Malformed(f"{what} argument '{path}' is absent")
        return None
    if len(values) > 1:
        raise _Malformed(f"{what} argument '{path}' reaches {len(values)} values, not one")
    return values[0]


def _assess_one(ex: PhysicalExtractor, element: Any) -> tuple[dict[str, Any], str]:
    requested = _number(_single(element, ex.value_arg, "value", required=True), "value")
    if ex.range is not None:
        lo, hi = ex.range
    else:
        lo = _number(_single(element, ex.min_arg, "min", required=True), "min")
        hi = _number(_single(element, ex.max_arg, "max", required=True), "max")
    if lo >= hi:
        raise _Malformed(f"range min {lo} >= max {hi}")
    span = hi - lo

    current_raw = _single(element, ex.current_arg, "current", required=False) if ex.current_arg else None
    if requested < lo or requested > hi:
        # Outside the declared safe range. The spec reads > 1.0 as exactly
        # this, and |requested - current| / span does NOT deliver it on its
        # own: range [20, 90], current 85, requested 92 is a 0.1 step. So an
        # out-of-range request is 1.0 plus how far outside it lies --
        # strictly > 1.0 whatever the current value.
        fraction = 1.0 + max(lo - requested, requested - hi) / span
        basis = "outside_range"
    elif current_raw is not None:
        current = _number(current_raw, "current")
        # Capped at 1.0: a request INSIDE the range is never "outside the
        # operating envelope", even from a plant that has drifted out of it
        # (current 95 in [20, 90] -> 60 is the move back in, not a deny).
        fraction = min(abs(requested - current) / span, 1.0)
        basis = "current"
    elif ex.when_current_absent == "midpoint":
        fraction = abs(requested - (lo + hi) / 2.0) / span
        basis = "midpoint"
    else:
        # The largest step that can be in progress for a plant somewhere in
        # its range: >= the true step whenever current is in range. The
        # midpoint rule is not that -- min -> max reads 0.5 under it.
        fraction = max(requested - lo, hi - requested) / span
        basis = "worst_case"

    physical: dict[str, Any] = {"envelope_fraction": fraction}
    if ex.unit is not None:
        physical["unit"] = ex.unit
    physical["requested"] = requested
    physical["range"] = [lo, hi]
    return physical, basis


def assess_physical(rule: PhysicalRule, arguments: Any) -> PhysicalAssessment:
    """Compute `magnitude.physical` for one call.

    envelope_fraction, for a request inside [min, max]:
      * `current` known:  |requested - current| / (max - min), capped at 1.0
      * `current` absent: `worst_case` (default) max(requested - min,
        max - requested) / (max - min) -- an upper bound on the step; or
        `midpoint` |requested - (min + max) / 2| / (max - min), opt-in
    and for a request outside it: 1.0 + distance outside / (max - min).

    With `each`, every element of that list is assessed by the first
    `select` entry whose `when` holds for it; elements no entry selects are
    not physical and add nothing. The envelope carries the LARGEST element's
    fraction -- a batch is one step per tag, not one step summed over tags;
    `magnitude.count` (the list length) is what charges `physical_writes`.

    Fails closed: anything that cannot be measured -> envelope_fraction
    FAIL_CLOSED_ENVELOPE_FRACTION and `error` naming why. Never 0.
    """
    try:
        if rule.each is None:
            elements = [arguments]
        else:
            lists = _resolve(arguments, rule.each)
            if len(lists) != 1 or not isinstance(lists[0], list):
                raise _Malformed(f"each: '{rule.each}' is not a list argument")
            elements = lists[0]
        worst: tuple[dict[str, Any], str] | None = None
        for index, element in enumerate(elements):
            chosen = next(
                (ex for ex in rule.select if ex.when is None or ex.when.matches_all(element)),
                None,
            )
            if chosen is None:
                continue
            try:
                assessed = _assess_one(chosen, element)
            except _Malformed as exc:
                where = f"{rule.each}[{index}]: " if rule.each is not None else ""
                raise _Malformed(where + str(exc)) from None
            if worst is None or assessed[0]["envelope_fraction"] > worst[0]["envelope_fraction"]:
                worst = assessed
    except _Malformed as exc:
        return PhysicalAssessment(
            physical={"envelope_fraction": FAIL_CLOSED_ENVELOPE_FRACTION},
            basis="fail_closed",
            error=str(exc),
        )
    if worst is None:
        return PhysicalAssessment(physical=None, basis=None)
    return PhysicalAssessment(physical=worst[0], basis=worst[1])


def load_mappings_dir(path: str | os.PathLike | None = None) -> MappingRegistry:
    """Load every `<system>.yaml` file in `path` (default: this package's own
    bundled `mappings/` directory -- filesystem/github/postgres starters).
    """
    directory = Path(path) if path is not None else DEFAULT_MAPPINGS_DIR
    systems: dict[str, SystemMapping] = {}
    if not directory.is_dir():
        return MappingRegistry(systems)

    for entry in sorted(directory.glob("*.yaml")):
        system_name = entry.stem
        systems[system_name] = _load_one_file(entry, system_name)
    return MappingRegistry(systems)


def _load_one_file(path: Path, system_name: str) -> SystemMapping:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise MappingError(f"mapping file {path} is not valid YAML: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise MappingError(f"mapping file {path} must be a YAML mapping at the top level")

    raw_tools = raw.get("tools")
    if not isinstance(raw_tools, dict) or not raw_tools:
        raise MappingError(f"mapping file {path} must have a non-empty 'tools' mapping")

    tools: dict[str, ToolMapping] = {}
    for tool_name, entry in raw_tools.items():
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise MappingError(f"mapping file {path}: tool names must be non-empty strings")
        tools[tool_name] = _parse_tool_entry(path, tool_name, entry)

    magnitude_from_arg: str | None = None
    raw_magnitude = raw.get("magnitude")
    if raw_magnitude is not None:
        if not isinstance(raw_magnitude, dict) or "from_arg" not in raw_magnitude:
            raise MappingError(f"mapping file {path}: 'magnitude' must be a mapping with a 'from_arg' key")
        from_arg = raw_magnitude["from_arg"]
        if not isinstance(from_arg, str) or not from_arg.strip():
            raise MappingError(f"mapping file {path}: 'magnitude.from_arg' must be a non-empty string")
        magnitude_from_arg = from_arg.strip()

    # `x-...` keys are inert: a place to hold YAML anchors (a node-id pattern
    # used by several tools) so a pack states each one once.
    unknown_top_keys = {k for k in set(raw) - {"tools", "magnitude"} if not str(k).startswith("x-")}
    if unknown_top_keys:
        raise MappingError(f"mapping file {path}: unknown top-level key(s) {sorted(unknown_top_keys)}")

    return SystemMapping(
        system=system_name, tools=tools, magnitude_from_arg=magnitude_from_arg, source_path=str(path)
    )


def _parse_tool_entry(path: Path, tool_name: str, entry: object) -> ToolMapping:
    if not isinstance(entry, dict):
        raise MappingError(f"mapping file {path}: tools.{tool_name} must be a mapping")

    verb = entry.get("verb")
    if verb not in _VALID_VERBS:
        raise MappingError(
            f"mapping file {path}: tools.{tool_name}.verb must be one of {sorted(_VALID_VERBS)}, got {verb!r}"
        )

    where = f"mapping file {path}: tools.{tool_name}"
    axes = _parse_axes(where, entry.get("axes"))

    unknown_entry_keys = set(entry) - {
        "verb", "axes", "safety_function", "safety_function_when", "cases", "magnitude"
    }
    if unknown_entry_keys:
        raise MappingError(
            f"mapping file {path}: tools.{tool_name} has unknown key(s) {sorted(unknown_entry_keys)}"
        )

    safety_function = entry.get("safety_function")
    if safety_function is not None and not isinstance(safety_function, bool):
        raise MappingError(f"{where}.safety_function must be true or false, got {safety_function!r}")

    raw_when = entry.get("safety_function_when")
    if raw_when is None:
        safety_when: tuple[Condition, ...] = ()
    elif isinstance(raw_when, list) and raw_when:
        safety_when = tuple(_parse_condition(f"{where}.safety_function_when[{i}]", c) for i, c in enumerate(raw_when))
    else:
        safety_when = (_parse_condition(f"{where}.safety_function_when", raw_when),)

    raw_cases = entry.get("cases")
    cases: list[Case] = []
    if raw_cases is not None:
        if not isinstance(raw_cases, list) or not raw_cases:
            raise MappingError(f"{where}.cases must be a non-empty list if present")
        for i, raw_case in enumerate(raw_cases):
            cases.append(_parse_case(f"{where}.cases[{i}]", raw_case))

    physical = None
    raw_magnitude = entry.get("magnitude")
    if raw_magnitude is not None:
        if not isinstance(raw_magnitude, dict) or set(raw_magnitude) != {"physical"}:
            raise MappingError(f"{where}.magnitude must be a mapping with exactly one key, 'physical'")
        physical = _parse_physical(f"{where}.magnitude.physical", raw_magnitude["physical"])

    physical_aware = (
        verb in PHYSICAL_VERBS
        or any(c.verb in PHYSICAL_VERBS for c in cases)
        or safety_function is not None
        or any(c.safety_function is not None for c in cases)
        or bool(safety_when)
        or physical is not None
    )
    if physical_aware and "externality" not in axes:
        raise MappingError(
            f"{where}: a physical verb, safety flag or physical extractor needs axes.externality "
            f"declared -- the physical-impact rules arm only on 'physical', and the fill "
            f"({CORE_AXIS_DEFAULTS['externality']!r}) would arm none of them"
        )

    return ToolMapping(
        verb=verb,
        axes=axes,
        safety_function=safety_function,
        safety_function_when=safety_when,
        cases=tuple(cases),
        physical=physical,
    )


def _parse_axes(where: str, raw_axes: object) -> dict[str, str]:
    raw_axes = raw_axes or {}
    if not isinstance(raw_axes, dict):
        raise MappingError(f"{where}.axes must be a mapping if present")

    axes: dict[str, str] = {}
    for axis_name, allowed in _AXIS_ALLOWED.items():
        if axis_name not in raw_axes:
            continue  # partial axes are fine -- see module docstring
        value = raw_axes[axis_name]
        if value not in allowed:
            raise MappingError(f"{where}.axes.{axis_name} must be one of {sorted(allowed)}, got {value!r}")
        axes[axis_name] = value

    unknown_axis_keys = set(raw_axes) - set(_AXIS_ALLOWED)
    if unknown_axis_keys:
        raise MappingError(f"{where}.axes has unknown key(s) {sorted(unknown_axis_keys)}")
    return axes


def _parse_path(where: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MappingError(f"{where} must be a non-empty argument path")
    path = value.strip()
    for segment in path.split("."):
        key = segment[:-2] if segment.endswith("[]") else segment
        if not key or "[" in key or "]" in key:
            raise MappingError(f"{where}: '{path}' is not a path like 'a', 'a.b' or 'a[].b'")
    return path


def _parse_condition(where: str, raw: object) -> Condition:
    if not isinstance(raw, dict) or set(raw) != {"arg", "matches"}:
        raise MappingError(f"{where} must be a mapping with exactly 'arg' and 'matches'")
    if not isinstance(raw["matches"], str) or not raw["matches"]:
        raise MappingError(f"{where}.matches must be a non-empty regular expression")
    try:
        pattern = re.compile(raw["matches"])
    except re.error as exc:
        raise MappingError(f"{where}.matches is not a valid regular expression: {exc}") from exc
    return Condition(arg=_parse_path(f"{where}.arg", raw["arg"]), pattern=pattern)


def _parse_case(where: str, raw: object) -> Case:
    if not isinstance(raw, dict) or "when" not in raw:
        raise MappingError(f"{where} must be a mapping with a 'when' condition")
    unknown = set(raw) - {"when", "verb", "axes", "safety_function"}
    if unknown:
        raise MappingError(f"{where} has unknown key(s) {sorted(unknown)}")
    verb = raw.get("verb")
    if verb is not None and verb not in _VALID_VERBS:
        raise MappingError(f"{where}.verb must be one of {sorted(_VALID_VERBS)}, got {verb!r}")
    axes = _parse_axes(where, raw.get("axes"))
    safety_function = raw.get("safety_function")
    if safety_function is not None and not isinstance(safety_function, bool):
        raise MappingError(f"{where}.safety_function must be true or false, got {safety_function!r}")
    if verb is None and not axes and safety_function is None:
        raise MappingError(f"{where} overrides nothing -- give it a verb, axes or safety_function")
    raw_when = raw["when"]
    if isinstance(raw_when, list) and raw_when:
        when = tuple(_parse_condition(f"{where}.when[{i}]", c) for i, c in enumerate(raw_when))
    else:
        when = (_parse_condition(f"{where}.when", raw_when),)
    return Case(when=when, verb=verb, axes=axes, safety_function=safety_function)


def _parse_bound(where: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise MappingError(f"{where} must be a finite number, got {value!r}")
    return float(value)


def _parse_extractor(where: str, raw: object, *, allow_each: bool) -> tuple[PhysicalExtractor, str | None]:
    if not isinstance(raw, dict):
        raise MappingError(f"{where} must be a mapping")
    allowed = {"when", "value_arg", "range", "min_arg", "max_arg", "current_arg", "unit", "when_current_absent"}
    if allow_each:
        allowed.add("each")
    unknown = set(raw) - allowed
    if unknown:
        raise MappingError(f"{where} has unknown key(s) {sorted(unknown)}")

    if "range" in raw:
        if "min_arg" in raw or "max_arg" in raw:
            raise MappingError(f"{where}: give 'range' OR 'min_arg'/'max_arg', not both")
        rng = raw["range"]
        if not isinstance(rng, list) or len(rng) != 2:
            raise MappingError(f"{where}.range must be [min, max]")
        lo, hi = _parse_bound(f"{where}.range[0]", rng[0]), _parse_bound(f"{where}.range[1]", rng[1])
        if lo >= hi:
            raise MappingError(f"{where}.range: min {lo} must be below max {hi}")
        static_range: tuple[float, float] | None = (lo, hi)
        min_arg = max_arg = None
    elif "min_arg" in raw and "max_arg" in raw:
        static_range = None
        min_arg = _parse_path(f"{where}.min_arg", raw["min_arg"])
        max_arg = _parse_path(f"{where}.max_arg", raw["max_arg"])
    else:
        raise MappingError(f"{where} needs a safe range: 'range: [min, max]' or both 'min_arg' and 'max_arg'")

    unit = raw.get("unit")
    if unit is not None and not isinstance(unit, str):
        raise MappingError(f"{where}.unit must be a string")
    absent_rule = raw.get("when_current_absent", "worst_case")
    if absent_rule not in _CURRENT_ABSENT_RULES:
        raise MappingError(f"{where}.when_current_absent must be one of {sorted(_CURRENT_ABSENT_RULES)}")

    extractor = PhysicalExtractor(
        when=_parse_condition(f"{where}.when", raw["when"]) if "when" in raw else None,
        value_arg=_parse_path(f"{where}.value_arg", raw.get("value_arg")),
        range=static_range,
        min_arg=min_arg,
        max_arg=max_arg,
        current_arg=_parse_path(f"{where}.current_arg", raw["current_arg"]) if "current_arg" in raw else None,
        unit=unit,
        when_current_absent=absent_rule,
    )
    each = _parse_path(f"{where}.each", raw["each"]) if allow_each and "each" in raw else None
    return extractor, each


def _parse_physical(where: str, raw: object) -> PhysicalRule:
    """Two shapes: one extractor (`value_arg`, `range`, ...) or
    `{each?, select: [extractor, ...]}` for a tool whose tags need different
    ranges. `each` may appear on the single-extractor shape too."""
    if not isinstance(raw, dict):
        raise MappingError(f"{where} must be a mapping")
    if "select" not in raw:
        extractor, each = _parse_extractor(where, raw, allow_each=True)
        return PhysicalRule(each=each, select=(extractor,))

    unknown = set(raw) - {"each", "select"}
    if unknown:
        raise MappingError(f"{where}: with 'select', the only other key is 'each' (got {sorted(unknown)})")
    raw_select = raw["select"]
    if not isinstance(raw_select, list) or not raw_select:
        raise MappingError(f"{where}.select must be a non-empty list")
    select = tuple(
        _parse_extractor(f"{where}.select[{i}]", item, allow_each=False)[0] for i, item in enumerate(raw_select)
    )
    each = _parse_path(f"{where}.each", raw["each"]) if "each" in raw else None
    return PhysicalRule(each=each, select=select)
