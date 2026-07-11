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
missing axis value (irreversible / systemic / physical). This is NOT a
different, gateway-invented "conservative" guess -- it is chosen specifically
so an operator's partial mapping behaves predictably: an axis you don't set
here ends up exactly where core would have coerced it anyway, no surprises.

GIGO honesty (design doc section 8, verbatim): "Mapping quality is adapter
quality. A tool the gateway maps wrong is governed wrong. The starter
mappings are a floor you can read and correct, not a guarantee -- the same
candor we apply to what the base policy does not catch."

This module is pure config loading: no network, no MCP SDK. Malformed YAML
inside an EXISTING mappings directory is a hard MappingError (refuse to
boot, matching registry.py's ConfigError philosophy) -- silently ignoring a
broken mapping file would leave an operator believing a tool is governed by
their mapping when it silently is not. A directory that does not exist at
all is NOT an error: it just means no declarative mappings are configured,
and every call falls through to the heuristic (still SPEC-conformant).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_VALID_VERBS = frozenset({"read", "create", "update", "delete", "execute", "transact", "emit"})

_AXIS_ALLOWED: dict[str, frozenset[str]] = {
    "reversibility": frozenset({"reversible", "recoverable", "irreversible"}),
    "blast_radius": frozenset({"single", "scoped", "broad", "systemic"}),
    "externality": frozenset({"internal", "outbound", "physical"}),
}

# MUST match reeflex-core/app/envelope.py `_AXIS_DEFAULTS` exactly (verified
# while building this package) -- see module docstring "PARTIAL AXES".
CORE_AXIS_DEFAULTS: dict[str, str] = {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "physical",
}

# The package's own bundled starter mappings (filesystem/github/postgres).
DEFAULT_MAPPINGS_DIR: Path = Path(__file__).resolve().parent / "mappings"


class MappingError(Exception):
    """A mappings/<system>.yaml file is malformed. Refuse to boot -- same
    fail-closed-at-config-time spirit as registry.ConfigError."""


@dataclass(frozen=True)
class ToolMapping:
    verb: str
    axes: dict[str, str]  # only the axis keys this entry actually specified


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
        """
        sysmap = self._systems.get(system)
        if sysmap is None:
            return None
        tool = sysmap.tools.get(tool_name)
        if tool is None:
            return None
        axes = dict(CORE_AXIS_DEFAULTS)
        axes.update(tool.axes)
        count = _magnitude_from_arg(arguments, sysmap.magnitude_from_arg)
        return {"verb": tool.verb, **axes}, count

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

    unknown_top_keys = set(raw) - {"tools", "magnitude"}
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

    raw_axes = entry.get("axes") or {}
    if not isinstance(raw_axes, dict):
        raise MappingError(f"mapping file {path}: tools.{tool_name}.axes must be a mapping if present")

    axes: dict[str, str] = {}
    for axis_name, allowed in _AXIS_ALLOWED.items():
        if axis_name not in raw_axes:
            continue  # partial axes are fine -- see module docstring
        value = raw_axes[axis_name]
        if value not in allowed:
            raise MappingError(
                f"mapping file {path}: tools.{tool_name}.axes.{axis_name} must be one of "
                f"{sorted(allowed)}, got {value!r}"
            )
        axes[axis_name] = value

    unknown_axis_keys = set(raw_axes) - set(_AXIS_ALLOWED)
    if unknown_axis_keys:
        raise MappingError(
            f"mapping file {path}: tools.{tool_name}.axes has unknown key(s) {sorted(unknown_axis_keys)}"
        )

    unknown_entry_keys = set(entry) - {"verb", "axes"}
    if unknown_entry_keys:
        raise MappingError(
            f"mapping file {path}: tools.{tool_name} has unknown key(s) {sorted(unknown_entry_keys)}"
        )

    return ToolMapping(verb=verb, axes=axes)
