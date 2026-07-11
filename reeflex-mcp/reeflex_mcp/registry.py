"""
registry.py -- load reeflex-mcp.yaml: the multi-upstream registry (design doc
section 7) plus the service-mode client/session scaffold (section 10).

This module is PURE config parsing: no network, no MCP SDK, no connections.
upstream.py turns the parsed UpstreamSpec objects into live connections.

Shape (operator-owned; secrets by-reference, never inline -- see
../design/MCP-GATEWAY-DESIGN.md section 7 for the annotated example, and
./reeflex-mcp.yaml.example in this package for a runnable one):

    mode: observe                 # observe (default) | enforce -- REEFLEX_MODE env overrides this
    upstreams:
      - name: fs                  # namespace prefix -> fs__read_file, fs__write_file ...
        command: ["python", "server.py"]      # stdio upstream (list of argv)
        target: { system: filesystem, environment: staging }
        required: true            # default true -- see section 21.2 fail-closed-at-boot
      - name: gh
        url: https://mcp.internal/github      # streamable-HTTP upstream
        auth: { token_env: GH_MCP_TOKEN }      # by-reference; read at connect time, never here
        target: { system: github, environment: production }
    clients:                      # OPTIONAL -- service-mode per-client session scaffold (section 10)
      - token_env: CLIENT_A_TOKEN # by-reference; the bearer token an HTTP front client presents
        session_id: agent:alice   # the stable session_id that token maps to (core's R5 ledger key)
    mappings_dir: ./mappings      # OPTIONAL -- Track 4 (design doc section 8) declarative mappings
                                   # directory. REEFLEX_MCP_MAPPINGS_DIR env overrides this when set
                                   # (see effective_mappings_dir()). Unset -> this package's own
                                   # bundled starter mappings (mappings.DEFAULT_MAPPINGS_DIR).

`target.environment` is the strictness lever (design doc section 7): the same
five base policy rules read harder or softer purely from this axis -- there
is no separate "prod mode" switch to forget.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field

import yaml

from . import config

_VALID_ENVIRONMENTS = frozenset({"production", "staging", "dev"})


class ConfigError(Exception):
    """Raised when reeflex-mcp.yaml is missing, malformed, or ambiguous.

    This is always a LOCAL misconfiguration -- refuse to boot (section 21.2's
    fail-closed-at-boot spirit applied to config, not just connectivity):
    an adapter that silently guesses at a broken registry is not conformant.
    """


@dataclass(frozen=True)
class UpstreamSpec:
    """One `upstreams[]` entry, fully parsed and validated (not yet connected)."""

    name: str
    kind: str  # "stdio" | "http"
    target_system: str
    target_environment: str
    required: bool = True
    # stdio
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    # http
    url: str | None = None
    auth_token_env: str | None = None  # NAME of the env var; never the value itself


@dataclass(frozen=True)
class ClientSpec:
    """One `clients[]` entry -- the service-mode auth + session scaffold (section 10)."""

    token_env: str  # NAME of the env var holding the bearer token; never the value
    session_id: str


@dataclass(frozen=True)
class GatewayConfig:
    file_mode: str | None  # raw `mode:` from the YAML, or None if absent
    upstreams: tuple[UpstreamSpec, ...]
    clients: tuple[ClientSpec, ...]
    source_path: str
    mappings_dir: str | None = None  # raw `mappings_dir:` from the YAML, or None if absent (Track 4)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_config(path: str | None = None) -> GatewayConfig:
    """Load + validate reeflex-mcp.yaml. Raises ConfigError on any problem.

    path defaults to config.config_path() (env REEFLEX_MCP_CONFIG or
    "./reeflex-mcp.yaml") when not given explicitly.
    """
    resolved_path = path if path is not None else config.config_path()

    try:
        with open(resolved_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"reeflex-mcp config not found at {resolved_path!r}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"reeflex-mcp config at {resolved_path!r} is not valid YAML: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"reeflex-mcp config at {resolved_path!r} must be a YAML mapping at the top level")

    file_mode = raw.get("mode")
    if file_mode is not None and file_mode not in ("observe", "enforce"):
        raise ConfigError(f"reeflex-mcp config 'mode' must be 'observe' or 'enforce', got {file_mode!r}")

    raw_upstreams = raw.get("upstreams")
    if not isinstance(raw_upstreams, list) or not raw_upstreams:
        raise ConfigError(
            f"reeflex-mcp config at {resolved_path!r} must have a non-empty 'upstreams' list"
        )

    seen_names: set[str] = set()
    upstreams: list[UpstreamSpec] = []
    for i, entry in enumerate(raw_upstreams):
        spec = _parse_upstream(entry, index=i, source_path=resolved_path)
        if spec.name in seen_names:
            raise ConfigError(f"reeflex-mcp config: duplicate upstream name {spec.name!r}")
        seen_names.add(spec.name)
        upstreams.append(spec)

    raw_clients = raw.get("clients") or []
    if not isinstance(raw_clients, list):
        raise ConfigError("reeflex-mcp config: 'clients' must be a list if present")
    clients = [_parse_client(entry, index=i) for i, entry in enumerate(raw_clients)]

    mappings_dir = raw.get("mappings_dir")
    if mappings_dir is not None and (not isinstance(mappings_dir, str) or not mappings_dir.strip()):
        raise ConfigError("reeflex-mcp config: 'mappings_dir' must be a non-empty string if present")

    return GatewayConfig(
        file_mode=file_mode,
        upstreams=tuple(upstreams),
        clients=tuple(clients),
        source_path=resolved_path,
        mappings_dir=mappings_dir.strip() if isinstance(mappings_dir, str) else None,
    )


def _parse_upstream(entry: object, *, index: int, source_path: str) -> UpstreamSpec:
    if not isinstance(entry, dict):
        raise ConfigError(f"reeflex-mcp config: upstreams[{index}] must be a mapping")

    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError(f"reeflex-mcp config: upstreams[{index}].name is required")
    name = name.strip()
    if "__" in name:
        raise ConfigError(
            f"reeflex-mcp config: upstreams[{index}].name={name!r} must not contain '__' "
            "(reserved as the namespace separator, e.g. 'fs__read_file')"
        )

    has_command = "command" in entry and entry.get("command") not in (None, "", [])
    has_url = "url" in entry and entry.get("url") not in (None, "")
    if has_command == has_url:  # both or neither
        raise ConfigError(
            f"reeflex-mcp config: upstream {name!r} must set exactly one of 'command' (stdio) or 'url' (http)"
        )

    target = entry.get("target")
    if not isinstance(target, dict):
        raise ConfigError(f"reeflex-mcp config: upstream {name!r} requires a 'target' mapping")
    target_system = target.get("system")
    if not isinstance(target_system, str) or not target_system.strip():
        raise ConfigError(f"reeflex-mcp config: upstream {name!r}.target.system is required")
    target_environment = target.get("environment")
    if target_environment not in _VALID_ENVIRONMENTS:
        raise ConfigError(
            f"reeflex-mcp config: upstream {name!r}.target.environment must be one of "
            f"{sorted(_VALID_ENVIRONMENTS)}, got {target_environment!r}"
        )

    required = entry.get("required", True)
    if not isinstance(required, bool):
        raise ConfigError(f"reeflex-mcp config: upstream {name!r}.required must be a boolean")

    if has_command:
        command_field = entry["command"]
        if isinstance(command_field, str):
            argv = [command_field]
        elif isinstance(command_field, list) and all(isinstance(x, str) for x in command_field):
            argv = list(command_field)
        else:
            raise ConfigError(
                f"reeflex-mcp config: upstream {name!r}.command must be a string or a list of strings"
            )
        if not argv:
            raise ConfigError(f"reeflex-mcp config: upstream {name!r}.command must not be empty")
        env_field = entry.get("env") or {}
        if not isinstance(env_field, dict):
            raise ConfigError(f"reeflex-mcp config: upstream {name!r}.env must be a mapping if present")
        return UpstreamSpec(
            name=name,
            kind="stdio",
            target_system=target_system.strip(),
            target_environment=target_environment,
            required=required,
            command=argv[0],
            args=tuple(argv[1:]),
            env={str(k): str(v) for k, v in env_field.items()},
        )

    # http
    url = entry["url"]
    if not isinstance(url, str) or not url.strip():
        raise ConfigError(f"reeflex-mcp config: upstream {name!r}.url must be a non-empty string")
    auth_token_env = None
    auth = entry.get("auth")
    if auth is not None:
        if not isinstance(auth, dict) or not isinstance(auth.get("token_env"), str):
            raise ConfigError(
                f"reeflex-mcp config: upstream {name!r}.auth must be a mapping with a string 'token_env'"
            )
        auth_token_env = auth["token_env"].strip()
        if not auth_token_env:
            raise ConfigError(f"reeflex-mcp config: upstream {name!r}.auth.token_env must not be empty")

    return UpstreamSpec(
        name=name,
        kind="http",
        target_system=target_system.strip(),
        target_environment=target_environment,
        required=required,
        url=url.strip(),
        auth_token_env=auth_token_env,
    )


def _parse_client(entry: object, *, index: int) -> ClientSpec:
    if not isinstance(entry, dict):
        raise ConfigError(f"reeflex-mcp config: clients[{index}] must be a mapping")
    token_env = entry.get("token_env")
    session_id = entry.get("session_id")
    if not isinstance(token_env, str) or not token_env.strip():
        raise ConfigError(f"reeflex-mcp config: clients[{index}].token_env is required")
    if not isinstance(session_id, str) or not session_id.strip():
        raise ConfigError(f"reeflex-mcp config: clients[{index}].session_id is required")
    return ClientSpec(token_env=token_env.strip(), session_id=session_id.strip())


# ---------------------------------------------------------------------------
# Env-ref resolution -- by-reference, resolved lazily (never at parse time)
# ---------------------------------------------------------------------------


def resolve_env_ref(var_name: str | None) -> str | None:
    """Read an env var by name, fresh, at the moment it's needed (e.g. at
    upstream connect time, or at client-token lookup time). Returns None if
    var_name is None or the env var is unset/blank. Never caches, never logs
    the resolved value.
    """
    if not var_name:
        return None
    value = os.environ.get(var_name, "").strip()
    return value or None


# ---------------------------------------------------------------------------
# Mode precedence: REEFLEX_MODE env (if explicitly set) overrides the file
# ---------------------------------------------------------------------------


def effective_mode(gw_config: GatewayConfig) -> str:
    """Resolve the gateway's operating mode.

    Precedence: REEFLEX_MODE env var, IF explicitly set, always wins (matches
    every other Reeflex adapter's env-overrides-file convention). Otherwise
    the YAML's `mode:` key. Otherwise "observe" (the never-breaks-traffic
    default -- SPEC section 6, design doc section 15).
    """
    if os.environ.get("REEFLEX_MODE", "").strip():
        return config.mode()
    if gw_config.file_mode in ("observe", "enforce"):
        return gw_config.file_mode
    return "observe"


# ---------------------------------------------------------------------------
# Mappings dir precedence (Track 4, design doc section 8): REEFLEX_MCP_MAPPINGS_DIR
# env (if explicitly set) overrides the file; same env-overrides-file
# convention as effective_mode() above.
# ---------------------------------------------------------------------------


def effective_mappings_dir(gw_config: GatewayConfig) -> str | None:
    """Resolve the declarative-mappings directory.

    Precedence: REEFLEX_MCP_MAPPINGS_DIR env var, if set, always wins.
    Otherwise the YAML's `mappings_dir:` key. Otherwise None -- which tells
    `mappings.load_mappings_dir(None)` to use this package's own bundled
    starter mappings (mappings.DEFAULT_MAPPINGS_DIR: filesystem/github/
    postgres), NOT an error or an empty registry by accident.
    """
    env_value = config.mappings_dir_env()
    if env_value:
        return env_value
    return gw_config.mappings_dir


# ---------------------------------------------------------------------------
# Client/session lookup -- section 10 service-mode scaffold
# ---------------------------------------------------------------------------


def session_id_for_token(gw_config: GatewayConfig, bearer_token: str | None) -> str | None:
    """Look up the configured session_id for a presented bearer token.

    Resolves each configured client's token_env FRESH (not at load time) so a
    rotated secret takes effect on the next call without a restart. Returns
    None if bearer_token is falsy or matches no configured client -- the
    caller (gateway.py) is responsible for falling back to a stable
    per-connection default (never an empty session_id; core requires one).
    """
    if not bearer_token:
        return None
    for client in gw_config.clients:
        configured = resolve_env_ref(client.token_env)
        if configured is not None and configured == bearer_token:
            return client.session_id
    return None


# ---------------------------------------------------------------------------
# Raw YAML read/write -- Track 5 (design doc section 13): `setup`/`add`/
# `import` PROGRAMMATICALLY register upstreams into reeflex-mcp.yaml itself.
#
# This operates on the raw parsed dict, NOT the validated GatewayConfig
# (load_config() above) -- so it can merge into a file this process has not
# necessarily fully validated yet, and re-serialization only has to
# reproduce a plain YAML mapping, not reconstruct a GatewayConfig object.
#
# HONEST LIMITATION (documented, matching reeflex_claude/setup_settings.py's
# own note about settings.json): re-serializing via `yaml.safe_dump` does
# NOT preserve comments or exact formatting in an existing reeflex-mcp.yaml
# -- only the DATA (every key/value) survives the round trip. This is the
# same deliberate, documented trade-off reeflex-claude accepts for
# settings.json; a comment-preserving YAML round-trip (e.g. via ruamel.yaml)
# would add a new dependency this package does not otherwise need -- YAGNI
# unless an operator actually asks for it.
# ---------------------------------------------------------------------------


def load_raw_yaml(path: str) -> dict:
    """Load reeflex-mcp.yaml as a raw dict (not validated). Missing file ->
    a fresh default config ({"mode": "observe", "upstreams": []}). Raises
    ConfigError on invalid YAML or a non-mapping top level -- callers MUST
    NOT write anything when this raises (no destructive fallback, matching
    client_configs.ClientConfigError's discipline for third-party files,
    applied here to our OWN config file too).
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        return {"mode": "observe", "upstreams": []}
    except yaml.YAMLError as exc:
        raise ConfigError(f"reeflex-mcp config at {path!r} is not valid YAML: {exc}") from exc

    if raw is None:
        return {"mode": "observe", "upstreams": []}
    if not isinstance(raw, dict):
        raise ConfigError(f"reeflex-mcp config at {path!r} must be a YAML mapping at the top level")
    raw.setdefault("upstreams", [])
    if not isinstance(raw["upstreams"], list):
        raise ConfigError(f"reeflex-mcp config at {path!r}: 'upstreams' must be a list")
    return raw


def write_raw_yaml(path: str, raw: dict) -> None:
    parent = pathlib.Path(path).parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(raw, fh, sort_keys=False, default_flow_style=False)


def upsert_upstream_raw(raw: dict, entry: dict) -> bool:
    """Merge one upstream entry (a plain dict shaped like one `upstreams[]`
    item) into `raw` (mutated in place), matched by `name` -- NOT by
    position, mirroring reeflex_claude/setup_settings.py's is_ours()
    philosophy applied to upstream identity instead of a hook command
    string. Returns True if an existing entry with the same name was
    replaced, False if a new one was appended.

    Idempotent: running this twice with the same `entry` is a no-op the
    second time (byte-identical replacement).
    """
    upstreams = raw.setdefault("upstreams", [])
    if not isinstance(upstreams, list):
        raise ConfigError("'upstreams' exists in reeflex-mcp.yaml but is not a list; refusing to modify.")

    name = entry.get("name")
    for i, existing in enumerate(upstreams):
        if isinstance(existing, dict) and existing.get("name") == name:
            upstreams[i] = entry
            return True
    upstreams.append(entry)
    return False


def remove_upstream_raw(raw: dict, name: str) -> bool:
    """Remove the upstream named `name` from `raw` (mutated in place).
    Returns True if it was present and removed, False if it was not found."""
    upstreams = raw.get("upstreams")
    if not isinstance(upstreams, list):
        return False
    before = len(upstreams)
    raw["upstreams"] = [u for u in upstreams if not (isinstance(u, dict) and u.get("name") == name)]
    return len(raw["upstreams"]) != before
