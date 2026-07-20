"""
lifecycle.py -- Track 5 (design doc section 13): `setup` / `add` / `import` /
`doctor` / `restore`. The CLI (cli.py) is a thin argparse wrapper around the
functions here.

SINGLE-PATH LIMIT (design doc section 13, verbatim -- read this before
trusting anything else in this module):

  "The gateway governs only what flows *through* it. A server added directly
  to the client is an ungoverned path -- doctor detects it, cannot prevent
  it. On hostile/multi-user machines, single-path must be enforced at the
  OS/network level. In service mode, single-path is enforced by network
  topology (upstreams reachable only from the gateway) -- the robust model."

Everything below is UX around that limit, not a way around it: `setup` and
`import` fix a client config so it launches ONLY the gateway; `doctor`
notices when that invariant has drifted (a server re-appeared directly, or
the gateway entry itself disappeared); none of it can stop an operator (or
an attacker with filesystem access to the client config) from adding a
server directly again five minutes later. That is a structural property of
"the client decides what to launch", not a bug in this module.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from . import client_configs, registry

_DEFAULT_ENVIRONMENT = "production"  # SPEC section 2: unknown -> safe-conservative default
_VALID_ENVIRONMENTS = ("production", "staging", "dev")


class LifecycleError(Exception):
    """A setup/add/import operation cannot proceed safely. Callers print
    this and exit non-zero; no partial/destructive write is left behind."""


# ---------------------------------------------------------------------------
# Interactive prompt helper -- mirrors reeflex_claude/cli.py's
# _prompt_or_default() exactly (same rationale: never block a non-interactive
# caller -- CI, piped input, redirected stdin -- silently use the default).
# ---------------------------------------------------------------------------


def prompt_or_default(value: str | None, label: str, default: str, choices: tuple[str, ...] | None = None) -> str:
    if value is not None:
        return value
    if sys.stdin.isatty():
        try:
            raw = input(f"{label} [{default}]: ").strip()
        except Exception:  # noqa: BLE001
            return default
        if not raw:
            return default
        if choices and raw not in choices:
            print(f"[reeflex-mcp] {raw!r} is not one of {choices}; using default {default!r}.", file=sys.stderr)
            return default
        return raw
    return default


# ---------------------------------------------------------------------------
# Deriving a reeflex-mcp.yaml upstream entry from one mcpServers entry
# ---------------------------------------------------------------------------


def sanitize_upstream_name(name: str) -> tuple[str, str | None]:
    """Upstream names must not contain '__' (the namespace separator --
    registry.py rejects it). Returns (sanitized_name, warning_or_None)."""
    if "__" not in name:
        return name, None
    sanitized = name.replace("__", "_")
    return sanitized, (
        f"mcpServers key {name!r} contains '__' (reserved as reeflex-mcp's namespace "
        f"separator) -- imported as {sanitized!r} instead."
    )


def derive_upstream_entry(
    name: str, client_entry: dict[str, Any], *, environment: str, required: bool = True
) -> tuple[dict[str, Any], list[str]]:
    """Turn one mcpServers entry into a reeflex-mcp.yaml `upstreams[]` dict.

    `target.system` defaults to the (sanitized) server name itself -- a
    predictable derivation that also means importing a server named
    "filesystem"/"github"/"postgres" automatically picks up this package's
    bundled Track 4 starter mapping for that exact name.

    Returns (entry, warnings). Raises LifecycleError if the client entry has
    neither a usable 'command' nor 'url' (nothing to import).

    SECRETS BY-REFERENCE (standing project rule): an inline auth header on a
    remote ('url') entry is NEVER copied into reeflex-mcp.yaml -- only a
    warning telling the operator to set it up via `auth.token_env` by hand.
    A stdio entry's own 'env' block IS copied (that is how MCP clients
    themselves configure a child process's environment -- there is no
    by-reference alternative in that shape), but flagged for the operator to
    review, since it MAY contain an inline secret the client config's own
    author put there directly.
    """
    warnings: list[str] = []
    sanitized_name, name_warning = sanitize_upstream_name(name)
    if name_warning:
        warnings.append(name_warning)

    entry: dict[str, Any] = {
        "name": sanitized_name,
        "target": {"system": sanitized_name, "environment": environment},
        "required": required,
    }

    command = client_entry.get("command")
    url = client_entry.get("url")

    if isinstance(command, str) and command.strip():
        args = client_entry.get("args")
        argv = [command, *args] if isinstance(args, list) else [command]
        entry["command"] = argv
        env = client_entry.get("env")
        if isinstance(env, dict) and env:
            entry["env"] = {str(k): str(v) for k, v in env.items()}
            warnings.append(
                f"{sanitized_name!r}: copied this server's 'env' block verbatim from the client "
                "config into reeflex-mcp.yaml -- review it for any inline secret; prefer a real "
                "env var reference wherever possible."
            )
    elif isinstance(url, str) and url.strip():
        entry["url"] = url
        headers = client_entry.get("headers")
        if isinstance(headers, dict) and headers:
            warnings.append(
                f"{sanitized_name!r}: the client config has HTTP headers on this entry (commonly an "
                "inline auth token) that were NOT copied -- reeflex-mcp.yaml requires secrets "
                "by-reference. Set the token in an env var and add "
                "'auth: { token_env: <VAR_NAME> }' to this upstream by hand."
            )
    else:
        raise LifecycleError(f"mcpServers entry {name!r} has neither a usable 'command' nor 'url' -- cannot import it")

    return entry, warnings


# ---------------------------------------------------------------------------
# setup / import -- read a client config, write reeflex-mcp.yaml, rewrite
# the client config to the single gateway entry, backup first.
# ---------------------------------------------------------------------------


@dataclass
class ImportResult:
    profile_key: str
    path: str
    backup_path: str | None
    imported: list[str]
    warnings: list[str]
    already_configured: bool = False


def import_profile(
    profile: client_configs.ClientProfile,
    *,
    reeflex_config_path: str,
    only_name: str | None = None,
    environment_for: dict[str, str] | None = None,
    default_environment: str = _DEFAULT_ENVIRONMENT,
    interactive: bool = True,
    core_url: str | None = None,
    mode: str | None = None,
) -> ImportResult:
    """Import foreign mcpServers entries from ONE client profile into
    reeflex-mcp.yaml, then rewrite that client config.

    only_name: if given, ONLY that one server is imported/removed (Track 5's
      `import <name>` -- a surgical fix for one drifted server); any OTHER
      foreign entries in the same file are left untouched. If None (Track
      5's `setup`), EVERY foreign entry is imported and the client config's
      mcpServers is replaced wholesale with just the gateway entry.
    environment_for: optional {server_name: environment} overrides (skips
      the interactive prompt/default for that ONE server -- e.g. `import
      <name> --environment prod`).
    default_environment: used for any server NOT in `environment_for` --
      either as the interactive prompt's default, or (if interactive=False)
      the value used directly, e.g. `setup --environment staging` applies
      this to every imported server uniformly.
    interactive: if False, never prompts -- always uses default_environment
      (or the environment_for override) directly. Used by tests, CI, and
      any caller that passed an explicit --environment.
    core_url/mode: forwarded verbatim to client_configs.gateway_entry() (BUG
      3(2)) -- when given, the scaffolded gateway entry carries an "env"
      block (REEFLEX_CORE_URL/REEFLEX_MODE) so the launched gateway can
      reach reeflex-core without a hand-edit. None (the default) reproduces
      the prior no-env entry, e.g. for callers (cmd_import) not yet wired to
      pass them.

    Raises client_configs.ClientConfigError on invalid JSON (refuses to
    write anything). Raises LifecycleError if `only_name` is given but not
    found as a foreign entry.
    """
    environment_for = environment_for or {}
    data = client_configs.load_client_config(profile.path)
    servers = client_configs.get_mcp_servers(data)

    foreign = {n: e for n, e in servers.items() if not client_configs.is_ours(n, e)}
    gateway_already_present = any(client_configs.is_ours(n, e) for n, e in servers.items())

    if only_name is not None:
        if only_name not in foreign:
            raise LifecycleError(
                f"{only_name!r} is not a foreign (non-reeflex-mcp) server in {profile.path} -- nothing to import"
            )
        targets = {only_name: foreign[only_name]}
    else:
        targets = foreign

    if not targets:
        if gateway_already_present and not foreign:
            return ImportResult(profile.key, str(profile.path), None, [], [], already_configured=True)
        return ImportResult(profile.key, str(profile.path), None, [], [])

    raw = registry.load_raw_yaml(reeflex_config_path)
    imported: list[str] = []
    all_warnings: list[str] = []
    for name, client_entry in targets.items():
        if not isinstance(client_entry, dict):
            all_warnings.append(f"{name!r}: mcpServers entry is not an object -- skipped")
            continue
        environment = environment_for.get(name)
        if environment is None:
            environment = prompt_or_default(
                None if interactive else default_environment,
                f"Target environment for {name!r} (production|staging|dev)",
                default_environment,
                choices=_VALID_ENVIRONMENTS,
            )
        try:
            entry, warnings_ = derive_upstream_entry(name, client_entry, environment=environment)
        except LifecycleError as exc:
            all_warnings.append(str(exc))
            continue
        registry.upsert_upstream_raw(raw, entry)
        imported.append(entry["name"])
        all_warnings.extend(warnings_)

    registry.write_raw_yaml(reeflex_config_path, raw)

    # -- backup + rewrite the client config --------------------------------
    backup = client_configs.make_backup(profile.path)

    if only_name is not None:
        # Surgical: remove ONLY the named entry; keep every other entry
        # (including any other foreign ones NOT being imported right now)
        # untouched, and ensure our gateway entry is present.
        new_servers = dict(servers)
        new_servers.pop(only_name, None)
        new_servers[client_configs.OWNERSHIP_NAME] = client_configs.gateway_entry(
            config_path=reeflex_config_path, core_url=core_url, mode=mode
        )
        new_data = dict(data)
        new_data["mcpServers"] = new_servers
    else:
        # Bulk setup: the client now launches ONLY the gateway.
        new_data = dict(data)
        new_data["mcpServers"] = {
            client_configs.OWNERSHIP_NAME: client_configs.gateway_entry(
                config_path=reeflex_config_path, core_url=core_url, mode=mode
            )
        }

    client_configs.write_client_config(profile.path, new_data)

    return ImportResult(
        profile_key=profile.key,
        path=str(profile.path),
        backup_path=str(backup) if backup else None,
        imported=imported,
        warnings=all_warnings,
    )


# ---------------------------------------------------------------------------
# Drift detection -- `doctor`
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftFinding:
    profile_key: str
    profile_label: str
    path: str
    kind: str  # "foreign_server" | "gateway_missing" | "invalid_config"
    server_name: str | None
    message: str


def check_drift(profiles: list[client_configs.ClientProfile] | None = None) -> list[DriftFinding]:
    """Compare each standard client config's mcpServers against the
    single-gateway-entry invariant `setup`/`import` establish. A profile
    whose file does not exist is silently skipped (nothing to check) --
    this is a per-call comparison, NOT a background watcher (design doc
    section 13: no file-watching)."""
    profiles = profiles if profiles is not None else client_configs.standard_profiles()
    findings: list[DriftFinding] = []

    for profile in profiles:
        if not profile.path.exists():
            continue
        try:
            data = client_configs.load_client_config(profile.path)
        except client_configs.ClientConfigError as exc:
            findings.append(
                DriftFinding(profile.key, profile.label, str(profile.path), "invalid_config", None, str(exc))
            )
            continue

        servers = client_configs.get_mcp_servers(data)
        if not servers:
            continue

        foreign = {n: e for n, e in servers.items() if not client_configs.is_ours(n, e)}
        gateway_present = any(client_configs.is_ours(n, e) for n, e in servers.items())

        # A "custom" profile came from an explicit --path (test/one-off
        # usage, e.g. cli.py's _resolve_target_profiles), not one of the
        # --client CHOICES -- the suggested fix must use --path there
        # instead of a --client value the CLI would reject.
        fix_flag = f"--path {profile.path}" if profile.key == "custom" else f"--client {profile.key}"

        for name in foreign:
            findings.append(
                DriftFinding(
                    profile.key,
                    profile.label,
                    str(profile.path),
                    "foreign_server",
                    name,
                    f"{profile.label} ({profile.path}) has {name!r} registered directly -- an "
                    f"UNGOVERNED PATH (bypasses reeflex-mcp entirely). Fix: "
                    f"reeflex-mcp import {name} {fix_flag}",
                )
            )

        if foreign and not gateway_present:
            findings.append(
                DriftFinding(
                    profile.key,
                    profile.label,
                    str(profile.path),
                    "gateway_missing",
                    None,
                    f"{profile.label} ({profile.path}) has no reeflex-mcp gateway entry at all -- "
                    "run 'reeflex-mcp setup' to wire it in.",
                )
            )

    return findings
