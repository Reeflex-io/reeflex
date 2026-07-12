"""
cli.py -- `reeflex-mcp` console entry point (also `python -m reeflex_mcp`).

Bare invocation (no subcommand, backward compatible with the Track-2
interface): loads reeflex-mcp.yaml, builds the Gateway, and runs it on the
selected transport. Refuses to boot (non-zero exit, no server started) on a
bad config or on a REQUIRED upstream being unreachable -- section 21.2's
fail-closed-at-boot applied at the process level, not just inside a lifespan.

`check` subcommand (Track 3): the fail-closed self-test, mirroring
reeflex-claude's `check` -- points a real gateway subprocess at an
UNREACHABLE reeflex-core (127.0.0.1:1) in enforce mode, drives it with a real
MCP client, and asserts a real `tools/call` comes back `isError=True` with a
fail-closed reason. A pass that does NOT deny is exactly the fail-open bug
this probe exists to catch -- see cmd_check()/run_deny_probe() below.

`doctor` here is the Track 5 (design doc section 13) CLIENT-CONFIG DRIFT
CHECK -- NOT the Track 3 fail-closed self-probe (that one stays named
`check`, precisely to avoid this collision -- confirmed by the coordinator).

Track 5 subcommands (design doc section 13, reusing the reeflex-claude setup
discipline -- ownership marker, non-destructive merge, refuse-on-invalid-
JSON, prompt-or-default):
  setup    -- import mcpServers entries from the standard client config
              locations into reeflex-mcp.yaml, then rewrite each client
              config to a single gateway entry (backs up the original first).
  restore  -- undo `setup`/`import`'s rewrite of a client config from the
              backup it made.
  add      -- register a new upstream directly (not read from a client
              config); attempts a hot-reload of a running streamable-HTTP
              gateway (see gateway.py's /admin/reload route) so new tools
              appear to already-connected clients without a restart.
  import   -- pull ONE named server's definition out of a client config
              where `doctor` found it registered directly (bypassing the
              gateway) into reeflex-mcp.yaml, and remove just that one entry
              from the client config.
  doctor   -- client-config DRIFT check: compares each standard client
              config's mcpServers against the single-gateway-entry
              invariant; run automatically at gateway startup (non-fatal)
              and on demand. NO FILE-WATCHING (YAGNI) -- see lifecycle.py.

SINGLE-PATH LIMIT (design doc section 13, verbatim) -- read lifecycle.py's
module docstring: the gateway governs only what flows through it; `doctor`
detects a direct/ungoverned server, it cannot prevent one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from typing import List, Tuple

from . import client_configs, config, lifecycle
from . import registry
from .gateway import Gateway, UpstreamBootError, run_stdio, run_streamable_http
from .registry import ConfigError, load_config

_PROBE_TIMEOUT_SECONDS = 30.0
# Reserved/unreachable per the project's established convention (see
# reeflex-claude/cli.py run_deny_probe) -- forced regardless of the
# operator's real REEFLEX_CORE_URL.
_UNREACHABLE_CORE_URL = "http://127.0.0.1:1"

_CLIENT_CHOICES = ("claude-desktop", "mcp-json", "claude-settings")
_ENVIRONMENT_CHOICES = ("production", "staging", "dev")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reeflex-mcp",
        description=(
            "Reeflex MCP gateway -- governs any MCP upstream: intercepts "
            "tools/call, normalizes it into a Reeflex Action Envelope, asks "
            "reeflex-core /v1/decide. See reeflex-mcp.yaml.example."
        ),
    )
    parser.add_argument(
        "--config",
        default=None,
        help="path to reeflex-mcp.yaml (default: $REEFLEX_MCP_CONFIG or ./reeflex-mcp.yaml)",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default=None,
        help="front transport (default: $REEFLEX_MCP_TRANSPORT or stdio)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="bind host for streamable-http (default: $REEFLEX_MCP_HOST or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="bind port for streamable-http (default: $REEFLEX_MCP_PORT or 8000)",
    )

    sub = parser.add_subparsers(dest="command")
    sub.add_parser(
        "check",
        help=(
            "Fail-closed self-test: points a real gateway subprocess at an "
            "unreachable reeflex-core in enforce mode and asserts a real "
            "tools/call is denied (isError=True). A pass that does NOT deny "
            "is the fail-open bug."
        ),
    )

    p_setup = sub.add_parser(
        "setup",
        help="Import MCP client configs' mcpServers into reeflex-mcp.yaml and rewrite them "
             "to a single gateway entry (backs up the original client config first).",
    )
    p_setup.add_argument("--config", default=None, help="reeflex-mcp.yaml to write")
    p_setup.add_argument("--client", choices=_CLIENT_CHOICES, default=None,
                          help="only this client profile (default: every standard location that exists)")
    p_setup.add_argument("--path", default=None, help="an explicit client config file instead of a standard profile")
    p_setup.add_argument("--environment", choices=_ENVIRONMENT_CHOICES, default=None,
                          help="target environment for every imported upstream (default: prompt, else 'production')")
    p_setup.add_argument("--non-interactive", action="store_true",
                          help="never prompt; always use --environment or the conservative default")

    p_restore = sub.add_parser(
        "restore",
        help="Restore a client config from the backup 'setup'/'import' made before rewriting it.",
    )
    p_restore.add_argument("--client", choices=_CLIENT_CHOICES, default=None)
    p_restore.add_argument("--path", default=None)

    p_add = sub.add_parser(
        "add",
        help="Register a new upstream directly (not read from a client config); hot-reloads a "
             "running streamable-HTTP gateway if reachable, so new tools appear without a restart.",
    )
    p_add.add_argument("name")
    p_add.add_argument("--config", default=None)
    # dest="upstream_command", NOT the default "command" -- add_subparsers(dest="command")
    # ABOVE already claims that name for subcommand dispatch; sharing it would
    # silently clobber args.command with this flag's list value (found live
    # while demonstrating this command -- see the Track 5 report).
    p_add.add_argument("--command", dest="upstream_command", nargs="+", default=None,
                        help="stdio command + args, e.g. --command npx -y @modelcontextprotocol/server-filesystem /data")
    p_add.add_argument("--url", default=None, help="streamable-HTTP upstream URL")
    p_add.add_argument("--system", default=None, help="target.system (default: the upstream name itself)")
    p_add.add_argument("--environment", choices=_ENVIRONMENT_CHOICES, default="production")
    p_add.add_argument("--optional", action="store_true", help="mark required: false (default: required: true)")
    p_add.add_argument("--gateway-url", default=None,
                        help="the running gateway's base URL to hot-reload (default: derived from "
                             "$REEFLEX_MCP_HOST/$REEFLEX_MCP_PORT)")
    p_add.add_argument("--no-reload", action="store_true", help="only edit reeflex-mcp.yaml; skip the hot-reload POST")

    p_import = sub.add_parser(
        "import",
        help="Pull ONE named server's definition out of a client config where 'doctor' found it "
             "registered directly (bypassing the gateway) into reeflex-mcp.yaml.",
    )
    p_import.add_argument("name")
    p_import.add_argument("--config", default=None)
    p_import.add_argument("--client", choices=_CLIENT_CHOICES, default=None,
                           help="which client profile to search (default: all standard locations)")
    p_import.add_argument("--path", default=None)
    p_import.add_argument("--environment", choices=_ENVIRONMENT_CHOICES, default=None)
    p_import.add_argument("--non-interactive", action="store_true")
    p_import.add_argument("--gateway-url", default=None)
    p_import.add_argument("--no-reload", action="store_true")

    p_doctor = sub.add_parser(
        "doctor",
        help="Client-config drift check: warns if a server was added directly to a client "
             "(bypassing the gateway) or the gateway entry itself is missing.",
    )
    p_doctor.add_argument("--client", choices=_CLIENT_CHOICES, default=None)
    p_doctor.add_argument("--path", default=None)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "check":
        return cmd_check()
    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "restore":
        return cmd_restore(args)
    if args.command == "add":
        return cmd_add(args)
    if args.command == "import":
        return cmd_import(args)
    if args.command == "doctor":
        return cmd_doctor(args)

    return cmd_run(args)


# ---------------------------------------------------------------------------
# run -- the gateway itself (unchanged from Track 2, minus subcommand plumbing)
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    config_path = args.config if args.config is not None else config.config_path()
    transport = args.transport if args.transport is not None else config.transport()
    host = args.host if args.host is not None else config.host()
    port = args.port if args.port is not None else config.port()

    try:
        gw_config = load_config(config_path)
    except ConfigError as exc:
        print(f"[reeflex-mcp] FATAL: {exc}", file=sys.stderr)
        return 1

    gateway = Gateway(gw_config)
    print(
        f"[reeflex-mcp] mode={gateway.mode} transport={transport} "
        f"upstreams={[u.name for u in gw_config.upstreams]} config={gw_config.source_path}",
        file=sys.stderr,
    )

    # Track 5 (design doc section 13): drift check runs automatically at
    # every gateway startup (advisory, non-fatal -- boot proceeds regardless).
    # This is exactly the "no file-watching" design: a stdio client restart
    # restarts the gateway too, so a manually-edited client config is caught
    # right here, at the moment it would matter, with zero background polling.
    try:
        findings = lifecycle.check_drift()
        for finding in findings:
            print(f"[reeflex-mcp] DRIFT: {finding.message}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 -- drift check must never block boot
        print(f"[reeflex-mcp] WARN: drift check failed: {exc}", file=sys.stderr)

    try:
        if transport == "stdio":
            asyncio.run(run_stdio(gateway))
        else:
            asyncio.run(run_streamable_http(gateway, host=host, port=port))
    except UpstreamBootError as exc:
        print(f"[reeflex-mcp] FATAL: refusing to boot -- {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[reeflex-mcp] shutdown", file=sys.stderr)
        return 0

    return 0


# ---------------------------------------------------------------------------
# check -- the fail-closed self-probe (Track 3 item 4)
# ---------------------------------------------------------------------------


def resolve_gateway_command() -> List[str]:
    """Resolve how to invoke the gateway for the self-test probe.

    Prefers the real PATH-resolved `reeflex-mcp` console script (mirrors
    reeflex-claude/cli.py resolve_hook_command() exactly -- same rationale:
    finding it via PATH is itself part of what this check verifies). Falls
    back to `python -m reeflex_mcp` for a source checkout that has not been
    pip-installed (e.g. this repo's own dev venv).
    """
    exe = shutil.which("reeflex-mcp")
    if exe:
        return [exe]
    return [sys.executable, "-m", "reeflex_mcp"]


def _write_probe_config() -> str:
    """Generate a temp reeflex-mcp.yaml registering ONLY the package's
    built-in `_doctor_upstream` (no external dependency, no network, works in
    a clean `pip install reeflex-mcp` environment)."""
    yaml_text = f"""\
mode: enforce
upstreams:
  - name: doctor
    command: [{sys.executable!r}, "-m", "reeflex_mcp._doctor_upstream"]
    target: {{ system: doctor, environment: production }}
    required: true
"""
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(yaml_text)
    fh.close()
    return fh.name


async def _run_deny_probe_async(gateway_cmd: List[str], config_path: str) -> Tuple[bool, str]:
    """Launch the gateway as a REAL subprocess (stdio transport), forcing
    enforce mode + an unreachable reeflex-core, and drive it with a real MCP
    client. Returns (passed, detail_message). Never raises (all failure modes
    are captured into the detail message and reported as a FAIL)."""
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    probe_env = dict(os.environ)
    probe_env["REEFLEX_MODE"] = "enforce"
    probe_env["REEFLEX_CORE_URL"] = _UNREACHABLE_CORE_URL
    probe_env["REEFLEX_MCP_CONFIG"] = config_path

    command, *rest_args = gateway_cmd
    params = StdioServerParameters(
        command=command,
        args=[*rest_args, "--transport", "stdio"],
        env=probe_env,
    )

    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools_result = await session.list_tools()
                names = sorted(t.name for t in tools_result.tools)
                if "doctor__delete_thing" not in names:
                    return False, (
                        f"gateway booted but the built-in doctor upstream's tool was not visible "
                        f"(saw: {names}). The gateway itself may have failed to start correctly."
                    )

                result = await session.call_tool("doctor__delete_thing", {"name": "check-probe"})

                if not result.isError:
                    text = "".join(c.text for c in result.content if hasattr(c, "text"))
                    return False, (
                        "FAIL-OPEN BUG: the gateway FORWARDED a call while reeflex-core was "
                        f"unreachable in enforce mode (isError=False). content={text!r}. "
                        "This means enforce mode does not fail closed."
                    )

                text = "".join(c.text for c in result.content if hasattr(c, "text"))
                if "unreachable" not in text.lower() and "failing closed" not in text.lower():
                    return False, (
                        f"the call WAS denied (isError=True) but the reason text does not look "
                        f"like a core-unreachable fail-closed denial -- got: {text!r}. "
                        "This may indicate the probe is being denied by something else."
                    )
                return True, f"gateway denied the probe (isError=True), fail-closed verified. content={text!r}"
    except FileNotFoundError as exc:
        return False, (
            f"gateway command not found: {gateway_cmd!r} ({exc}). Confirm 'pip install "
            "reeflex-mcp' completed successfully and that the interpreter's Scripts/bin "
            "directory is on PATH."
        )
    except Exception as exc:  # noqa: BLE001 -- any probe failure is a FAIL, never a crash
        return False, f"probe failed with an unexpected error: {exc}"


def run_deny_probe(gateway_cmd: List[str], config_path: str, timeout: float = _PROBE_TIMEOUT_SECONDS) -> Tuple[bool, str]:
    """Synchronous wrapper around `_run_deny_probe_async`, with a hard
    timeout (anti-hang discipline) -- a probe that hangs is reported as a
    FAIL, never left to block `reeflex-mcp check` forever."""
    try:
        return asyncio.run(asyncio.wait_for(_run_deny_probe_async(gateway_cmd, config_path), timeout=timeout))
    except asyncio.TimeoutError:
        return False, f"probe timed out after {timeout}s -- gateway_cmd={gateway_cmd!r}"
    except Exception as exc:  # noqa: BLE001 -- belt-and-suspenders; _run_deny_probe_async already catches broadly
        return False, f"probe failed with an unexpected error: {exc}"


def cmd_check() -> int:
    gateway_cmd = resolve_gateway_command()
    config_path = _write_probe_config()
    print(f"[reeflex-mcp] probing gateway command: {gateway_cmd} (config={config_path})")
    print(f"[reeflex-mcp] forcing REEFLEX_MODE=enforce, REEFLEX_CORE_URL={_UNREACHABLE_CORE_URL}")

    try:
        passed, detail = run_deny_probe(gateway_cmd, config_path)
    finally:
        try:
            os.unlink(config_path)
        except OSError:
            pass

    print("=" * 70)
    if passed:
        print("PASS -- fail-closed verified")
    else:
        print("FAIL -- fail-closed NOT verified")
    print("=" * 70)
    print(detail)
    if not passed:
        print(
            "Remediation: reinstall with 'pip install --force-reinstall reeflex-mcp', "
            "confirm 'reeflex-mcp' resolves on PATH, then re-run 'reeflex-mcp check'."
        )

    return 0 if passed else 1


# ---------------------------------------------------------------------------
# Track 5 (design doc section 13) -- setup / restore / add / import / doctor
# ---------------------------------------------------------------------------


def _resolve_target_profiles(args: argparse.Namespace) -> List[client_configs.ClientProfile]:
    """--path wins outright (an explicit file, not a standard profile);
    else --client narrows to one standard profile; else every standard
    profile that currently exists (setup/doctor's default: process/check
    whatever is actually present, touch nothing that isn't)."""
    if getattr(args, "path", None):
        from pathlib import Path
        p = Path(args.path)
        return [client_configs.ClientProfile("custom", str(p), p)]
    if getattr(args, "client", None):
        return [client_configs.resolve_profile(args.client)]
    return [p for p in client_configs.standard_profiles() if p.path.exists()]


def _try_hot_reload(gateway_url: str | None) -> Tuple[bool, str]:
    """POST /admin/reload to a running streamable-HTTP gateway (gateway.py's
    Gateway._wire_admin()). Best-effort: an unreachable gateway (e.g. stdio
    mode, or nothing running yet) is reported, not raised -- the config
    change is still saved either way; it just takes effect on the next
    gateway start (or the next client reconnect, for stdio front)."""
    url = (gateway_url or f"http://{config.host()}:{config.port()}").rstrip("/") + "/admin/reload"
    token = os.environ.get("REEFLEX_MCP_ADMIN_TOKEN", "").strip()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        return False, (
            f"could not reach a running gateway at {url} ({exc}) -- the config change is saved; "
            "it will take effect on the next gateway start (or client reconnect for a stdio front)."
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"hot-reload request to {url} failed: {exc}"

    added = body.get("added", [])
    failed = body.get("failed", [])
    if added:
        return True, f"gateway at {url} hot-reloaded: connected {added}, tools/list_changed broadcast to front sessions."
    if failed:
        return False, f"gateway at {url} tried to hot-reload but failed: {failed}"
    return True, f"gateway at {url} reachable; nothing new to connect ({body.get('note', '')})."


def cmd_setup(args: argparse.Namespace) -> int:
    reeflex_config_path = args.config if args.config is not None else config.config_path()
    profiles = _resolve_target_profiles(args)

    if not profiles:
        print(
            "[reeflex-mcp] No standard MCP client config found (claude_desktop_config.json / "
            "project .mcp.json / .claude/settings.json). Nothing to import. Use --path to point "
            "at a specific file.",
            file=sys.stderr,
        )
        return 0

    # --environment, if given, applies uniformly and turns off prompting for
    # it; otherwise prompt per-server (interactive TTY) or fall back to the
    # conservative default (non-interactive) -- see lifecycle.prompt_or_default.
    default_environment = args.environment or "production"
    interactive = not args.non_interactive and args.environment is None

    overall_ok = True
    for profile in profiles:
        try:
            result = lifecycle.import_profile(
                profile,
                reeflex_config_path=reeflex_config_path,
                default_environment=default_environment,
                interactive=interactive,
            )
        except client_configs.ClientConfigError as exc:
            print(f"[reeflex-mcp] ERROR: {exc}", file=sys.stderr)
            overall_ok = False
            continue
        except lifecycle.LifecycleError as exc:
            print(f"[reeflex-mcp] ERROR: {exc}", file=sys.stderr)
            overall_ok = False
            continue

        if result.already_configured:
            print(f"[reeflex-mcp] {profile.label} ({profile.path}) already configured -- nothing to do.")
            continue
        if not result.imported and not result.backup_path:
            print(f"[reeflex-mcp] {profile.label} ({profile.path}) has no mcpServers -- nothing to import.")
            continue

        print(f"[reeflex-mcp] {profile.label} ({profile.path}):")
        print(f"[reeflex-mcp]   imported upstream(s): {result.imported}")
        print(f"[reeflex-mcp]   wrote {reeflex_config_path}")
        if result.backup_path:
            print(f"[reeflex-mcp]   backed up original to {result.backup_path}")
        print(f"[reeflex-mcp]   rewrote {profile.path} to a single '{client_configs.OWNERSHIP_NAME}' entry")
        for warning in result.warnings:
            print(f"[reeflex-mcp]   WARNING: {warning}", file=sys.stderr)

    print(
        "\n[reeflex-mcp] SINGLE-PATH LIMIT: the gateway governs only what flows through it. "
        "If a server is later added directly back to a client config (bypassing the gateway), "
        "that is an ungoverned path -- 'reeflex-mcp doctor' detects it but cannot prevent it. "
        "On a hostile or multi-user machine, enforce single-path at the OS/network level; in "
        "service (streamable-HTTP) mode, the robust model is network topology -- upstreams "
        "reachable only from the gateway."
    )
    return 0 if overall_ok else 1


def cmd_restore(args: argparse.Namespace) -> int:
    profiles = _resolve_target_profiles(args)
    if not profiles:
        print("[reeflex-mcp] No standard MCP client config found to restore. Use --path to specify one.",
              file=sys.stderr)
        return 1

    any_restored = False
    for profile in profiles:
        if client_configs.restore_backup(profile.path):
            print(f"[reeflex-mcp] restored {profile.path} from {client_configs.backup_path(profile.path)}")
            any_restored = True
        else:
            print(f"[reeflex-mcp] no backup found for {profile.path} -- nothing to restore.", file=sys.stderr)

    return 0 if any_restored else 1


def cmd_add(args: argparse.Namespace) -> int:
    reeflex_config_path = args.config if args.config is not None else config.config_path()

    if not args.upstream_command and not args.url:
        print("[reeflex-mcp] ERROR: 'add' requires either --command ... or --url <url>", file=sys.stderr)
        return 1
    if args.upstream_command and args.url:
        print("[reeflex-mcp] ERROR: 'add' takes exactly one of --command or --url, not both", file=sys.stderr)
        return 1

    entry: dict = {
        "name": args.name,
        "target": {"system": args.system or args.name, "environment": args.environment},
        "required": not args.optional,
    }
    if args.upstream_command:
        entry["command"] = list(args.upstream_command)
    else:
        entry["url"] = args.url

    try:
        raw = registry.load_raw_yaml(reeflex_config_path)
        registry.upsert_upstream_raw(raw, entry)
        registry.write_raw_yaml(reeflex_config_path, raw)
    except registry.ConfigError as exc:
        print(f"[reeflex-mcp] ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"[reeflex-mcp] registered upstream {args.name!r} in {reeflex_config_path}: {entry}")

    if args.no_reload:
        print("[reeflex-mcp] --no-reload given; not attempting a hot-reload.")
        return 0

    ok, detail = _try_hot_reload(args.gateway_url)
    print(f"[reeflex-mcp] {detail}")
    return 0  # the upstream IS registered either way -- hot-reload is a best-effort convenience


def cmd_import(args: argparse.Namespace) -> int:
    reeflex_config_path = args.config if args.config is not None else config.config_path()
    profiles = _resolve_target_profiles(args)

    if not profiles:
        print("[reeflex-mcp] No client config found to import from. Use --client or --path.", file=sys.stderr)
        return 1

    environment_for = {args.name: args.environment} if args.environment else {}
    found_in = None
    last_error: Exception | None = None
    result = None
    for profile in profiles:
        try:
            result = lifecycle.import_profile(
                profile,
                reeflex_config_path=reeflex_config_path,
                only_name=args.name,
                environment_for=environment_for,
                interactive=not args.non_interactive,
            )
            found_in = profile
            break
        except lifecycle.LifecycleError as exc:
            last_error = exc
            continue
        except client_configs.ClientConfigError as exc:
            print(f"[reeflex-mcp] ERROR: {exc}", file=sys.stderr)
            return 1

    if result is None or found_in is None:
        print(
            f"[reeflex-mcp] ERROR: {args.name!r} was not found as a directly-registered server in "
            f"any checked client config. {last_error or ''}",
            file=sys.stderr,
        )
        return 1

    print(f"[reeflex-mcp] imported {args.name!r} from {found_in.label} ({found_in.path}) into {reeflex_config_path}")
    if result.backup_path:
        print(f"[reeflex-mcp] backed up original to {result.backup_path}")
    print(f"[reeflex-mcp] removed {args.name!r} from {found_in.path}'s mcpServers (gateway entry preserved)")
    for warning in result.warnings:
        print(f"[reeflex-mcp] WARNING: {warning}", file=sys.stderr)

    if args.no_reload:
        return 0
    ok, detail = _try_hot_reload(args.gateway_url)
    print(f"[reeflex-mcp] {detail}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    profiles = _resolve_target_profiles(args) if (args.client or args.path) else None
    findings = lifecycle.check_drift(profiles)

    if not findings:
        print("[reeflex-mcp] doctor: no drift detected -- every checked client config is single-path.")
        return 0

    print(f"[reeflex-mcp] doctor: {len(findings)} finding(s):")
    for finding in findings:
        print(f"[reeflex-mcp]   [{finding.kind}] {finding.message}")

    print(
        "\n[reeflex-mcp] SINGLE-PATH LIMIT: a server registered directly in a client config is an "
        "ungoverned path -- doctor detects it, it cannot prevent it. Fix each finding above with "
        "the suggested 'reeflex-mcp import <name>' command."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
