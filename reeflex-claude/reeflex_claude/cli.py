"""
cli.py -- console entry point for the `reeflex-claude` package.

Subcommands:
  hook   -- the PreToolUse stdin/stdout hook. EXACTLY the existing protocol
            (delegates to reeflex_claude.hook.main(); byte-for-byte identical
            to hook_entry.py / `python -m reeflex_claude`). This is what
            Claude Code's settings.json invokes.
  setup  -- writes/merges the PreToolUse hook entry into Claude Code
            settings.json (project or global), fail-CLOSED by default.
  check  -- the F12 self-test as a first-class command: proves the hook
            fails closed (deny + exit 0) on an unreachable core, and warns
            if settings.json is not wired up.

STRUCTURAL FIX (code-reports/cold-start-doc-fidelity-friction-log-dev-2-
20260701.md, finding F12): once pip-installed, `reeflex-claude` is a console
entry point resolved via PATH. The hook command written by `setup` is the
bare string "reeflex-claude hook" -- no absolute path, no cwd-dependent
`python -m` import -- so the "wrong cwd -> ModuleNotFoundError -> non-zero
exit -> Claude Code silently runs the tool anyway" failure class cannot occur
on this path. It remains possible only on the git-clone / hook_entry.py
"Development install" path documented in README.md, which retains its own
warning and manual verify instructions.
"""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import subprocess
import sys
from typing import List, Optional, Tuple

from .enforce import _DEFAULT_CORE_URL as DEFAULT_CORE_URL
from .setup_settings import (
    DEFAULT_MATCHER,
    DEFAULT_TIMEOUT,
    HOOK_COMMAND,
    SettingsError,
    has_hook_entry,
    load_settings,
    merge_env,
    merge_hook_entry,
    resolve_settings_path,
    write_settings,
)

DEFAULT_MODE = "enforce"
DEFAULT_VERIFY_SSL = "true"
DEFAULT_ENVIRONMENT = "production"

# Deny-scenario probe payload (F12 self-test). session_id is fixed and
# clearly synthetic so a resulting audit record is unambiguous.
_CHECK_PAYLOAD = {
    "session_id": "reeflex-claude-check",
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "rm -rf /"},
    "cwd": "/",
}

_PROBE_TIMEOUT_SECONDS = 15


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_target_flags(subparser: argparse.ArgumentParser) -> None:
    group = subparser.add_mutually_exclusive_group()
    group.add_argument(
        "--project", dest="target", action="store_const", const="project",
        help="Target ./.claude/settings.json relative to the current directory (default).",
    )
    group.add_argument(
        "--global", dest="target", action="store_const", const="global",
        help="Target ~/.claude/settings.json instead of the project settings file.",
    )
    subparser.set_defaults(target="project")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reeflex-claude",
        description="Reeflex governance adapter for Claude Code PreToolUse hooks.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser(
        "hook",
        help="Run the PreToolUse hook (reads one JSON payload on stdin, prints one "
             "JSON verdict on stdout, always exits 0). This is what settings.json invokes.",
    )

    p_setup = sub.add_parser(
        "setup",
        help="Write/merge the PreToolUse hook entry into Claude Code settings.json.",
    )
    _add_target_flags(p_setup)
    p_setup.add_argument(
        "--core-url", default=None,
        help=f"Reeflex core URL (default {DEFAULT_CORE_URL}).",
    )
    p_setup.add_argument(
        "--token", default=None,
        help="Optional bearer token for core auth. Prefer exporting REEFLEX_CORE_TOKEN "
             "in your shell/CI secret store instead of passing it here -- see README.",
    )
    p_setup.add_argument(
        "--verify-ssl", default=None, choices=("true", "false"),
        help="Verify TLS certificates on calls to core (default true). Set to false "
             "only for dev/self-signed endpoints, at your own risk.",
    )
    p_setup.add_argument(
        "--mode", default=None, choices=("enforce", "observe"),
        help="enforce = fail-closed (default, what setup writes). observe = fail-open "
             "calibration mode; recommended only for a first dry-run.",
    )
    p_setup.add_argument(
        "--env", dest="environment", default=None,
        choices=("production", "staging", "dev"),
        help="Target environment recorded on every action (default production).",
    )

    p_check = sub.add_parser(
        "check",
        help="Verify the fail-closed hook installation (deny-scenario self-test).",
    )
    _add_target_flags(p_check)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "hook":
        return cmd_hook(args)
    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "check":
        return cmd_check(args)

    parser.print_help()
    return 1


# ---------------------------------------------------------------------------
# hook
# ---------------------------------------------------------------------------

def cmd_hook(_args: argparse.Namespace) -> int:
    """
    Delegate to the existing hook.main() -- byte-for-byte the same protocol
    as hook_entry.py. hook.main() always calls sys.exit(0) itself (its own
    fail-closed safety net); that SystemExit propagates through this function
    unchanged, which is exactly what we want -- we never want CLI-level logic
    between us and that guarantee.
    """
    from .hook import main as hook_main
    hook_main()
    return 0  # unreachable in practice: hook_main() always sys.exit(0)s first.


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------

def _prompt_or_default(value, label: str, default: str, choices: Optional[Tuple[str, ...]] = None) -> str:
    """
    Return `value` if given (flag was passed). Otherwise, if stdin is a TTY,
    prompt interactively with `default` shown; otherwise (non-interactive --
    CI, piped, redirected) silently use `default`. Never blocks a
    non-interactive caller.
    """
    if value is not None:
        return value
    if sys.stdin.isatty():
        try:
            raw = input(f"{label} [{default}]: ").strip()
        except Exception:
            return default
        if not raw:
            return default
        if choices and raw not in choices:
            print(f"[reeflex-claude] '{raw}' is not one of {choices}; using default '{default}'.",
                  file=sys.stderr)
            return default
        return raw
    return default


def _prompt_token(value: Optional[str]) -> Optional[str]:
    """
    Return `value` if given. Otherwise, only when interactive, offer a masked
    prompt (getpass) so a token is never echoed to the terminal/scrollback.
    Non-interactive callers get None (no token configured) -- the printed
    guidance tells the operator to set REEFLEX_CORE_TOKEN via env instead.
    """
    if value is not None:
        return value or None
    if sys.stdin.isatty():
        try:
            raw = getpass.getpass(
                "Bearer token for core auth (optional -- leave blank to configure "
                "REEFLEX_CORE_TOKEN via env instead): "
            )
        except Exception:
            return None
        return raw.strip() or None
    return None


def cmd_setup(args: argparse.Namespace) -> int:
    path = resolve_settings_path(args.target)

    try:
        settings = load_settings(path)
    except SettingsError as exc:
        print(f"[reeflex-claude] ERROR: {exc}", file=sys.stderr)
        return 1

    core_url    = _prompt_or_default(args.core_url, "Reeflex core URL", DEFAULT_CORE_URL)
    mode        = _prompt_or_default(args.mode, "Mode (enforce|observe)", DEFAULT_MODE,
                                      choices=("enforce", "observe"))
    verify_ssl  = _prompt_or_default(args.verify_ssl, "Verify SSL (true|false)", DEFAULT_VERIFY_SSL,
                                      choices=("true", "false"))
    environment = _prompt_or_default(args.environment, "Target environment (production|staging|dev)",
                                      DEFAULT_ENVIRONMENT, choices=("production", "staging", "dev"))
    token       = _prompt_token(args.token)

    try:
        replaced = merge_hook_entry(settings, command=HOOK_COMMAND,
                                     matcher=DEFAULT_MATCHER, timeout=DEFAULT_TIMEOUT)

        env_updates = {
            "REEFLEX_CORE_URL": core_url,
            "REEFLEX_MODE": mode,
            "REEFLEX_CLAUDE_ENVIRONMENT": environment,
            "REEFLEX_VERIFY_SSL": verify_ssl,
        }
        if token:
            env_updates["REEFLEX_CORE_TOKEN"] = token

        merge_env(settings, env_updates)
        write_settings(path, settings)
    except SettingsError as exc:
        print(f"[reeflex-claude] ERROR: {exc}", file=sys.stderr)
        return 1

    action = "Updated existing" if replaced else "Wrote new"
    print(f"[reeflex-claude] {action} PreToolUse hook entry in {path}")
    print(f"[reeflex-claude]   matcher: {DEFAULT_MATCHER}")
    print(f"[reeflex-claude]   command: {HOOK_COMMAND}  (timeout {DEFAULT_TIMEOUT}s)")
    shown_env = {k: ("***" if k == "REEFLEX_CORE_TOKEN" else v) for k, v in env_updates.items()}
    print(f"[reeflex-claude]   env: {json.dumps(shown_env)}")

    if token:
        print(
            "[reeflex-claude] WARNING: REEFLEX_CORE_TOKEN was written in PLAINTEXT to "
            f"{path}. If this file is committed to version control, rotate the token "
            "and treat it as leaked. Prefer exporting REEFLEX_CORE_TOKEN as a shell/CI "
            "secret instead of passing --token, especially with --project settings that "
            "are often shared/committed."
        )
    else:
        print(
            "[reeflex-claude] No token configured. If your core requires bearer auth, "
            "set REEFLEX_CORE_TOKEN in your environment (by reference -- never hardcode "
            "it) before Claude Code launches; see README."
        )

    if mode == "enforce":
        print("[reeflex-claude] Mode: ENFORCE (fail-closed) -- the safe default for a governance gate.")
        print(
            "[reeflex-claude] TIP: for a zero-risk first calibration pass, rerun with "
            "--mode observe, review the audit log, then switch back to enforce (the "
            "default) once policy is tuned."
        )
    else:
        print(
            "[reeflex-claude] Mode: OBSERVE (fail-open, calibration only) -- no tool call "
            "is ever blocked in this mode. Switch to --mode enforce once you have "
            "reviewed the audit log."
        )

    print("[reeflex-claude] Now run: reeflex-claude check")
    return 0


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def resolve_hook_command() -> List[str]:
    """
    Resolve how to invoke the hook for the self-test probe.

    Prefers the real PATH-resolved `reeflex-claude` console script -- this is
    the exact thing settings.json's bare "reeflex-claude hook" command relies
    on, so finding it via PATH is itself part of what this check verifies.

    Falls back to `python -m reeflex_claude.cli hook` (the identical code
    path) when the console script is not on PATH -- e.g. a source checkout
    that has not been `pip install`-ed, such as this test suite. That fallback
    exercises the SAME hook.main() logic, just not PATH resolution itself;
    the real PATH-resolution proof is the clean-venv install test (see
    PUBLISH-PYPI.md / the BUILD PROOF step), not this unit-level fallback.
    """
    exe = shutil.which("reeflex-claude")
    if exe:
        return [exe, "hook"]
    return [sys.executable, "-m", "reeflex_claude.cli", "hook"]


def run_deny_probe(hook_cmd: List[str], timeout: float = _PROBE_TIMEOUT_SECONDS) -> Tuple[bool, str]:
    """
    Run hook_cmd with a destructive ('rm -rf /') payload on stdin and verify
    it fails CLOSED: stdout contains permissionDecision == "deny" and the
    process exits 0.

    The probe deliberately forces REEFLEX_MODE=enforce and points
    REEFLEX_CORE_URL at an unreachable address (127.0.0.1:1), regardless of
    the operator's real configuration. This checks the ADAPTER's fail-closed
    PLUMBING (installed correctly, invokable, denies on an unreachable core)
    -- not the operator's policy configuration, which is the core's job to
    enforce and is out of scope for this adapter-level self-test.

    Returns (passed, detail_message). Never raises.
    """
    import os
    probe_env = dict(os.environ)
    probe_env["REEFLEX_MODE"] = "enforce"
    probe_env["REEFLEX_CORE_URL"] = "http://127.0.0.1:1"  # reserved/unreachable

    payload = json.dumps(_CHECK_PAYLOAD)

    try:
        proc = subprocess.run(
            hook_cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=probe_env,
        )
    except FileNotFoundError as exc:
        return False, (
            f"hook command not found: {hook_cmd!r} ({exc}). Confirm 'pip install "
            "reeflex-claude' completed successfully and that the interpreter's "
            "Scripts/bin directory is on PATH."
        )
    except subprocess.TimeoutExpired:
        return False, f"hook command timed out after {timeout}s: {hook_cmd!r}."
    except Exception as exc:  # noqa: BLE001
        return False, f"failed to run hook command {hook_cmd!r}: {exc}"

    if proc.returncode != 0:
        return False, (
            f"hook exited {proc.returncode} (expected 0). A non-zero exit from a "
            "PreToolUse hook makes Claude Code run the tool anyway -- this IS the "
            f"fail-open bug. stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )

    try:
        parsed = json.loads(proc.stdout.strip())
        decision = parsed["hookSpecificOutput"]["permissionDecision"]
    except Exception as exc:  # noqa: BLE001
        return False, (
            f"could not parse hook stdout as the expected hookSpecificOutput JSON "
            f"contract: {exc}; stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )

    if decision != "deny":
        return False, (
            f"hook returned permissionDecision={decision!r} for a destructive probe "
            "(expected 'deny'). This probe forces REEFLEX_MODE=enforce, so this is "
            "unexpected regardless of your normal configuration."
        )

    return True, f"hook denied the probe and exited 0 (fail-closed verified). stdout={proc.stdout.strip()}"


def cmd_check(args: argparse.Namespace) -> int:
    hook_cmd = resolve_hook_command()
    print(f"[reeflex-claude] probing hook command: {hook_cmd}")
    passed, detail = run_deny_probe(hook_cmd)

    print("=" * 70)
    if passed:
        print("PASS -- fail-closed verified")
    else:
        print("FAIL -- fail-closed NOT verified")
    print("=" * 70)
    print(detail)
    if not passed:
        print(
            "Remediation: reinstall with 'pip install --force-reinstall reeflex-claude', "
            "confirm 'reeflex-claude hook' resolves on PATH, then re-run 'reeflex-claude check'."
        )

    # Advisory settings check -- does not affect PASS/FAIL exit code.
    path = resolve_settings_path(args.target)
    if path.exists():
        try:
            settings = load_settings(path)
        except SettingsError as exc:
            print(f"[reeflex-claude] WARNING: could not check {path}: {exc}")
        else:
            if has_hook_entry(settings):
                print(f"[reeflex-claude] settings OK: {path} contains the reeflex-claude PreToolUse hook.")
            else:
                print(
                    f"[reeflex-claude] WARNING: {path} exists but does not contain a "
                    "reeflex-claude PreToolUse hook entry. Run 'reeflex-claude setup' to wire it in."
                )
    else:
        print(
            f"[reeflex-claude] NOTE: {path} not found. The hook works standalone, but "
            "Claude Code will not call it until you run 'reeflex-claude setup'."
        )

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
