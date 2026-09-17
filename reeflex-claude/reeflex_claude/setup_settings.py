"""
setup_settings.py -- Claude Code settings.json read/merge/write for `reeflex-claude setup`.

Implements the F12 structural fix (code-reports/cold-start-doc-fidelity-friction-log-
dev-2-20260701.md): the PreToolUse hook command must not be a cwd-dependent
`python -m` import, because "wrong cwd -> ModuleNotFoundError -> non-zero exit ->
Claude Code silently runs the tool anyway" is a silent-allow bypass.

A BARE console entry point (`reeflex-claude hook`) does not close that hole, it
only moves it from cwd to PATH: pip-install into a virtualenv, launch `claude`
from a normal shell, and the hook is `command not found` -> non-zero exit ->
every tool call runs UNGATED, with no audit record and no message from Claude
Code. Measured on a real agent (qa--032). So `setup` wires the ABSOLUTE path of
the installed entry point -- see resolve_hook_command() -- which depends on
neither cwd nor the launching shell's PATH. `reeflex-claude check` resolves the
same way, so the command it probes is the command Claude Code will actually run.

The matcher is a WILDCARD, deliberately. Claude Code treats `matcher` as an
allowlist: a tool whose name does not match never reaches the hook at all, so an
allowlist of built-in tool names silently exempts every `mcp__*` tool, Task,
SlashCommand, Skill and every tool added to Claude Code after this string was
written. A governance gate cannot be enumerated in advance -- classify.py's
_classify_unknown() exists precisely to price a tool we have never seen, and it
is unreachable unless the matcher lets the event through.

MERGE SEMANTICS (never clobber):
  - Load existing JSON (or start from {} if the file is absent/empty).
  - Identify "our" hook entry by substring match on the command
    (`"reeflex-claude hook" in command`) -- NOT by position, so a hand-edited
    file with the hook entry anywhere in hooks.PreToolUse is still found.
  - If found: update that entry's type/command/timeout in place and refresh its
    containing block's matcher to the canonical value. Every other key, every
    other PreToolUse block, and every other hook entry is left untouched.
  - If not found: append a NEW PreToolUse block. Nothing existing is removed.
  - env values (REEFLEX_CORE_URL etc.) are merged into settings["env"] --
    existing unrelated keys in that object are preserved.
  - On invalid JSON or a non-object top level, raise SettingsError and DO NOT
    write anything -- no destructive fallback. The caller is responsible for
    surfacing this to the operator and exiting non-zero.

NOTE on "byte-safe": re-serialization uses `json.dumps(..., indent=2)`, which
preserves every existing key, value, and (dict-insertion) key order exactly,
but normalizes whitespace/indentation. Exact byte-for-byte formatting
preservation (e.g. via a comment-preserving JSON5 round-trip) is not needed --
Claude Code's settings.json is plain JSON with no comments -- and is YAGNI for
this scope. UPGRADE PATH: a surgical text-patcher if byte-identical formatting
of untouched regions is ever required.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Dict

from .deadline import HOOK_TIMEOUT_ENV, RUNNER_TIMEOUT_SECONDS

# ---------------------------------------------------------------------------
# Canonical hook entry
# ---------------------------------------------------------------------------

# Every tool, including ones that do not exist yet. See the module docstring:
# the matcher is an allowlist, so anything absent from it reaches no gate.
DEFAULT_MATCHER = "*"

# Fallback command, and the ownership marker. hook_command_for_settings() prefers the
# absolute path of the installed entry point.
HOOK_COMMAND = "reeflex-claude hook"

# The hook timeout written into settings.json. It is an ALIAS of deadline.py's
# RUNNER_TIMEOUT_SECONDS and not a second declaration of 30, because RFX-321
# was two numbers in two files with no clamp between them: the installer wrote
# 30 here, the adapter honoured any REEFLEX_CLAUDE_TIMEOUT an operator set, and
# at 45 the runner killed the hook and `rm -rf` ran with no human. One constant,
# imported by both, is the structural half of that fix.
DEFAULT_TIMEOUT = int(RUNNER_TIMEOUT_SECONDS)

# Substring used to identify "our" hook entry among possibly-foreign ones.
_OWNERSHIP_MARKER = "reeflex-claude hook"


def hook_command_for_settings() -> str:
    """
    The hook command to wire into settings.json.

    Prefer the ABSOLUTE path of the installed `reeflex-claude` entry point: a
    PreToolUse hook is spawned by Claude Code, whose PATH is whatever the user's
    launching shell had -- not the virtualenv pip installed into. A bare name
    that fails to resolve exits non-zero, which Claude Code treats as "continue",
    i.e. a silent allow with no audit record.

    When the console script cannot be located (source checkout, exotic install
    layout), fall back to this interpreter's ABSOLUTE path plus `-m` -- the same
    two-tier resolution `reeflex-claude check` uses for its probe, so the command
    that is wired is the command that is verified. Both branches are absolute, so
    neither depends on the launching shell's PATH; `check`'s deny probe is what
    confirms the module is actually importable.
    """
    exe = shutil.which("reeflex-claude")
    if exe:
        return f"{shlex.quote(exe)} hook"
    return f"{shlex.quote(sys.executable)} -m reeflex_claude.cli hook"


class SettingsError(Exception):
    """Raised when settings.json cannot be safely read or merged. Never write on this."""


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def resolve_settings_path(target: str) -> Path:
    """
    target: "project" -> ./.claude/settings.json (relative to CURRENT cwd)
            "global"  -> ~/.claude/settings.json
    """
    if target == "global":
        return Path.home() / ".claude" / "settings.json"
    return Path.cwd() / ".claude" / "settings.json"


# ---------------------------------------------------------------------------
# Load / merge / write
# ---------------------------------------------------------------------------

def load_settings(path: Path) -> Dict[str, Any]:
    """
    Load settings.json at path. Missing file or empty file -> {} (fresh install).
    Raises SettingsError on invalid JSON or a non-object top level -- callers
    MUST NOT write anything when this raises (no destructive fallback).
    """
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SettingsError(
            f"{path} is not valid JSON ({exc}); refusing to modify it. "
            "Fix the file by hand (or move it aside) and re-run 'reeflex-claude setup'."
        ) from exc
    if not isinstance(data, dict):
        raise SettingsError(
            f"{path} does not contain a JSON object at the top level; refusing to modify it."
        )
    return data


def is_ours(command: Any) -> bool:
    """
    True if `command` is one of our hook entries.

    Recognises all three forms our own `setup` has ever written:
      * the bare console script (`reeflex-claude hook`) -- every release <= 0.1.7
      * an absolute path to the console script, possibly shell-quoted, where the
        quote character lands between the executable name and `hook`
      * `<abs python> -m reeflex_claude.cli hook` (note the UNDERSCORE: the
        module name, not the distribution name)
    Without all three, `setup` would append a duplicate entry alongside an older
    one instead of updating it in place, leaving two hooks on one tool call.
    """
    if not isinstance(command, str):
        return False
    if _OWNERSHIP_MARKER in command:
        return True
    names = ("reeflex-claude", "reeflex_claude")
    if not any(n in command for n in names):
        return False
    return re.search(r"(^|\s)hook(\s|$)", command) is not None


def wired_hook_command(settings: Dict[str, Any]):
    """
    Return the hook command string currently wired into settings, or None.

    `check` needs this: resolving the command itself only proves that the
    INSTALLING shell can find the entry point, which it always can. The command
    that matters is the one Claude Code will spawn -- the string in the file.
    """
    hooks_root = settings.get("hooks")
    if not isinstance(hooks_root, dict):
        return None
    pretool = hooks_root.get("PreToolUse")
    if not isinstance(pretool, list):
        return None
    for block in pretool:
        if not isinstance(block, dict):
            continue
        block_hooks = block.get("hooks")
        if not isinstance(block_hooks, list):
            continue
        for item in block_hooks:
            if isinstance(item, dict) and is_ours(item.get("command")):
                return item.get("command")
    return None


def wired_hook_timeout(settings: Dict[str, Any]):
    """
    Return the timeout (seconds) on our wired hook entry, or None.

    This is the number that decides when Claude Code's runner KILLS the hook,
    and therefore the number the adapter's internal deadline has to stay inside
    (deadline.py).  `check` reads it so an installation whose two numbers have
    drifted apart -- a hand-edited file, an upgrade over an older entry -- is
    visible before it matters rather than after an `rm -rf`.
    """
    hooks_root = settings.get("hooks")
    if not isinstance(hooks_root, dict):
        return None
    pretool = hooks_root.get("PreToolUse")
    if not isinstance(pretool, list):
        return None
    for block in pretool:
        if not isinstance(block, dict):
            continue
        block_hooks = block.get("hooks")
        if not isinstance(block_hooks, list):
            continue
        for item in block_hooks:
            if isinstance(item, dict) and is_ours(item.get("command")):
                value = item.get("timeout")
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    return None
                return float(value)
    return None


def deadline_mismatch(settings: Dict[str, Any]):
    """
    Describe how this installation's two timeout numbers disagree, or None.

    There are two, and RFX-321 is what happens when nothing compares them:
      * the hook entry's `timeout` -- when the runner kills us;
      * `REEFLEX_CLAUDE_HOOK_TIMEOUT` in settings["env"] -- what the hook
        believes that number is.
    `setup` writes both from one value, so they agree on a fresh install.  They
    can still drift by hand, and BOTH directions of drift are a real
    installation:

      * an env value LARGER than the entry's timeout claims more budget than
        the runner will give.  deadline.py clamps it away regardless -- this is
        the check that tells the operator rather than silently being right for
        them.
      * an entry timeout SMALLER than the built-in default with NO env value to
        declare it.  This one is not cosmetic and the clamp does not save it:
        the hook believes it has RUNNER_TIMEOUT_SECONDS, sets its deadline
        inside THAT, and the runner kills it first -- which is RFX-321 again,
        reached by hand-editing the entry down instead of the socket timeout
        up.  The hook cannot detect this on its own: it is handed a payload on
        stdin, not the path of the settings file that summoned it, and Claude
        Code merges several of those.  So `check` is where it can be seen.
    """
    entry = wired_hook_timeout(settings)
    if entry is None:
        return None
    env = settings.get("env")
    if not isinstance(env, dict):
        env = {}
    raw = str(env.get(HOOK_TIMEOUT_ENV, "")).strip()
    if not raw:
        if entry < RUNNER_TIMEOUT_SECONDS:
            return (f"the hook entry's timeout is {entry:.0f}s but nothing tells the "
                    f"hook so, and it assumes its built-in "
                    f"{RUNNER_TIMEOUT_SECONDS:.0f}s. The runner would kill the hook "
                    f"before its own deadline, and Claude Code runs the tool when a "
                    f"PreToolUse hook is killed. Re-run 'reeflex-claude setup', or set "
                    f"{HOOK_TIMEOUT_ENV}={entry:.0f} in the settings env block.")
        return None
    try:
        declared = float(raw)
    except ValueError:
        return (f"{HOOK_TIMEOUT_ENV}={raw!r} in settings env is not a number; "
                f"the hook will use its built-in {RUNNER_TIMEOUT_SECONDS:.0f}s default.")
    if declared > entry:
        return (f"{HOOK_TIMEOUT_ENV}={declared:.0f} is LARGER than the hook entry's "
                f"timeout of {entry:.0f}s. The runner kills the hook at {entry:.0f}s, "
                f"so the larger number is not budget the hook can spend. Re-run "
                f"'reeflex-claude setup' to write both from one value.")
    return None


def merge_hook_entry(
    settings: Dict[str, Any],
    *,
    command: str = HOOK_COMMAND,
    matcher: str = DEFAULT_MATCHER,
    timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """
    Merge our PreToolUse hook entry into settings (mutated in place).

    Returns True if an existing entry was updated in place, False if a new
    block was appended.

    Raises SettingsError if 'hooks', 'hooks.PreToolUse', or a matched
    block's 'hooks' key exists but is not the expected JSON type -- refuses
    to modify rather than guessing.
    """
    hooks_root = settings.setdefault("hooks", {})
    if not isinstance(hooks_root, dict):
        raise SettingsError("'hooks' exists in settings but is not a JSON object; refusing to modify.")

    pretool = hooks_root.setdefault("PreToolUse", [])
    if not isinstance(pretool, list):
        raise SettingsError("'hooks.PreToolUse' exists but is not a JSON array; refusing to modify.")

    replaced = False
    for block in pretool:
        if not isinstance(block, dict):
            continue
        block_hooks = block.get("hooks")
        if not isinstance(block_hooks, list):
            continue
        for item in block_hooks:
            if isinstance(item, dict) and is_ours(item.get("command")):
                item["type"] = "command"
                item["command"] = command
                item["timeout"] = timeout
                block["matcher"] = matcher
                replaced = True

    if not replaced:
        pretool.append({
            "matcher": matcher,
            "hooks": [{"type": "command", "command": command, "timeout": timeout}],
        })

    return replaced


def has_hook_entry(settings: Dict[str, Any]) -> bool:
    """True if settings already contains our PreToolUse hook entry. Read-only."""
    hooks_root = settings.get("hooks")
    if not isinstance(hooks_root, dict):
        return False
    pretool = hooks_root.get("PreToolUse")
    if not isinstance(pretool, list):
        return False
    for block in pretool:
        if not isinstance(block, dict):
            continue
        block_hooks = block.get("hooks")
        if not isinstance(block_hooks, list):
            continue
        for item in block_hooks:
            if isinstance(item, dict) and is_ours(item.get("command")):
                return True
    return False


def merge_env(settings: Dict[str, Any], updates: Dict[str, str]) -> None:
    """
    Merge `updates` into settings["env"] (mutated in place), preserving any
    existing unrelated keys. Raises SettingsError if 'env' exists but is not
    a JSON object.
    """
    env = settings.setdefault("env", {})
    if not isinstance(env, dict):
        raise SettingsError("'env' exists in settings but is not a JSON object; refusing to modify.")
    env.update(updates)


def write_settings(path: Path, settings: Dict[str, Any]) -> None:
    """Write settings as pretty JSON, creating parent directories if absent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(settings, indent=2, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
