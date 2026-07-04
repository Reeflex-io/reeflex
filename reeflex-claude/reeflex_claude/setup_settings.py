"""
setup_settings.py -- Claude Code settings.json read/merge/write for `reeflex-claude setup`.

Implements the F12 structural fix (code-reports/cold-start-doc-fidelity-friction-log-
dev-2-20260701.md): once pip-installed, the PreToolUse hook command is the bare
console entry point `reeflex-claude hook` -- no absolute path, no cwd-dependent
`python -m` import, so there is no "wrong cwd -> ModuleNotFoundError -> non-zero
exit -> Claude Code silently runs the tool anyway" failure mode left to trigger.

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
from pathlib import Path
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Canonical hook entry (Leo's spec, verbatim)
# ---------------------------------------------------------------------------

DEFAULT_MATCHER = (
    "Bash|Write|Edit|MultiEdit|Read|Glob|Grep|LS|NotebookEdit|WebFetch|WebSearch"
)
HOOK_COMMAND = "reeflex-claude hook"
DEFAULT_TIMEOUT = 30

# Substring used to identify "our" hook entry among possibly-foreign ones.
_OWNERSHIP_MARKER = "reeflex-claude hook"


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
    """True if `command` is a string containing our ownership marker."""
    return isinstance(command, str) and _OWNERSHIP_MARKER in command


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
