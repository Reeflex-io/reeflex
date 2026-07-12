"""
client_configs.py -- Track 5 (design doc section 13): reading/rewriting
third-party MCP client configs.

Reuses the reeflex-claude setup discipline (reeflex_claude/setup_settings.py):
  - refuse-on-invalid-JSON -- ClientConfigError, write NOTHING on a parse
    failure or non-object top level.
  - ownership marker -- `is_ours()` recognizes OUR gateway entry (reserved
    name "reeflex-mcp", or a command/args mentioning reeflex_mcp/reeflex-mcp)
    among possibly-foreign entries, by content, not by position.
  - byte-safe-enough re-serialization -- json.dumps(..., indent=2), which
    preserves every existing key/value/order but normalizes whitespace (same
    documented, deliberate limitation as reeflex-claude's setup_settings.py).

NEW vs. reeflex-claude (explicit, deliberate): reeflex-claude's setup only
ever ADDS a hook block to a settings.json we effectively own the meaning of.
Track 5's `setup`/`import` REWRITE a THIRD-PARTY file's `mcpServers` section
-- removing entries that used to launch real servers directly, replacing
them with a single gateway entry. That is materially more invasive, which is
exactly why this module adds something reeflex-claude does not need:
`make_backup()` / `restore_backup()`, always called before the first
destructive write to a given path.

Standard locations (design doc section 13), all using the SAME de facto MCP
client-config shape (`{"mcpServers": {"<name>": {"command":..., "args":[...]}
| {"url":...}}}`):
  - Claude Desktop:        claude_desktop_config.json (OS-specific path)
  - Claude Code (project): ./.mcp.json
  - Claude Code settings:  .claude/settings.json (project or global --
                           mirrors reeflex_claude/setup_settings.py's own
                           resolve_settings_path())
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The reserved mcpServers key for our own single gateway entry.
OWNERSHIP_NAME = "reeflex-mcp"
# Substrings checked in an entry's command/args to recognize it as ours even
# if the operator renamed the mcpServers key.
_OWNERSHIP_MARKERS = ("reeflex_mcp", "reeflex-mcp")

_BACKUP_SUFFIX = ".reeflex-mcp-backup"


class ClientConfigError(Exception):
    """A client config file is malformed. Refuse to modify it -- no
    destructive fallback, matching reeflex-claude's SettingsError discipline."""


# ---------------------------------------------------------------------------
# Standard locations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientProfile:
    key: str  # "claude-desktop" | "mcp-json" | "claude-settings"
    label: str
    path: Path


def claude_desktop_path() -> Path:
    """OS-specific path for Claude Desktop's config. macOS + Windows paths
    are Anthropic's documented locations; the Linux path is the community
    convention (not officially documented by Anthropic for this client)."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else (Path.home() / "AppData" / "Roaming")
        return base / "Claude" / "claude_desktop_config.json"
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def project_mcp_json_path() -> Path:
    """Claude Code's project-level MCP config, relative to the CURRENT cwd."""
    return Path.cwd() / ".mcp.json"


def claude_settings_path(target: str = "project") -> Path:
    """Mirrors reeflex_claude/setup_settings.py's resolve_settings_path()
    exactly: "project" -> ./.claude/settings.json, "global" -> ~/.claude/settings.json."""
    if target == "global":
        return Path.home() / ".claude" / "settings.json"
    return Path.cwd() / ".claude" / "settings.json"


def standard_profiles() -> list[ClientProfile]:
    """All standard locations, design doc section 13's order. Each entry's
    `.path` is computed fresh (not cached) so a test that chdirs or sets
    $APPDATA between calls sees the new location."""
    return [
        ClientProfile("claude-desktop", "Claude Desktop", claude_desktop_path()),
        ClientProfile("mcp-json", "project .mcp.json", project_mcp_json_path()),
        ClientProfile("claude-settings", ".claude/settings.json (project)", claude_settings_path("project")),
    ]


def resolve_profile(key: str) -> ClientProfile:
    for profile in standard_profiles():
        if profile.key == key:
            return profile
    raise ValueError(f"unknown client profile {key!r}")


# ---------------------------------------------------------------------------
# Load / write -- refuse-on-invalid-JSON discipline
# ---------------------------------------------------------------------------


def load_client_config(path: Path) -> dict[str, Any]:
    """Load a client config. Missing/empty file -> {} (nothing to import,
    nothing to break). Raises ClientConfigError on invalid JSON or a
    non-object top level -- callers MUST NOT write anything when this raises."""
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ClientConfigError(
            f"{path} is not valid JSON ({exc}); refusing to modify it. "
            "Fix the file by hand (or move it aside) and re-run 'reeflex-mcp setup'."
        ) from exc
    if not isinstance(data, dict):
        raise ClientConfigError(f"{path} does not contain a JSON object at the top level; refusing to modify it.")
    return data


def write_client_config(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def get_mcp_servers(data: dict[str, Any]) -> dict[str, Any]:
    """Return data["mcpServers"] if present and a dict, else {}. Never
    raises -- an unexpected shape there is treated as "nothing to import"
    rather than a hard error (the top-level JSON validity check above is
    the actual refuse-to-modify gate)."""
    servers = data.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


# ---------------------------------------------------------------------------
# Backup / restore -- the NEW-vs-reeflex-claude affordance (see module docstring)
# ---------------------------------------------------------------------------


def backup_path(path: Path) -> Path:
    return path.with_name(path.name + _BACKUP_SUFFIX)


def make_backup(path: Path) -> Path | None:
    """Copy `path` to its backup location. Returns the backup path, or None
    if there is nothing to back up (the file does not exist -- a fresh
    client install with no prior config).

    Never overwrites an EXISTING backup: the backup must always capture the
    true pre-gateway state, so a second `setup`/`import` run (e.g. importing
    a newly-drifted server) does not clobber it with an already-migrated
    copy.
    """
    if not path.exists():
        return None
    bpath = backup_path(path)
    if not bpath.exists():
        shutil.copy2(path, bpath)
    return bpath


def restore_backup(path: Path) -> bool:
    """Restore `path` from its backup (overwriting whatever is there now,
    including our gateway entry). Returns True if restored, False if no
    backup exists for this path."""
    bpath = backup_path(path)
    if not bpath.exists():
        return False
    shutil.copy2(bpath, path)
    return True


def has_backup(path: Path) -> bool:
    return backup_path(path).exists()


# ---------------------------------------------------------------------------
# Ownership marker
# ---------------------------------------------------------------------------


def is_ours(name: str, entry: Any) -> bool:
    """True if this mcpServers entry is OUR single gateway entry -- by
    reserved name, or (if the operator renamed the key) by a command/args
    string mentioning reeflex_mcp/reeflex-mcp. Never by position."""
    if name == OWNERSHIP_NAME:
        return True
    if not isinstance(entry, dict):
        return False
    command = entry.get("command")
    if isinstance(command, str) and any(marker in command for marker in _OWNERSHIP_MARKERS):
        return True
    args = entry.get("args")
    if isinstance(args, list):
        for a in args:
            if isinstance(a, str) and any(marker in a for marker in _OWNERSHIP_MARKERS):
                return True
    return False


def gateway_entry(*, config_path: str | None = None, transport: str = "stdio") -> dict[str, Any]:
    """The single mcpServers entry a client config is rewritten to.

    Prefers the real PATH-resolved `reeflex-mcp` console script (same
    rationale as reeflex_claude/cli.py's resolve_hook_command(): finding it
    via PATH is itself part of what later verifies the install). Falls back
    to `python -m reeflex_mcp` for a source checkout that has not been
    pip-installed.
    """
    exe = shutil.which("reeflex-mcp")
    if exe:
        command, args = exe, ["--transport", transport]
    else:
        command, args = sys.executable, ["-m", "reeflex_mcp", "--transport", transport]
    if config_path:
        args = [*args, "--config", config_path]
    return {"command": command, "args": args}
