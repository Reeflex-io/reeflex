"""
classify.py -- Verb + axis + tier + danger_signature classifier for Claude Code tool calls.

This module implements the NORMALIZE step of the Reeflex adapter contract (SPEC §6)
for the Claude Code PreToolUse hook backend.  It is pure (no network, no I/O) so it
can be tested exhaustively without any infrastructure.

==============================================================================
VERB MAPPING RATIONALE (SPEC §3)
==============================================================================
Verbs are derived from ACTION SEMANTICS, not just the tool name, because the
same tool (Bash) can express radically different intents.

    Write                              -> create
    Edit / MultiEdit / NotebookEdit    -> update
    Read / Glob / Grep / LS            -> read
    WebFetch / WebSearch               -> read  (externality: outbound)
    Bash (intent-classified below)     -> read | delete | emit | execute
    Unknown tool                       -> execute  (conservative)

Bash verb classification reads the leading command token(s):
  READ:     ls, pwd, cat, head, tail, wc, grep, rg, find (without -delete/-exec rm),
            git status|log|diff|show|branch, which, type, stat, df, du, tree, echo
  DELETE:   rm, rmdir, unlink, shred; SQL DROP/DELETE/TRUNCATE; git clean
  EMIT:     git push, npm/yarn publish, curl/wget with upload flags
            (-X POST/PUT/DELETE or data piping), scp/rsync to remote,
            ssh remote-exec, mail/sendmail
  EXECUTE:  everything else (build, deploy, run, pip install, docker, make, ...)

==============================================================================
AXIS MAPPING RATIONALE (SPEC §4)
==============================================================================
All three axes are ALWAYS set.  Safe-conservative defaults (SPEC §2):
  unknown reversibility -> irreversible
  unknown blast_radius  -> systemic
  unknown externality   -> internal  (coding-agent tools are software; "physical"
                                      is reserved for SCADA/robotics/energy -- not
                                      applicable here; internal is the conservative
                                      choice for an unknown software tool)

Note: the general SPEC §2 note about "unknown externality -> physical" applies to
adapters that cannot determine externality.  For this adapter, we CAN determine
externality for all known tool types; the unknown-tool fallback uses "internal"
because a coding agent tool is not expected to have physical-world effects, and
over-firing "physical" on e.g. a linter would be actively misleading.  The
upgrade path is to refine the allow-list of known tools.

Bash READ:
  reversibility: reversible   (no state change)
  blast_radius:  single
  externality:   internal

Bash DELETE (rm / shred / SQL):
  reversibility: irreversible  (shell deletes are gone; no recycle bin)
  blast_radius:
    SYSTEMIC -- target is /, /*, ~/$HOME, a system dir (/etc /usr /var /bin
                /lib /boot /dev /sys /proc /run), or `DROP DATABASE` / `DROP SCHEMA`
                or a fork-bomb pattern
    BROAD    -- rm -r / -rf on any dir (non-systemic), DROP TABLE, TRUNCATE,
                DELETE FROM without WHERE clause, git clean -fdx
                OR rm of >= 20 explicit file arguments
    SCOPED   -- rm of 2..19 explicit files
    SINGLE   -- rm of exactly 1 file
  externality: internal  (unless the same command also matches an outbound
               pattern -- edge case, marked outbound if so)

Bash EMIT (push / publish / upload):
  reversibility: irreversible  (published/pushed bytes are out the door)
  blast_radius:  broad for git push --force or npm/yarn publish;
                 scoped otherwise
  externality:   outbound

Bash EXECUTE (build/run/deploy/unknown):
  DEFAULT (REEFLEX_CLAUDE_STRICT unset or falsy):
    reversibility: recoverable
    blast_radius:  scoped
    externality:   internal
  STRICT mode (REEFLEX_CLAUDE_STRICT=1/true/yes):
    reversibility: irreversible
    blast_radius:  scoped
    externality:   internal
  Rationale: coding agents issue many `npm install`, `pytest`, `make build`
  commands.  Blanket irreversible would ASK on every build.  We classify the
  explicitly dangerous patterns (delete, emit) and treat the rest as moderate.
  The environment variable is the operator escape hatch to tighten this.
  UPGRADE PATH: replace with per-command allow-list once tooling stabilises.

Write (create):
  reversibility: irreversible if os.path.exists(file_path) [overwrite = prior
                 content permanently lost]; recoverable for a new file.
  blast_radius:  broad if path matches a SENSITIVE/PROD-CONFIG signature (see
                 _SENSITIVE_PATH_RE); single otherwise.
  externality:   internal

Edit / MultiEdit / NotebookEdit (update):
  reversibility: recoverable  (targeted edit; git-revertable)
  blast_radius:  single (or scoped if sensitive path)
  externality:   internal

Read / Glob / Grep / LS (read):
  reversibility: reversible
  blast_radius:  single
  externality:   internal

WebFetch / WebSearch (read):
  reversibility: reversible
  blast_radius:  single
  externality:   outbound  (the request leaves the system)

Unknown tool:
  reversibility: irreversible  (safe-conservative)
  blast_radius:  scoped
  externality:   internal  (see note above)

==============================================================================
CLASSIFICATION TIER (context.classification_tier)
==============================================================================
Used by the demo Rego pack -- emit EXACTLY these four strings:
  benign              -- READ ops, Bash READ
  moderate            -- default Bash EXECUTE (recoverable/scoped); single/scoped DELETE
  destructive_broad   -- broad DELETE, EMIT, Write overwrite of prod config
  destructive_systemic -- systemic DELETE, fork-bomb, DROP DATABASE

Tier for DELETE is determined by blast_radius, NOT by reversibility (all shell
deletes are irreversible):
  blast_radius single  -> tier moderate
  blast_radius scoped  -> tier moderate
  blast_radius broad   -> tier destructive_broad
  blast_radius systemic -> tier destructive_systemic

==============================================================================
DANGER SIGNATURE (context.danger_signature)
==============================================================================
A short, machine-readable slug surfacing the most salient danger:
  none | rm_recursive_root | rm_recursive | sql_drop_database | sql_drop_table
  git_force_push | fork_bomb | publish | disk_write | sensitive_write

==============================================================================
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Optional


# ---------------------------------------------------------------------------
# Sensitive path pattern (Write blast_radius broad)
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_RE = re.compile(
    r"""
    (
        \.env($|\.)               |   # .env or .env.local etc.
        secrets                   |   # any path component "secrets"
        credentials               |   # any path component "credentials"
        \.pem$                    |   # PEM certificate
        id_rsa                    |   # SSH private key
        /etc/                     |   # /etc/* system config
        docker-compose.*\.ya?ml$  |   # docker-compose.yml / .yaml
        Dockerfile$               |   # Dockerfile
        \.tf$                     |   # Terraform
        \.tfvars$                 |   # Terraform vars
        \.github/workflows/       |   # GitHub Actions
        /deploy/                  |   # k8s deploy dirs
        /k8s/                     |
        /manifests/               |
        nginx\.conf$              |   # nginx config
        \.service$                    # systemd unit
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# System-directory pattern (Bash DELETE systemic blast_radius)
# ---------------------------------------------------------------------------

_SYSTEM_DIR_RE = re.compile(
    r"^(/|/\*|~|\$HOME|/etc|/usr|/var|/bin|/lib|/boot|/dev|/sys|/proc|/run)(/|$)"
)

# ---------------------------------------------------------------------------
# Fork-bomb pattern
# ---------------------------------------------------------------------------

_FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{.*:\|:.*\}")

# ---------------------------------------------------------------------------
# Bash READ command prefixes
# ---------------------------------------------------------------------------

_READ_COMMANDS = frozenset([
    "ls", "pwd", "cat", "head", "tail", "wc", "grep", "rg", "echo",
    "stat", "df", "du", "tree", "which", "type",
])

_READ_GIT_SUBCOMMANDS = frozenset([
    "status", "log", "diff", "show", "branch",
])

# ---------------------------------------------------------------------------
# Bash EMIT patterns
# ---------------------------------------------------------------------------

_EMIT_RE = re.compile(
    r"""
    \bgit\s+push\b                      |   # git push (any)
    \bnpm\s+(publish|pack)\b            |   # npm publish / pack
    \byarn\s+publish\b                  |   # yarn publish
    \bcurl\b.*(-X\s*(POST|PUT|DELETE)|--data\b|--upload-file|-d\b) |
    \bwget\b.*(--post-data|--method=(POST|PUT|DELETE))  |
    \bscp\b                             |   # scp upload
    \brsync\b.*:                        |   # rsync to remote
    \bssh\b.*\s\S+\s+\S                |   # ssh remote-exec
    \bmail\b                            |
    \bsendmail\b
    """,
    re.VERBOSE | re.IGNORECASE,
)

_FORCE_PUSH_RE = re.compile(r"\bgit\s+push\b.*--force\b|\bgit\s+push\b.*-f\b")
_PUBLISH_RE = re.compile(r"\b(npm|yarn)\s+publish\b")

# ---------------------------------------------------------------------------
# Bash DELETE patterns
# ---------------------------------------------------------------------------

_GIT_CLEAN_RE  = re.compile(r"\bgit\s+clean\b.*-[a-zA-Z]*f[a-zA-Z]*", re.IGNORECASE)
_SQL_DROP_DATABASE_RE = re.compile(r"\bDROP\s+(DATABASE|SCHEMA)\b", re.IGNORECASE)
_SQL_DROP_TABLE_RE    = re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE)
_SQL_TRUNCATE_RE      = re.compile(r"\bTRUNCATE\b", re.IGNORECASE)
_SQL_DELETE_NO_WHERE  = re.compile(r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", re.IGNORECASE | re.DOTALL)

_RM_RECURSIVE_RE   = re.compile(r"\brm\b.*-[a-zA-Z]*r[a-zA-Z]*")

# ---------------------------------------------------------------------------
# Bash READ: find without dangerous flags
# ---------------------------------------------------------------------------

_FIND_DANGEROUS_RE = re.compile(r"\bfind\b.*(-delete|-exec\s+rm\b)")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify(tool_name: str, tool_input: dict) -> dict:
    """
    Classify a Claude Code PreToolUse event.

    Returns a dict with keys:
      verb              str   SPEC §3 verb
      reversibility     str   SPEC §4 axis
      blast_radius      str   SPEC §4 axis
      externality       str   SPEC §4 axis
      magnitude_count   int   >= 1
      target_kind       str   "command" | "file" | "resource"
      target_ref        str | None
      danger_signature  str   short slug
      classification_tier str  benign | moderate | destructive_broad | destructive_systemic
      command_preview   str | None  first 200 chars of command
      file_path         str | None
    """
    tool_name_lower = tool_name.lower() if tool_name else ""

    # Route to the appropriate classifier
    if tool_name_lower == "bash":
        return _classify_bash(tool_input)
    elif tool_name_lower == "write":
        return _classify_write(tool_input)
    elif tool_name_lower in ("edit", "multiedit", "notebookedit"):
        return _classify_edit(tool_input)
    elif tool_name_lower in ("read", "glob", "grep", "ls"):
        return _classify_read_tool(tool_input)
    elif tool_name_lower in ("webfetch", "websearch"):
        return _classify_web(tool_input)
    else:
        return _classify_unknown(tool_input)


# ---------------------------------------------------------------------------
# Per-tool classifiers
# ---------------------------------------------------------------------------

def _classify_bash(tool_input: dict) -> dict:
    command = tool_input.get("command") or tool_input.get("cmd") or ""
    command_str = str(command)
    preview = command_str[:200] if command_str else None

    # Determine verb from intent
    verb = _bash_verb(command_str)

    if verb == "read":
        return _make(
            verb="read",
            reversibility="reversible",
            blast_radius="single",
            externality="internal",
            magnitude_count=1,
            target_kind="command",
            target_ref=None,
            danger_signature="none",
            classification_tier="benign",
            command_preview=preview,
            file_path=None,
        )

    if verb == "delete":
        return _classify_bash_delete(command_str, preview)

    if verb == "emit":
        return _classify_bash_emit(command_str, preview)

    # execute (default)
    return _classify_bash_execute(command_str, preview)


def _bash_verb(command: str) -> str:
    """Classify the verb for a Bash command string."""
    if not command.strip():
        return "execute"

    # Fork-bomb check first (dangerous pattern before any parsing)
    if _FORK_BOMB_RE.search(command):
        return "delete"  # classify as delete so danger_signature fires

    # Try to parse the leading command token safely
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return "execute"

    # Use os.path.basename to handle ./rm, /usr/bin/rm, etc. cleanly
    cmd0 = os.path.basename(tokens[0]).lower()

    # DELETE
    if cmd0 in ("rm", "rmdir", "unlink", "shred"):
        return "delete"
    if _GIT_CLEAN_RE.search(command):
        return "delete"
    if (_SQL_DROP_DATABASE_RE.search(command) or _SQL_DROP_TABLE_RE.search(command)
            or _SQL_TRUNCATE_RE.search(command) or _SQL_DELETE_NO_WHERE.search(command)):
        return "delete"

    # EMIT
    if _EMIT_RE.search(command):
        return "emit"

    # READ
    if cmd0 in _READ_COMMANDS:
        return "read"
    if cmd0 == "find" and not _FIND_DANGEROUS_RE.search(command):
        return "read"
    if cmd0 == "git":
        subcmd = tokens[1].lower() if len(tokens) > 1 else ""
        if subcmd in _READ_GIT_SUBCOMMANDS:
            return "read"

    return "execute"


def _classify_bash_delete(command: str, preview: Optional[str]) -> dict:
    """Detailed classification for a Bash DELETE intent."""

    # Fork-bomb
    if _FORK_BOMB_RE.search(command):
        return _make(
            verb="delete",
            reversibility="irreversible",
            blast_radius="systemic",
            externality="internal",
            magnitude_count=1,
            target_kind="command",
            target_ref=None,
            danger_signature="fork_bomb",
            classification_tier="destructive_systemic",
            command_preview=preview,
            file_path=None,
        )

    # SQL DROP DATABASE / SCHEMA
    if _SQL_DROP_DATABASE_RE.search(command):
        return _make(
            verb="delete",
            reversibility="irreversible",
            blast_radius="systemic",
            externality="internal",
            magnitude_count=1,
            target_kind="resource",
            target_ref=None,
            danger_signature="sql_drop_database",
            classification_tier="destructive_systemic",
            command_preview=preview,
            file_path=None,
        )

    # SQL DROP TABLE
    if _SQL_DROP_TABLE_RE.search(command):
        return _make(
            verb="delete",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            magnitude_count=1,
            target_kind="resource",
            target_ref=None,
            danger_signature="sql_drop_table",
            classification_tier="destructive_broad",
            command_preview=preview,
            file_path=None,
        )

    # SQL TRUNCATE / DELETE FROM without WHERE
    if _SQL_TRUNCATE_RE.search(command) or _SQL_DELETE_NO_WHERE.search(command):
        return _make(
            verb="delete",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            magnitude_count=1,
            target_kind="resource",
            target_ref=None,
            danger_signature="sql_drop_table",
            classification_tier="destructive_broad",
            command_preview=preview,
            file_path=None,
        )

    # git clean
    if _GIT_CLEAN_RE.search(command):
        return _make(
            verb="delete",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            magnitude_count=1,
            target_kind="command",
            target_ref=None,
            danger_signature="rm_recursive",
            classification_tier="destructive_broad",
            command_preview=preview,
            file_path=None,
        )

    # rm / rmdir / unlink / shred
    # Check for recursive flag first
    is_recursive = bool(_RM_RECURSIVE_RE.search(command))

    # Parse path arguments after rm flags
    path_args = _extract_rm_paths(command)
    count = max(len(path_args), 1)

    # Check for systemic target (/, /*, ~, $HOME, system dirs)
    is_systemic = any(_is_systemic_path(p) for p in path_args) if path_args else False

    # Determine blast_radius and tier.
    # All shell deletes are irreversible; tier is scaled by blast_radius.
    # single/scoped = moderate (don't fire R2 on a routine rm /tmp/x)
    # broad/systemic = destructive_broad/destructive_systemic
    if is_systemic:
        blast_radius = "systemic"
        sig = "rm_recursive_root"
        tier = "destructive_systemic"
    elif is_recursive:
        blast_radius = "broad"
        sig = "rm_recursive"
        tier = "destructive_broad"
    elif count >= 20:
        blast_radius = "broad"
        sig = "rm_recursive"
        tier = "destructive_broad"
    elif count >= 2:
        blast_radius = "scoped"
        sig = "none"
        tier = "moderate"
    else:
        blast_radius = "single"
        sig = "none"
        tier = "moderate"

    return _make(
        verb="delete",
        reversibility="irreversible",
        blast_radius=blast_radius,
        externality="internal",
        magnitude_count=count,
        target_kind="command",
        target_ref=path_args[0] if len(path_args) == 1 else None,
        danger_signature=sig,
        classification_tier=tier,
        command_preview=preview,
        file_path=path_args[0] if len(path_args) == 1 else None,
    )


def _classify_bash_emit(command: str, preview: Optional[str]) -> dict:
    """Classification for a Bash EMIT intent (outbound network/publish)."""
    if _FORCE_PUSH_RE.search(command):
        blast_radius = "broad"
        sig = "git_force_push"
    elif _PUBLISH_RE.search(command):
        blast_radius = "broad"
        sig = "publish"
    else:
        blast_radius = "scoped"
        sig = "none"

    return _make(
        verb="emit",
        reversibility="irreversible",
        blast_radius=blast_radius,
        externality="outbound",
        magnitude_count=1,
        target_kind="command",
        target_ref=None,
        danger_signature=sig,
        classification_tier="destructive_broad",
        command_preview=preview,
        file_path=None,
    )


def _classify_bash_execute(command: str, preview: Optional[str]) -> dict:
    """Classification for a Bash EXECUTE intent (build/run/deploy/unknown)."""
    strict = _is_strict_mode()
    if strict:
        reversibility = "irreversible"
    else:
        reversibility = "recoverable"

    return _make(
        verb="execute",
        reversibility=reversibility,
        blast_radius="scoped",
        externality="internal",
        magnitude_count=1,
        target_kind="command",
        target_ref=None,
        danger_signature="none",
        classification_tier="moderate",
        command_preview=preview,
        file_path=None,
    )


def _classify_write(tool_input: dict) -> dict:
    """Classification for a Write tool call."""
    # Use file_path only -- NOT file_text (which is the file CONTENT, not the
    # path; scanning content with os.path.exists / sensitive-path regex would
    # produce wrong results and under-classify overwrites as recoverable).
    file_path = tool_input.get("file_path") or ""
    file_path_str = str(file_path) if file_path else ""
    preview = None

    # Overwrite vs. new file
    if file_path_str and os.path.exists(file_path_str):
        reversibility = "irreversible"
    else:
        reversibility = "recoverable"

    # Sensitive path?
    is_sensitive = bool(file_path_str and _SENSITIVE_PATH_RE.search(file_path_str))
    if is_sensitive:
        blast_radius = "broad"
        sig = "sensitive_write"
        tier = "destructive_broad"
    else:
        blast_radius = "single"
        sig = "disk_write"
        tier = "moderate" if reversibility == "recoverable" else "destructive_broad"

    return _make(
        verb="create",
        reversibility=reversibility,
        blast_radius=blast_radius,
        externality="internal",
        magnitude_count=1,
        target_kind="file",
        target_ref=file_path_str or None,
        danger_signature=sig,
        classification_tier=tier,
        command_preview=preview,
        file_path=file_path_str or None,
    )


def _classify_edit(tool_input: dict) -> dict:
    """Classification for Edit / MultiEdit / NotebookEdit."""
    file_path = (tool_input.get("file_path") or "")
    file_path_str = str(file_path) if file_path else ""

    # Targeted edit: generally recoverable (git-revertable)
    # Sensitive path -> scoped blast_radius as a flag
    is_sensitive = bool(file_path_str and _SENSITIVE_PATH_RE.search(file_path_str))
    blast_radius = "scoped" if is_sensitive else "single"
    sig = "sensitive_write" if is_sensitive else "none"
    tier = "moderate"

    return _make(
        verb="update",
        reversibility="recoverable",
        blast_radius=blast_radius,
        externality="internal",
        magnitude_count=1,
        target_kind="file",
        target_ref=file_path_str or None,
        danger_signature=sig,
        classification_tier=tier,
        command_preview=None,
        file_path=file_path_str or None,
    )


def _classify_read_tool(tool_input: dict) -> dict:
    """Classification for Read / Glob / Grep / LS tools."""
    file_path = (tool_input.get("file_path") or tool_input.get("pattern") or "")
    file_path_str = str(file_path) if file_path else ""

    return _make(
        verb="read",
        reversibility="reversible",
        blast_radius="single",
        externality="internal",
        magnitude_count=1,
        target_kind="file",
        target_ref=file_path_str or None,
        danger_signature="none",
        classification_tier="benign",
        command_preview=None,
        file_path=file_path_str or None,
    )


def _classify_web(tool_input: dict) -> dict:
    """Classification for WebFetch / WebSearch tools."""
    url = tool_input.get("url") or tool_input.get("query") or ""

    return _make(
        verb="read",
        reversibility="reversible",
        blast_radius="single",
        externality="outbound",
        magnitude_count=1,
        target_kind="resource",
        target_ref=str(url)[:200] if url else None,
        danger_signature="none",
        classification_tier="benign",
        command_preview=None,
        file_path=None,
    )


def _classify_unknown(tool_input: dict) -> dict:
    """Conservative classification for any unrecognized tool."""
    return _make(
        verb="execute",
        reversibility="irreversible",
        blast_radius="scoped",
        externality="internal",
        magnitude_count=1,
        target_kind="resource",
        target_ref=None,
        danger_signature="none",
        classification_tier="moderate",
        command_preview=None,
        file_path=None,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make(
    verb: str,
    reversibility: str,
    blast_radius: str,
    externality: str,
    magnitude_count: int,
    target_kind: str,
    target_ref: Optional[str],
    danger_signature: str,
    classification_tier: str,
    command_preview: Optional[str],
    file_path: Optional[str],
) -> dict:
    return {
        "verb": verb,
        "reversibility": reversibility,
        "blast_radius": blast_radius,
        "externality": externality,
        "magnitude_count": magnitude_count,
        "target_kind": target_kind,
        "target_ref": target_ref,
        "danger_signature": danger_signature,
        "classification_tier": classification_tier,
        "command_preview": command_preview,
        "file_path": file_path,
    }


def _is_systemic_path(path: str) -> bool:
    """Return True if path is /, /*, ~, $HOME, or a known system directory."""
    p = path.strip()
    if p in ("/", "/*", "~", "$HOME", "~/", "$HOME/"):
        return True
    return bool(_SYSTEM_DIR_RE.match(p))


def _extract_rm_paths(command: str) -> list:
    """
    Best-effort extraction of file path arguments from an rm/rmdir/unlink/shred command.
    Strips flags (anything starting with -) and the command name itself.
    Returns a list of path strings; empty list if nothing parseable.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    # Find the rm/rmdir/unlink/shred token using basename (handles /bin/rm, ./rm, etc.)
    start = 0
    for i, t in enumerate(tokens):
        if os.path.basename(t).lower() in ("rm", "rmdir", "unlink", "shred"):
            start = i + 1
            break

    paths = []
    i = start
    while i < len(tokens):
        t = tokens[i]
        if t == "--":
            # Everything after -- is a path
            paths.extend(tokens[i+1:])
            break
        if t.startswith("-"):
            i += 1
            continue
        paths.append(t)
        i += 1

    return paths


def _is_strict_mode() -> bool:
    """Return True if REEFLEX_CLAUDE_STRICT env var is set to a truthy value."""
    v = os.environ.get("REEFLEX_CLAUDE_STRICT", "").strip().lower()
    return v in ("1", "true", "yes", "on")
