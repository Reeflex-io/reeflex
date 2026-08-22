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

Bash verb classification reads EVERY COMMAND ON THE LINE, not the first token
(RFX-144).  A shell command line is split at `&&`, `||`, `;`, `|`, `&` and
newline (quote-aware); `sh -c '<inner>'` is expanded in place; `sudo`, `env`,
`timeout`, `nohup`, `xargs` and friends are peeled off.  Each resulting
command is classified on its own and THE MOST DANGEROUS ONE IS REPORTED.  A
command line is a `read` only when every command on it is a read.

  READ:     ls, pwd, cat, head, tail, wc, grep, rg, find (without -delete/-exec rm),
            git status|log|diff|show|branch, which, type, stat, df, du, tree, echo
  DELETE:   rm, rmdir, unlink, shred; SQL DROP/DELETE/TRUNCATE; git clean;
            kubectl/oc delete|drain; helm uninstall; terraform/tofu/pulumi
            destroy; aws delete-*/terminate-*/s3 rm|rb; gcloud/az/doctl delete;
            gsutil/s3cmd/rclone rm; docker/podman volume rm|prune|rmi;
            mkfs/fdisk/wipefs/blkdiscard; find -delete/-exec rm;
            python/node/ruby/perl -c|-e with an inline destructive call;
            dd of=, truncate, a bare `> FILE` redirection
  EMIT:     git push, npm/yarn publish, curl/wget with upload flags
            (-X POST/PUT/DELETE or data piping), scp/rsync to remote,
            ssh remote-exec, mail/sendmail
  EXECUTE:  everything else (build, deploy, run, pip install, make, ...), plus
            a database client handed a SCRIPT FILE (the statements are not
            visible, so the effect is unbounded -- priced irreversible/broad)

WHY MOST-DANGEROUS-SEGMENT AND NOT FIRST-TOKEN
----------------------------------------------
Measured live against reeflex-core on 2026-08-22: with the first-token rule,
16 of 18 canonical irreversible production destructions were ALLOWED with no
human -- `cd /srv/prod && rm -rf data` priced recoverable/scoped,
`echo cleaning up && rm -rf /srv/prod/data` priced reversible/single (a
recursive production delete recorded by the governance product as a benign
read), `kubectl delete namespace production` priced recoverable/scoped.  None
of them can reach R2, which requires blast_radius == "broad".  The axes are
computed in the agent's own process from the agent's own command string, so
this was the agent pricing its own action.  See RFX-144 / RFX-146.

BOUNDING THE AFFECTED SET IS WHAT SETS blast_radius
---------------------------------------------------
When the affected set can be enumerated from the command string it is priced
by size (1 -> single, 2..19 -> scoped, >= 20 or recursive -> broad, a system
path -> systemic).  When it CANNOT be bounded -- a cloud resource, a cluster
object, a whole-infrastructure destroy, a subtree, a database script file, an
`xargs` set that only exists at runtime -- it is priced `broad`.  SPEC §2's
safe-conservative default for an unknown blast_radius is `systemic`; `broad`
is deliberately one notch below it, so an unbounded destruction goes to a
human (R2) rather than being refused outright (R3).

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
  blast_radius:  derived per SPEC §4.2 from the shape of the AFFECTED SET.
    SYSTEMIC -- target is /, /*, ~/$HOME, a system dir (/etc /usr /var /bin
                /lib /boot /dev /sys /proc /run), or `DROP DATABASE` / `DROP SCHEMA`
                or a fork-bomb pattern
    BROAD    -- rm -r / -rf on any dir (non-systemic), DROP TABLE, TRUNCATE,
                DELETE FROM without WHERE clause, git clean -fdx
                OR the affected set is a PREDICATE rather than an enumeration:
                   a wildcard argument (`rm -f *`, `rm ./logs/*.log`) or an rm
                   whose paths do not parse at all -- the shell decides the set,
                   so this adapter cannot claim a small one (SPEC §4.2 step 2)
                OR rm of >= 20 explicit file arguments (BROAD_MIN, inclusive)
    SCOPED   -- rm of 2..19 explicit files
    SINGLE   -- rm of exactly 1 explicit file
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
    blast_radius:  broad          <-- RFX-145
    externality:   internal
  Rationale: coding agents issue many `npm install`, `pytest`, `make build`
  commands.  Blanket irreversible would ASK on every build.  We classify the
  explicitly dangerous patterns (delete, emit) and treat the rest as moderate.
  The environment variable is the operator escape hatch to tighten this.
  RFX-145: strict mode used to lift ONLY reversibility, leaving blast_radius
  at "scoped".  R2 requires "broad", so the only documented knob for
  tightening the adapter could not change a single verdict -- it changed a
  word in the audit log.  It now lifts both axes, which is the only reading
  of "the safe-but-noisy setting" that means anything: with it set, an
  unrecognised command in production goes to a human.
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
  none | rm_recursive_root | rm_recursive | rm_glob | rm_unbounded
  sql_drop_database | sql_drop_table | sql_delete_predicate
  sql_script_unbounded | git_force_push | fork_bomb | publish | disk_write
  sensitive_write | k8s_delete | helm_uninstall | iac_destroy | cloud_delete
  cloud_object_delete | cloud_bucket_delete | container_prune
  container_delete | volume_delete | image_delete | disk_format | tree_delete
  inline_delete | content_overwrite | unknown_execute_strict

Two slugs are from RFX-131, both naming the case where the affected set is a
PREDICATE rather than an enumeration (SPEC §4.2 step 2):
  `rm_glob`              — a wildcard or unparseable path target (RFX-131
                           raised it for `rm`; it now covers every family that
                           prices a path set). Distinct from `rm_recursive`
                           because the command need not be recursive, and an
                           operator reading the audit trail should see WHY it
                           was priced broad.
  `sql_delete_predicate` — `DELETE FROM ... WHERE ...`. Distinct from
                           `sql_drop_table` because a filtered delete is not a
                           schema change, and conflating them would make the
                           trail read as more alarming than the action is.
The demo Rego pack treats this field as informational only (see policy/), so
adding a slug changes no decision.

==============================================================================
KNOWN RESIDUAL AFTER RFX-144 (tracked as RFX-153)
==============================================================================
A destruction that names EXACTLY ONE target is priced `single`, and R2 requires
`broad`, so it allows in production:

    rm /srv/prod/db.sqlite             > /srv/prod/db.sqlite
    truncate -s 0 /srv/prod/db.sqlite  dd if=/dev/zero of=/srv/prod/db.sqlite

That is ONE rule (`_radius_for_paths`), not four bugs, and the adapter cannot
close it without lying: SPEC §4.2 as landed in RFX-131 says a name may claim
KIND but not CARDINALITY, and a command naming one file has a cardinality of
one.  The adapter also defaults `target.environment` to "production", so
pricing a single named file `broad` here turns every `rm <file>` an agent
issues -- `rm /tmp/scratch.txt` included -- into an approval prompt.  Whether
the CANON should hold an irreversible destruction of a named production entity
regardless of cardinality is a policy decision (the RFX-128 / RFX-132 family),
so it is filed as RFX-153 rather than taken here.

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
# Glob / wildcard pattern (SPEC §4.2: a predicate, not an enumeration)
# ---------------------------------------------------------------------------
# A path argument carrying a shell wildcard does not name an entity — it names a
# FILTER, and the shell, not this adapter, decides how many files it expands to.
# Counting it as one path made `rm -f *` classify as blast_radius `single`
# (irreversible + single + production -> allow). SPEC §4.2 step 2: an adapter
# that cannot enumerate the affected set MUST NOT emit `single` or `scoped`.
#
# `?` is deliberately EXCLUDED. It is a single-character wildcard whose expansion
# is bounded, and it appears in ordinary filenames often enough that including it
# would trade a fail-open for a fail-noisy. `*`, `[...]` and brace expansion all
# expand without bound. RFX-131.
_GLOB_RE = re.compile(r"[*\[]|\{[^}]*,[^}]*\}")


def _is_glob(path: str) -> bool:
    """Return True if the path argument is a wildcard rather than an entity name."""
    return bool(_GLOB_RE.search(path))

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
# SPEC §4.2 step 2 — ANY `DELETE FROM`, with or without a WHERE clause, describes
# its affected set by a PREDICATE. A filter narrows a predicate to a smaller
# predicate; it does not enumerate one, and the row count is not in the command
# text. Before RFX-131 only the no-WHERE form was caught here, so
# `DELETE FROM orders WHERE status='old'` fell through to the rm path and came
# out `scoped` — 2..19 entities asserted over an unbounded set, and
# irreversible+scoped+production is R4's default ALLOW. `WHERE 1=1` was allowed.
_SQL_DELETE_ANY       = re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE)

_RM_RECURSIVE_RE   = re.compile(r"\brm\b.*-[a-zA-Z]*r[a-zA-Z]*")

# ---------------------------------------------------------------------------
# Bash READ: find without dangerous flags
# ---------------------------------------------------------------------------

_FIND_DANGEROUS_RE = re.compile(r"\bfind\b.*(-delete|-exec\s+(rm|shred|truncate)\b)")

# ---------------------------------------------------------------------------
# RFX-144: command families whose destructive effect is invisible to a
# first-token classifier.  All of these are matched STRUCTURALLY -- on the
# command word of a segment plus its own argument vector -- never as a bare
# substring of the command line, so `grep -rn delete src/` stays a read.
# ---------------------------------------------------------------------------

# Prefixes that run another command; peeled before the command word is read.
_WRAPPER_COMMANDS = frozenset([
    "sudo", "doas", "env", "nohup", "nice", "ionice", "time", "timeout",
    "stdbuf", "setsid", "command", "exec", "unbuffer",
])

# Shell KEYWORDS that introduce a command rather than being one.  Splitting
# `for f in a b; do rm -rf /srv/prod/$f; done` at `;` leaves the middle
# segment as `do rm -rf ...`, whose command word is `do` -- so without this,
# every destruction inside a loop or an `if` was priced as an unrecognised
# execute and allowed.  A loop is not an evasion technique; it is how anyone
# writes shell.  Measured before this line existed:
# `while true; do rm -rf /srv/prod/data; done` -> allow / default_allow.
_SHELL_KEYWORDS = frozenset([
    "do", "then", "else", "elif", "done", "fi", "!", "{", "}",
    "if", "while", "until", "for", "select", "case", "esac", "in",
])

# Shells: `sh -c '<inner>'` is expanded and <inner> classified in its place.
_SHELL_COMMANDS = frozenset(["sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"])

# Runs the peeled command once per line of stdin -- the affected set is
# supplied at runtime and cannot be bounded from the command string.
_UNBOUNDED_WRAPPERS = frozenset(["xargs", "parallel"])

_RM_COMMANDS = frozenset(["rm", "rmdir", "unlink", "shred"])

# Interpreters whose inline program text is visible on the command line.
_INLINE_INTERPRETERS = frozenset([
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs",
    "php", "deno", "bun",
])

_INLINE_DESTRUCTIVE_RE = re.compile(
    r"""
    shutil\.rmtree      | os\.removedirs   | os\.remove\b   | os\.unlink\b |
    os\.rmdir\b         | \.unlink\(       | \.rmdir\(      | rimraf       |
    \.rmSync\b          | \.rmdirSync\b    | \.unlinkSync\b | \.rmtree\b   |
    FileUtils\.rm_rf    | File\.delete     | \bunlink\(     | \brmdir\(
    """,
    re.VERBOSE,
)

# Database clients: a script file hides the statements from the classifier.
_DB_CLIENTS = frozenset([
    "psql", "mysql", "mariadb", "mongosh", "mongo", "sqlite3", "cqlsh",
    "clickhouse-client", "redis-cli", "sqlcmd",
])
_DB_SCRIPT_FLAGS = frozenset(["-f", "--file", "--init", "-init", "--source"])

# Filesystem/device formatters -- device-level, never recoverable.
_DISK_COMMANDS = frozenset([
    "fdisk", "parted", "wipefs", "blkdiscard", "sgdisk", "mkswap",
])

# Severity ladders used to pick the most dangerous segment of a command line.
_TIER_RANK  = {"benign": 0, "moderate": 1, "destructive_broad": 2, "destructive_systemic": 3}
_BLAST_RANK = {"single": 0, "scoped": 1, "broad": 2, "systemic": 3}
_REV_RANK   = {"reversible": 0, "recoverable": 1, "irreversible": 2}
_VERB_RANK  = {"read": 0, "execute": 1, "create": 1, "update": 1, "emit": 2, "delete": 3}


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
    """
    Classify a Bash tool call.

    RFX-144: a shell command line is not one command.  `cd /srv/prod && rm -rf
    data` runs two, `echo hi && rm -rf /srv/prod/data` runs two, `sh -c '...'`
    runs whatever is inside the quotes, and `cat list | xargs rm -rf` runs rm
    over a set that only exists at runtime.  Classifying the FIRST TOKEN of the
    line priced sixteen of eighteen canonical irreversible production
    destructions as `recoverable/scoped` or (worse) `reversible/single`, which
    R2 cannot reach.

    So: split the line into the commands it will actually run, classify each
    one, and report the most dangerous.  A command line is only a `read` when
    EVERY segment of it is a read.
    """
    command = tool_input.get("command") or tool_input.get("cmd") or ""
    command_str = str(command)
    preview = command_str[:200] if command_str else None

    # Fork-bomb is a property of the whole line, not of any one segment.
    if _FORK_BOMB_RE.search(command_str):
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

    segments = _shell_segments(command_str)
    if not segments:
        return _classify_bash_execute(command_str, preview)

    # SQL text can only destroy anything if something on this line will hand it
    # to a database.  Decided once for the whole line, because the client and
    # the statement are routinely in different segments (`echo 'DROP TABLE t'
    # | psql`).  See `_sql_reachable`.
    sql_reachable = _sql_reachable(segments)

    results = [_classify_segment(seg, preview, sql_reachable) for seg in segments]
    return max(results, key=_severity)


def _sql_reachable(segments: list) -> bool:
    """
    True when some command on this line is a database client, i.e. when SQL
    text appearing anywhere on the line could actually be executed.

    WHY THIS GATE EXISTS.  The SQL patterns are substring matches over the
    command text, and `_SQL_TRUNCATE_RE` is the bare word `\\bTRUNCATE\\b`.
    Ungated, they classify by vocabulary rather than by effect.  Measured on
    main 44c6f85 and on RFX-131's branch, all three of these were priced
    verb=delete / irreversible / broad and returned `ask` -- an approval
    prompt, on the stock pack, for a read:

        cat docs/truncate.md
        grep -rn truncate src/
        grep -rn "DELETE FROM users" src/

    RFX-131 widened `DELETE FROM` from the no-WHERE form to any form, which is
    right for the fail-open it closed and widens this fail-noisy set with it.
    A gate that asks on `grep` gets switched off, and a switched-off gate
    protects nobody -- the same argument RFX-145 makes about strict mode.

    Deliberately coarse: the whole LINE, not the segment.  A DB client
    anywhere on the line re-arms the SQL patterns for every segment of it, so
    `psql -c 'SELECT 1' && grep -rn truncate src/` is still priced as a
    delete.  That residual errs toward a human on a line that does touch a
    database, which is the safe direction; the fail-open it prevents
    (`echo 'DROP TABLE t' | psql`) is not.
    """
    for seg in segments:
        tokens, _ = _peel_wrappers(_safe_split(seg))
        if tokens and os.path.basename(tokens[0]).lower() in _DB_CLIENTS:
            return True
    return False


def _severity(cls: dict) -> tuple:
    """Order two classifications by how much damage they describe."""
    return (
        _TIER_RANK.get(cls["classification_tier"], 1),
        _BLAST_RANK.get(cls["blast_radius"], 1),
        _REV_RANK.get(cls["reversibility"], 2),
        _VERB_RANK.get(cls["verb"], 1),
    )


def _classify_segment(segment: str, preview: Optional[str],
                      sql_reachable: bool = True) -> dict:
    """
    Classify ONE command out of a shell command line.

    `preview` is the whole original line: the audit record and the envelope
    must show the operator what was actually submitted, not the fragment that
    happened to win the severity comparison.

    `sql_reachable` says whether a database client appears anywhere on the
    line; the SQL patterns are only consulted when it does (`_sql_reachable`).
    """
    tokens, unbounded = _peel_wrappers(_safe_split(segment))
    cmd0 = os.path.basename(tokens[0]).lower() if tokens else ""
    args = tokens[1:]
    low = [a.lower() for a in args]

    # --- SQL handed to a database client (psql -c 'DROP DATABASE x') ---------
    # `truncate` the coreutil is not `TRUNCATE` the statement, even on a line
    # that does reach a database: it is priced below by `_overwrite_targets`
    # from the paths it names.
    if sql_reachable and (
            _SQL_DROP_DATABASE_RE.search(segment) or _SQL_DROP_TABLE_RE.search(segment)
            or _SQL_DELETE_ANY.search(segment)
            or (_SQL_TRUNCATE_RE.search(segment) and cmd0 != "truncate")):
        return _classify_bash_delete(segment, preview)

    # --- git clean -fdx ------------------------------------------------------
    if _GIT_CLEAN_RE.search(segment):
        return _classify_bash_delete(segment, preview, sql=False)

    # --- rm / rmdir / unlink / shred -----------------------------------------
    if cmd0 in _RM_COMMANDS:
        return _classify_bash_delete(segment, preview, unbounded=unbounded, sql=False)

    # --- the families a first-token classifier cannot see (RFX-144) ----------
    infra = _infra_destructive(cmd0, args, low, segment)
    if infra is not None:
        sig, radius, target = infra
        if unbounded:
            radius = _max_radius(radius, "broad")
        return _make(
            verb="delete",
            reversibility="irreversible",
            blast_radius=radius,
            externality="internal",
            magnitude_count=1,
            target_kind="resource",
            target_ref=target,
            danger_signature=sig,
            classification_tier=_tier_for_radius(radius),
            command_preview=preview,
            file_path=None,
        )

    # --- whole-file content destruction: dd of=, truncate, bare `> file` -----
    overwrite_paths = _overwrite_targets(cmd0, args, low)
    if overwrite_paths is not None:
        return _classify_path_delete(
            overwrite_paths, recursive=False, unbounded=unbounded,
            signature="content_overwrite", preview=preview,
        )

    # --- a database script hides its statements from the classifier ----------
    if cmd0 in _DB_CLIENTS and _has_script_file(args, low):
        return _make(
            verb="execute",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            magnitude_count=1,
            target_kind="resource",
            target_ref=None,
            danger_signature="sql_script_unbounded",
            classification_tier="destructive_broad",
            command_preview=preview,
            file_path=None,
        )

    # --- EMIT (push / publish / upload) --------------------------------------
    if _EMIT_RE.search(segment):
        return _classify_bash_emit(segment, preview)

    # --- READ ----------------------------------------------------------------
    if cmd0 in _READ_COMMANDS:
        return _read_result(preview)
    if cmd0 == "find":
        # find with -delete / -exec rm was handled by _infra_destructive above.
        return _read_result(preview)
    if cmd0 == "git" and low and low[0] in _READ_GIT_SUBCOMMANDS:
        return _read_result(preview)

    # --- EXECUTE (default) ----------------------------------------------------
    return _classify_bash_execute(segment, preview)


def _read_result(preview: Optional[str]) -> dict:
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


def _infra_destructive(cmd0: str, args: list, low: list, segment: str):
    """
    Structural match for destructive command families whose command word is
    not `rm`.  Returns (danger_signature, blast_radius, target_ref) or None.

    Matching is on the command word plus that command's OWN arguments, so a
    read that merely mentions a destructive word (`grep -rn delete src/`,
    `kubectl get pods`) is not caught.

    Where the affected set cannot be enumerated from the command string the
    radius is `broad`, not `scoped`: SPEC §2's safe-conservative default for an
    unknown blast_radius is `systemic`, and `broad` is one notch below it so a
    human can still approve the action (R2) instead of it being refused
    outright (R3).
    """
    # Kubernetes / OpenShift
    if cmd0 in ("kubectl", "kubectl.exe", "oc", "k3s", "microk8s"):
        if "delete" in low or "drain" in low:
            return ("k8s_delete", "broad", _first_positional(args))
        return None

    if cmd0 == "helm":
        if "uninstall" in low or "delete" in low:
            return ("helm_uninstall", "broad", _first_positional(args))
        return None

    # Infrastructure as code
    if cmd0 in ("terraform", "tofu", "opentofu"):
        if "destroy" in low or "-destroy" in low or "--destroy" in low:
            return ("iac_destroy", "broad", None)
        return None
    if cmd0 == "pulumi" and "destroy" in low:
        return ("iac_destroy", "broad", None)

    # AWS
    if cmd0 == "aws":
        if low[:1] == ["s3"] or low[:1] == ["s3api"]:
            if "rb" in low:
                return ("cloud_bucket_delete", "broad", _first_uri(args))
            if "rm" in low:
                recursive = "--recursive" in low
                return ("cloud_object_delete", "broad" if recursive else "scoped",
                        _first_uri(args))
            if any(a.startswith("delete-") for a in low):
                return ("cloud_delete", "broad", None)
            return None
        if any(a.startswith(("delete-", "terminate-", "remove-", "destroy-")) for a in low):
            return ("cloud_delete", "broad", None)
        return None

    # GCP / Azure / other object stores
    if cmd0 in ("gsutil", "s3cmd", "rclone", "mc"):
        if "rm" in low or "rb" in low or "delete" in low or "purge" in low:
            recursive = any(f in low for f in ("-r", "-rf", "--recursive"))
            return ("cloud_object_delete", "broad" if recursive else "scoped",
                    _first_uri(args))
        return None
    if cmd0 in ("gcloud", "az", "doctl", "ibmcloud", "oci"):
        if "delete" in low or "destroy" in low or "purge" in low:
            return ("cloud_delete", "broad", _first_positional(args))
        return None

    # Containers
    if cmd0 in ("docker", "podman", "nerdctl"):
        if "prune" in low:
            return ("container_prune", "broad", None)
        if "volume" in low and ("rm" in low or "remove" in low):
            return ("volume_delete", "broad", _first_positional(args))
        if "down" in low and any(f in low for f in ("-v", "--volumes")):
            return ("volume_delete", "broad", None)
        if "rmi" in low or ("image" in low and ("rm" in low or "remove" in low)):
            return ("image_delete", "broad", None)
        if "rm" in low:
            return ("container_delete", "scoped", _first_positional(args))
        return None

    # Disk / filesystem level -- not recoverable at all.
    if cmd0 in _DISK_COMMANDS or cmd0.startswith("mkfs"):
        return ("disk_format", "systemic", _first_positional(args))

    # find -delete / -exec rm: the affected set is a subtree.
    if cmd0 == "find" and _FIND_DANGEROUS_RE.search(segment):
        return ("tree_delete", "broad", _first_positional(args))

    # Inline interpreter program text with a destructive call in it.
    if (cmd0 in _INLINE_INTERPRETERS
            and _INLINE_DESTRUCTIVE_RE.search(segment)
            and any(f in low for f in ("-c", "-e", "--eval", "--exec", "-p"))):
        return ("inline_delete", "broad", None)

    return None


def _overwrite_targets(cmd0: str, args: list, low: list):
    """
    Return the paths a whole-file content destruction targets, or None.

    Covers `dd ... of=PATH`, `truncate ... PATH` and a bare `> PATH`
    redirection used as a command.  The file survives; all of its previous
    content does not.
    """
    if cmd0 == "dd":
        targets = [a.split("=", 1)[1] for a in args if a.lower().startswith("of=")]
        return targets or None
    if cmd0 == "truncate":
        return _positional_args(args, value_flags=("-s", "--size", "-r", "--reference")) or None
    if cmd0 in (">", ">|"):
        return [a for a in args if not a.startswith("-")] or None
    return None


def _classify_path_delete(paths: list, recursive: bool, unbounded: bool,
                          signature: str, preview: Optional[str]) -> dict:
    """Price a destruction whose affected set is a list of filesystem paths."""
    radius, sig, tier = _radius_for_paths(paths, recursive)
    if sig == "none":
        sig = signature
    if unbounded:
        radius = _max_radius(radius, "broad")
        tier = _tier_for_radius(radius)
    return _make(
        verb="delete",
        reversibility="irreversible",
        blast_radius=radius,
        externality="internal",
        magnitude_count=max(len(paths), 1),
        target_kind="file",
        target_ref=paths[0] if len(paths) == 1 else None,
        danger_signature=sig,
        classification_tier=tier,
        command_preview=preview,
        file_path=paths[0] if len(paths) == 1 else None,
    )


def _classify_bash_delete(command: str, preview: Optional[str],
                          unbounded: bool = False, sql: bool = True) -> dict:
    """
    Detailed classification for a Bash DELETE intent.

    `sql=False` when the caller already knows this segment cannot execute SQL
    -- an `rm` or a `git clean` names no database client, so a filename that
    merely CONTAINS a SQL keyword is not a statement.  Ungated, the bare-word
    `_SQL_TRUNCATE_RE` priced `rm /var/log/truncate.log` as a broad SQL table
    truncation: irreversible + broad + production = `ask`, on a log file.
    """

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
    if sql and _SQL_DROP_DATABASE_RE.search(command):
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
    if sql and _SQL_DROP_TABLE_RE.search(command):
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

    # SQL TRUNCATE / DELETE FROM (with or without a WHERE clause — both are
    # predicates over an unenumerated set; SPEC §4.2 step 2, RFX-131)
    if sql and (_SQL_TRUNCATE_RE.search(command) or _SQL_DELETE_ANY.search(command)):
        return _make(
            verb="delete",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            magnitude_count=1,
            target_kind="resource",
            target_ref=None,
            danger_signature="sql_delete_predicate"
            if _SQL_DELETE_ANY.search(command)
            and not _SQL_DELETE_NO_WHERE.search(command)
            else "sql_drop_table",
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
    is_recursive = bool(_RM_RECURSIVE_RE.search(command))
    path_args = _extract_rm_paths(command)
    count = max(len(path_args), 1)

    blast_radius, sig, tier = _radius_for_paths(path_args, is_recursive)

    # RFX-144: `cat list | xargs rm` deletes a set that exists only at
    # runtime.  Nothing in the command string bounds it, so it cannot be
    # priced `single` on the strength of having no path arguments.
    #
    # (RFX-131's predicate rule -- a glob argument, or no parseable path at
    # all -- now lives inside `_radius_for_paths`, so it applies to every
    # family that prices a path set and not only to `rm`.)
    if unbounded:
        blast_radius = _max_radius(blast_radius, "broad")
        if sig == "none":
            sig = "rm_unbounded"
        tier = _tier_for_radius(blast_radius)

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


def _radius_for_paths(path_args: list, is_recursive: bool):
    """
    Price a filesystem destruction from the set of paths it names.

    All shell deletes are irreversible; the tier is scaled by blast_radius.
    single/scoped = moderate (don't fire R2 on a routine `rm /tmp/x`),
    broad/systemic = destructive_broad / destructive_systemic.

    KNOWN RESIDUAL (RFX-153): a destruction that names exactly one production
    file -- `rm /srv/prod/db.sqlite`, `> /srv/prod/db.sqlite`, `truncate -s 0
    /srv/prod/db.sqlite` -- is priced `single` here and therefore cannot reach
    R2.  That is one rule, not three bugs, and it is what SPEC §4.2 requires:
    a command that names one file has a cardinality of one, and this adapter
    may not claim otherwise.  Closing it here would also make every `rm <file>`
    an approval prompt (the adapter defaults target.environment to production),
    so it is a policy decision and not this function's to take.
    """
    count = max(len(path_args), 1)
    is_systemic = any(_is_systemic_path(p) for p in path_args) if path_args else False

    # SPEC §4.2 step 2 (RFX-131) -- the affected set is a PREDICATE, not an
    # enumeration: a wildcard argument, or no parseable path at all.  Either
    # way the cardinality is not in the command text, so `single` and `scoped`
    # are not available.  RFX-131 applied this to `rm`; it lives here so it
    # also covers `> *.log`, `truncate *.db` and `dd of=...` -- every family
    # that prices a path set.
    is_predicate = (not path_args) or any(_is_glob(p) for p in path_args)

    if is_systemic:
        return "systemic", "rm_recursive_root", "destructive_systemic"
    if is_recursive:
        return "broad", "rm_recursive", "destructive_broad"
    if is_predicate:
        return "broad", "rm_glob", "destructive_broad"
    if count >= 20:
        return "broad", "rm_recursive", "destructive_broad"
    if count >= 2:
        return "scoped", "none", "moderate"
    return "single", "none", "moderate"


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
    """
    Classification for a Bash EXECUTE intent (build/run/deploy/unknown).

    RFX-145: strict mode used to lift reversibility to `irreversible` and
    leave blast_radius at `scoped`.  R2 requires `broad`, so the only
    documented knob for tightening the adapter could not change a single
    verdict -- it changed a word in the audit log.  Strict mode now lifts
    BOTH axes, which is what "the safe-but-noisy setting" has to mean: an
    unrecognised command in production goes to a human.
    """
    strict = _is_strict_mode()
    if strict:
        return _make(
            verb="execute",
            reversibility="irreversible",
            blast_radius="broad",
            externality="internal",
            magnitude_count=1,
            target_kind="command",
            target_ref=None,
            danger_signature="unknown_execute_strict",
            classification_tier="destructive_broad",
            command_preview=preview,
            file_path=None,
        )

    return _make(
        verb="execute",
        reversibility="recoverable",
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


def _safe_split(s: str) -> list:
    """shlex.split, degrading to whitespace split on an unbalanced quote."""
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


def _split_on_operators(command: str) -> list:
    """
    Cut a shell command line at the operators that separate one command from
    the next -- `&&`, `||`, `;`, `|`, `&` and newline -- respecting single
    quotes, double quotes and backslash escapes.

    `2>&1` and `&>file` are redirections, not separators, and are left alone.
    """
    parts: list = []
    buf: list = []
    quote = None
    i, n = 0, len(command)

    while i < n:
        ch = command[i]

        if quote is not None:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue

        if command.startswith("&&", i) or command.startswith("||", i):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue

        if ch == "&":
            # `2>&1`, `&>log`, `>&2` are redirections.
            prev = "".join(buf).rstrip()[-1:] if buf else ""
            nxt = command[i + 1] if i + 1 < n else ""
            if prev == ">" or nxt == ">":
                buf.append(ch)
                i += 1
                continue
            parts.append("".join(buf))
            buf = []
            i += 1
            continue

        if ch in (";", "|", "\n"):
            parts.append("".join(buf))
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    parts.append("".join(buf))
    return [p for p in (x.strip() for x in parts) if p]


def _shell_c_payload(tokens: list):
    """
    Return the program text of a `sh -c '<inner>'` invocation, else None.

    `eval '<inner>'` is the same construct with different syntax -- a visible
    program string handed to the shell to run -- so it is expanded the same
    way.  Measured before this: `eval "rm -rf /srv/prod/data"` was priced as
    an unrecognised execute and ALLOWED.  Note this covers only the case where
    the program text is VISIBLE; `eval "$CMD"` and `$(echo rm) -rf ...` are
    not, and no string-matching classifier can price them (see the `gap-`
    family in conformance.py).
    """
    if not tokens:
        return None
    cmd0 = os.path.basename(tokens[0]).lower()

    if cmd0 == "eval":
        positional = [t for t in tokens[1:] if not t.startswith("-")]
        return positional[0] if positional else None

    if cmd0 not in _SHELL_COMMANDS:
        return None
    for i, t in enumerate(tokens[1:], start=1):
        if t in ("-c", "-lc", "-ic") and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def _shell_segments(command: str, depth: int = 0) -> list:
    """
    Split a shell command line into the individual commands it will run,
    expanding `sh -c '<inner>'` in place (up to three levels) so a wrapped
    command is classified by what it actually runs and not by the wrapper.
    """
    if not command.strip():
        return []

    out: list = []
    for segment in _split_on_operators(command):
        inner = None
        if depth < 3:
            peeled, _ = _peel_wrappers(_safe_split(segment))
            inner = _shell_c_payload(peeled)
        if inner:
            expanded = _shell_segments(inner, depth + 1)
            out.extend(expanded or [segment])
        else:
            out.append(segment)
    return out


def _peel_wrappers(tokens: list):
    """
    Strip prefixes that merely run another command and return
    (remaining_tokens, unbounded).

    `unbounded` is True when the peeled wrapper feeds the inner command a set
    of arguments that only exists at runtime (`xargs`, GNU `parallel`), which
    means no path list in the command string bounds the affected set.
    """
    unbounded = False
    i = 0
    n = len(tokens)

    while i < n:
        word = os.path.basename(tokens[i]).lower()

        # `do rm -rf X`, `then rm -rf X`, `! rm -rf X`: a keyword is not a
        # command.  Peeled before anything else so a destruction inside a
        # loop or a conditional is read as the destruction it is.
        if word in _SHELL_KEYWORDS:
            i += 1
            continue

        if word in _UNBOUNDED_WRAPPERS:
            unbounded = True
            i += 1
            # Skip xargs' own flags and their values.
            while i < n and tokens[i].startswith("-"):
                if tokens[i] in ("-n", "-P", "-I", "-d", "-L", "-s", "-a", "-E"):
                    i += 2
                else:
                    i += 1
            continue

        if word in _WRAPPER_COMMANDS:
            i += 1
            # `env FOO=bar cmd`, `sudo -u root cmd`, `timeout 30 cmd`
            while i < n and (tokens[i].startswith("-") or "=" in tokens[i]
                             or tokens[i].replace(".", "", 1).isdigit()):
                if tokens[i] in ("-u", "-g", "-U", "--user", "--group", "-n", "-i"):
                    i += 2
                else:
                    i += 1
            continue

        break

    return tokens[i:], unbounded


def _positional_args(args: list, value_flags: tuple = ()) -> list:
    """Positional arguments only: drops flags and the values they consume."""
    out: list = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in value_flags:
                skip = True
            continue
        out.append(a)
    return out


def _first_positional(args: list):
    """Best-effort target reference: the last positional word of a subcommand."""
    positional = [a for a in args if not a.startswith("-")]
    return positional[-1] if positional else None


def _first_uri(args: list):
    for a in args:
        if "://" in a:
            return a
    return None


def _has_script_file(args: list, low: list) -> bool:
    """
    True when a database client is handed a script FILE instead of inline SQL.

    The statements are then invisible to the classifier, so nothing in the
    command string bounds what the call does to the database.  `-e`/`-c`
    inline SQL is excluded on purpose: that text IS visible and the SQL
    patterns above already read it.
    """
    for i, a in enumerate(low):
        if a in _DB_SCRIPT_FLAGS and i + 1 < len(args):
            return True
        if a.startswith(("--file=", "--init=")):
            return True
        if a == "<" and i + 1 < len(args):
            return True
    return False


def _max_radius(a: str, b: str) -> str:
    return a if _BLAST_RANK.get(a, 1) >= _BLAST_RANK.get(b, 1) else b


def _tier_for_radius(radius: str) -> str:
    if radius == "systemic":
        return "destructive_systemic"
    if radius == "broad":
        return "destructive_broad"
    return "moderate"


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
