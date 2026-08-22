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

Bash verb classification (RFX-144) reads EVERY SEGMENT of the command line, and
the most dangerous segment decides.  Before RFX-144 it read the FIRST TOKEN of
the whole string, which is why `cd /srv/prod && rm -rf data` was priced as a `cd`
and `echo x && rm -rf /srv/prod/data` as a read.  See "SHELL DECOMPOSITION" and
"THE UNRESOLVED CLASS" below -- those two sections are the fix.

  READ:     ls, pwd, cat, head, tail, wc, grep, rg, find (without -delete/-exec rm),
            git status|log|diff|show|branch, which, type, stat, df, du, tree, echo
  DELETE:   rm, rmdir, unlink, shred; SQL DROP/DELETE/TRUNCATE; git clean;
            find -delete / -exec rm; a resource-deleting cloud/orchestrator verb
            (kubectl delete, aws s3 rm, aws <svc> delete-*, gcloud ... delete,
            az ... delete, docker <obj> rm, terraform destroy, helm uninstall);
            a truncating overwrite of an existing container of data
            (`> file`, `dd of=`, mkfs)
  EMIT:     git push, npm/yarn publish, curl/wget with upload flags
            (-X POST/PUT/DELETE or data piping), scp/rsync to remote,
            ssh remote-exec, mail/sendmail
  EXECUTE:  a RECOGNISED developer operation (see _DEV_SAFE) -- build, test,
            install, plan, status, inspect.  NOT "everything else": everything
            else is the UNRESOLVED class below.

==============================================================================
SHELL DECOMPOSITION (RFX-144)
==============================================================================
A Bash tool call carries ONE command string that may express many actions.  The
hook receives the whole string in a single payload -- Claude Code does not split
it -- so an adapter that classifies the leading token classifies the least
dangerous thing in the line.  Measured on main before this change: 24 of 27
canonical irreversible production destructions were ALLOWED, 16 of them exactly
as RFX-144 enumerates them, and the two that fired did so only because they
happened to begin with `rm`.

So the command string is decomposed FIRST, structurally, and each piece is
classified on its own:

  * split at top level on `;`, `&&`, `||`, `|`, `&` and newline, QUOTE-AWARE, so
    a separator inside '...' or "..." is not a separator (this is what keeps
    `python3 -c "a; b"` one segment -- an inline program is not a shell chain);
  * strip leading `VAR=value` assignments and prefix wrappers that run another
    command without changing what it does: env, sudo, doas, nohup, time,
    timeout N, nice, ionice, stdbuf, xargs, command, exec;
  * unwrap `sh|bash|zsh|dash|ksh -c '<string>'` by recursing into the string,
    bounded at _MAX_UNWRAP_DEPTH, so `sh -c 'rm -rf /srv/prod/data'` is the rm
    it contains.

The result is a list of segments.  Every segment is classified and the MOST
SEVERE result is returned, ranked by classification_tier and then by verb.  This
is a PARSE, not a guess: it makes no claim about what any command means, only
about where one command ends and the next begins.

==============================================================================
THE UNRESOLVED CLASS (RFX-144, RFX-145)
==============================================================================
The second half of the defect is not the parse -- it is the default.  Before this
change, any command the adapter did not recognise was classified
`execute / recoverable / scoped`, which is a MEASUREMENT: it asserts the action
is undoable and touches a bounded set.  For `kubectl delete namespace production`
that assertion is false, and it is false in the direction that allows.

SPEC §2's conservative defaults, which this module's own AXIS MAPPING section has
always stated, are: unknown reversibility -> irreversible, unknown blast_radius
-> systemic.  They were not applied to Bash EXECUTE.  They are now, with one
deliberate softening:

  UNRESOLVED (the adapter cannot name the effect of this command)
    reversibility: irreversible   (SPEC §2)
    blast_radius:  broad          (NOT systemic -- see below)
    externality:   internal
    tier:          destructive_broad
    danger_signature: unclassified_command

`broad` rather than `systemic` is a decidability choice, not a hedge.  `broad`
routes to R2 -> require_approval, so an unrecognised command reaches a HUMAN who
can approve it.  `systemic` routes to R3 -> deny, which is refused even with
approval and gives the operator no path forward at all.  An adapter that cannot
identify a command has not established that the command is catastrophic -- only
that nobody has checked.  That is a question for a person.  (RFX-132 is the open
owner-level ticket on whether core's conservative default should be DENY or HOLD;
this emission deliberately does not pre-empt it -- if the owner decides an
unclassifiable action must be denied, that is a change in core's rules, not here.)

What keeps this from prompting on every build is _DEV_SAFE: a positive list of
recognised, non-destructive developer operations.  The direction of the list is
the point.  A DENYLIST of dangerous commands fails OPEN on the command nobody
thought of -- which is how `kubectl delete namespace production` was allowed.  An
ALLOWLIST of safe commands fails NOISY on the command nobody thought of: an
operator sees a prompt for a tool we have not taught the adapter yet.  A missing
entry is then a usability bug with a visible symptom instead of a silent
irreversible production deletion.

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

Bash EXECUTE (a RECOGNISED developer operation -- see _DEV_SAFE):
  DEFAULT (REEFLEX_CLAUDE_STRICT unset or falsy):
    reversibility: recoverable
    blast_radius:  scoped
    externality:   internal
  STRICT mode (REEFLEX_CLAUDE_STRICT=1/true/yes):
    reversibility: irreversible
    blast_radius:  scoped
    externality:   internal
  Rationale: coding agents issue many `npm install`, `pytest`, `make build`
  commands.  Blanket irreversible would ASK on every build.  These are the
  commands the adapter has been taught, so it can say something true about them.
  Anything it has NOT been taught is UNRESOLVED, not this.

Bash UNRESOLVED (the adapter cannot name the effect):
  DEFAULT: irreversible / broad  / internal, tier destructive_broad
  STRICT:  irreversible / systemic / internal, tier destructive_systemic

  REEFLEX_CLAUDE_STRICT IS WHERE IT ACTS (RFX-145).  Before this change STRICT's
  only effect was to flip `reversibility` on the EXECUTE class from `recoverable`
  to `irreversible` -- and because that class also emitted `blast_radius: scoped`,
  R2 (irreversible + BROAD + production) could never fire, so the one documented
  knob for tightening the adapter changed NO decision, on any of the 24 measured
  fail-opens.  Measured before this change: 24/27 allowed with STRICT unset,
  24/27 allowed with STRICT=1, the same 24.
  STRICT now raises the UNRESOLVED class from `broad` to `systemic`, i.e. from
  "a human must approve this" to "this does not run".  That is what an operator
  who sets a tightening flag is asking for, and it is decision-changing and
  measurable.  It still also flips the EXECUTE class's reversibility, which on
  the stock policy pack remains decision-inert on its own -- stated here rather
  than quietly dropped, because the flag's documented meaning is broader than
  the one thing that moves a verdict.

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
  resource_delete | container_delete | overwrite_container | unclassified_command

Four slugs are new in RFX-144:
  resource_delete      -- a cloud/orchestrator delete of named leaf resources
  container_delete     -- a delete of a CONTAINER of data (namespace, volume,
                          database, bucket, cluster, filesystem)
  overwrite_container  -- a truncating overwrite of a container of data
                          (`> db.sqlite`, `dd of=`, mkfs)
  unclassified_command -- the adapter could not name this command's effect
The demo Rego pack treats this field as informational only, so adding a slug
changes no decision on its own.

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


# ===========================================================================
# RFX-144 -- shell decomposition
# ===========================================================================
# Prefix wrappers: commands that RUN ANOTHER COMMAND without changing what it
# does.  Stripping them is not an interpretation, it is removing a prefix.
# `xargs` is here for `cat list.txt | xargs rm -rf`: the rm is the action.
_WRAPPER_PREFIX_CMDS = frozenset([
    "env", "sudo", "doas", "nohup", "time", "timeout", "nice", "ionice",
    "stdbuf", "eatmydata", "xargs", "command", "exec", "builtin", "setsid",
    "unbuffer",
])

# `timeout 5 cmd` / `nice -n 10 cmd`: the wrapper takes a positional operand
# before the real command.  Consumed only when it is not itself a path/command.
_WRAPPER_NUMERIC_OPERAND = frozenset(["timeout", "nice", "ionice"])

# Shells whose `-c` argument is a COMMAND STRING, so it must be re-decomposed.
_SHELL_CMDS = frozenset(["sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"])

# Bound on `sh -c "sh -c '...'"` nesting.  Beyond it the segment is UNRESOLVED
# rather than silently classified from its outermost layer.
_MAX_UNWRAP_DEPTH = 4

# `VAR=value` prefix assignment.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


# ===========================================================================
# RFX-144 -- recognised resource deletions
# ===========================================================================
# A cloud/orchestrator CLI deletes by naming a service and a verb.  This table
# makes a claim about KIND only: "this invocation destroys a resource".  It makes
# NO claim about cardinality -- that is derived below from the shape of the
# affected set (SPEC §4.2's rule, and RFX-131's reasoning: a name may raise the
# kind, it may not decide the count).
#
# Each entry maps a command to the token pattern that means "delete".  A command
# not in this table is not thereby safe -- it lands in the UNRESOLVED class.
_RESOURCE_DELETE_VERBS = frozenset([
    "delete", "destroy", "remove", "rm", "uninstall", "purge", "drop",
    "terminate", "deregister", "detach-and-delete",
])

# Argv positions where a delete verb is meaningful, per command.  `None` means
# "any token position" (e.g. `aws rds delete-db-instance` -- the verb is fused
# into the operation name, so a prefix match on the token is used instead).
_RESOURCE_DELETE_CMDS = frozenset([
    "kubectl", "oc", "helm", "docker", "podman", "nerdctl", "terraform",
    "aws", "gcloud", "az", "doctl", "flyctl", "heroku", "kubeadm", "eksctl",
    "gsutil", "s3cmd", "rclone", "vault", "consul", "etcdctl", "systemctl",
])

# A resource kind that CONTAINS data: destroying it destroys everything inside,
# and the adapter cannot enumerate what that is.  Container -> systemic.
_CONTAINER_RESOURCE_KINDS = frozenset([
    "namespace", "namespaces", "ns", "volume", "volumes", "database",
    "databases", "db", "schema", "cluster", "clusters", "bucket", "buckets",
    "table", "tables", "instance", "instances", "node", "nodes", "pv",
    "persistentvolume", "persistentvolumes", "pvc", "persistentvolumeclaim",
    "image", "images", "snapshot", "snapshots", "filesystem", "disk", "disks",
    "project", "projects", "organization", "account", "subscription",
    "resource-group", "resourcegroup", "vm", "sql", "rds", "dynamodb",
    "keyspace", "index", "indices", "topic", "queue", "stack", "release",
])

# An unbounded selector: the affected set is a PREDICATE, not an enumeration.
_PREDICATE_FLAG_RE = re.compile(
    r"(^|\s)(--all\b|--all-namespaces\b|--recursive\b|-r\b|-R\b|--force\b"
    r"|--prune\b|-l\s|--selector\b|--field-selector\b|--filter\b|--wildcard\b)"
)

# ---------------------------------------------------------------------------
# RFX-144 -- truncating overwrite of a container of data
# ---------------------------------------------------------------------------
# `> path` (not `>>`), `dd ... of=path`, `mkfs*`, `truncate -s 0 path`.  An
# overwrite destroys the prior contents as irreversibly as an unlink does; the
# `Write` classifier has always said so (os.path.exists -> irreversible) and the
# shell forms said nothing.
_TRUNCATE_REDIRECT_RE = re.compile(r"(?<!>)>(?!>)\s*([^\s;|&<>]+)")
_DD_OUTPUT_RE = re.compile(r"\bdd\b[^;|&]*\bof=([^\s;|&]+)")
_MKFS_RE = re.compile(r"\bmkfs(\.[a-z0-9]+)?\b")

# A path that names a CONTAINER of records rather than one leaf entity.  This is
# a KIND claim and it is raise-only: it can make a single-path target `broad`, it
# can never make an enumerated set smaller.  A block device is worse again --
# writing a filesystem over it is not something a human approval can undo.
_DATA_CONTAINER_PATH_RE = re.compile(
    r"(\.sqlite3?$|\.db$|\.mdb$|\.sql$|\.dump$|\.bak$|\.tar(\.(gz|bz2|xz|zst))?$"
    r"|\.zip$|\.rdb$|\.aof$|\.frm$|\.ibd$|/pgdata(/|$)|/mysql(/|$))",
    re.IGNORECASE,
)
_BLOCK_DEVICE_RE = re.compile(
    r"^/dev/(?!null$|zero$|urandom$|random$|std(in|out|err)$|tty|fd/)"
)
# Sinks that discard rather than destroy.
_DISCARD_SINKS = frozenset(["/dev/null", "/dev/zero"])


# ===========================================================================
# RFX-144 -- _DEV_SAFE: recognised, non-destructive developer operations
# ===========================================================================
# The ONLY commands that keep the old permissive `execute` classification.  The
# value is either True ("every invocation of this command is a build/test/inspect
# operation") or a frozenset of subcommands that are.  A subcommand not listed is
# UNRESOLVED, not allowed.
#
# Read the direction, not the length: an omission here costs an operator a
# prompt.  An omission from a danger list costs a production database.
_DEV_SAFE = {
    # language / package tooling
    "npm": frozenset(["install", "ci", "run", "test", "run-script", "audit",
                      "ls", "list", "outdated", "view", "why", "exec", "link",
                      "init", "config", "dedupe", "update", "pkg", "version"]),
    "yarn": frozenset(["install", "add", "run", "test", "build", "why", "list",
                       "info", "why", "workspaces", "dlx"]),
    "pnpm": frozenset(["install", "add", "run", "test", "build", "list", "why",
                       "exec", "dlx", "why"]),
    "bun": frozenset(["install", "add", "run", "test", "build", "x"]),
    "pip": frozenset(["install", "download", "list", "show", "freeze", "check",
                      "wheel", "index"]),
    "pip3": frozenset(["install", "download", "list", "show", "freeze", "check",
                       "wheel", "index"]),
    "poetry": frozenset(["install", "add", "lock", "run", "show", "check",
                         "build", "env"]),
    "uv": frozenset(["pip", "sync", "run", "add", "lock", "venv", "tree"]),
    "cargo": frozenset(["build", "test", "check", "run", "fmt", "clippy",
                        "tree", "add", "update", "doc", "bench", "metadata"]),
    "go": frozenset(["build", "test", "run", "vet", "fmt", "mod", "get",
                     "list", "doc", "generate", "work", "tool"]),
    "mvn": True,
    "gradle": True,
    "./gradlew": True,
    "gradlew": True,
    "bundle": frozenset(["install", "exec", "list", "check", "update"]),
    "gem": frozenset(["install", "list", "which", "build"]),
    "composer": frozenset(["install", "require", "update", "dump-autoload",
                           "show", "validate"]),
    "dotnet": frozenset(["build", "test", "restore", "run", "publish", "list"]),

    # test runners / linters / type checkers / formatters
    "pytest": True, "tox": True, "nox": True, "unittest": True,
    "jest": True, "vitest": True, "mocha": True, "phpunit": True,
    "rspec": True, "cypress": True, "playwright": True,
    "ruff": True, "black": True, "isort": True, "flake8": True, "pylint": True,
    "mypy": True, "pyright": True, "eslint": True, "prettier": True,
    "tsc": True, "biome": True, "shellcheck": True, "hadolint": True,
    "clang-format": True, "gofmt": True, "rustfmt": True, "stylelint": True,

    # build drivers
    "make": frozenset(["build", "test", "check", "all", "install", "lint",
                       "fmt", "format", "dev", "docs", "compile", "run",
                       "help", "setup", "deps", ""]),
    "cmake": True, "ninja": True, "bazel": frozenset(["build", "test", "query",
                                                      "run", "info"]),
    "gcc": True, "g++": True, "clang": True, "clang++": True, "cc": True,
    "javac": True, "rustc": True, "tsx": True, "esbuild": True, "webpack": True,
    "vite": True, "rollup": True, "swc": True, "babel": True,

    # VCS -- non-destructive subcommands only.  `git clean`, `git push`,
    # `git reset --hard`, `git filter-branch` are NOT here.
    "git": frozenset(["status", "log", "diff", "show", "branch", "add",
                      "commit", "fetch", "pull", "checkout", "switch",
                      "restore", "stash", "tag", "remote", "config",
                      "rev-parse", "describe", "blame", "shortlog", "ls-files",
                      "ls-remote", "cat-file", "merge-base", "worktree",
                      "cherry-pick", "revert", "bisect", "apply", "init",
                      "clone", "submodule", "grep", "reflog", "notes",
                      "rebase", "merge", "am", "format-patch", "archive"]),
    "gh": frozenset(["pr", "issue", "repo", "run", "workflow", "api", "auth",
                     "release", "browse", "search", "label", "status"]),

    # container / orchestrator READ + BUILD operations only.  The delete verbs
    # for these same commands are handled by _RESOURCE_DELETE_* above; anything
    # that is in neither table (e.g. `kubectl apply`) is UNRESOLVED on purpose.
    "docker": frozenset(["build", "ps", "images", "logs", "inspect", "version",
                         "info", "pull", "push", "tag", "compose", "buildx",
                         "context", "top", "port", "diff", "events", "login"]),
    "podman": frozenset(["build", "ps", "images", "logs", "inspect", "pull"]),
    "kubectl": frozenset(["get", "describe", "logs", "explain", "version",
                          "config", "top", "api-resources", "api-versions",
                          "auth", "cluster-info", "diff", "wait", "port-forward",
                          "cp", "events"]),
    "oc": frozenset(["get", "describe", "logs", "version", "status", "whoami"]),
    "helm": frozenset(["list", "get", "show", "template", "lint", "search",
                       "repo", "dependency", "version", "history", "status"]),
    "terraform": frozenset(["plan", "validate", "fmt", "init", "show",
                            "providers", "version", "output", "graph",
                            "workspace", "get", "login"]),
    "tofu": frozenset(["plan", "validate", "fmt", "init", "show", "output"]),
    "kustomize": True,
    "skaffold": frozenset(["build", "diagnose", "render"]),

    # cloud CLIs -- READ operations only, recognised by the OPERATION name via
    # _CLOUD_READ_OP_RE below rather than by enumerating every service.  These
    # entries cover the operations that carry no service noun at all.
    "aws": frozenset(["help", "configure", "sts"]),
    "gcloud": frozenset(["help", "info", "version", "config", "auth"]),
    "az": frozenset(["help", "version", "account", "login"]),

    # shell builtins that change no state outside the shell.  `cd` matters more
    # than it looks: `cd /srv/prod && rm -rf data` is RFX-144's first case, and
    # with the chain now decomposed the `cd` segment is classified on its own.
    "cd": True, "pushd": True, "popd": True, "export": True, "unset": True,
    "shift": True, "wait": True, ":": True, "set": True, "umask": True,

    # inspection / misc
    "systemctl": frozenset(["status", "show", "list-units", "list-unit-files",
                            "is-active", "is-enabled", "cat"]),
    "journalctl": True, "dmesg": True, "ps": True, "top": True, "htop": True,
    "uname": True, "id": True, "whoami": True, "hostname": True, "date": True,
    "env": True, "printenv": True, "sleep": True, "true": True, "false": True,
    "mkdir": True, "touch": True, "cp": True, "ln": True, "chmod": True,
    "diff": True, "sort": True, "uniq": True, "cut": True, "tr": True,
    "seq": True, "basename": True, "dirname": True, "realpath": True,
    "readlink": True, "jq": True, "yq": True, "column": True, "nl": True,
    "md5sum": True, "sha256sum": True, "base64": True, "xxd": True, "od": True,
    "file": True, "less": True, "more": True, "man": True, "help": True,
    "pyenv": True, "nvm": True, "asdf": True, "brew": frozenset(
        ["install", "list", "info", "search", "update", "upgrade", "--version"]),
    "apt": frozenset(["install", "list", "show", "search", "update"]),
    "apt-get": frozenset(["install", "update"]),
    "curl": True, "wget": True,   # EMIT patterns already catch the upload forms
}

# `python -m <module>` / `python script.py` are recognised; `python -c <program>`
# and `python -` (stdin) are NOT.  An inline program is written by the agent in
# the same breath as the tool call and passed through nothing that could review
# it; a script on disk arrived via Write/Edit, which this same hook governs.  So
# the file has been seen by the gate and the inline string has not, and that is
# the whole of the distinction.
_INTERPRETERS = frozenset([
    "python", "python2", "python3", "node", "deno", "ruby", "perl", "php",
    "Rscript", "julia", "lua", "osascript", "pwsh", "powershell",
])
_INLINE_PROGRAM_FLAGS = frozenset(["-c", "-e", "--eval", "-E", "--command", "-"])

# `psql`/`mysql` etc: the SQL regexes above scan the whole segment, so a DROP or
# TRUNCATE is already a delete.  A pure read query is recognised; a script file
# (`-f`) is UNRESOLVED, because the adapter cannot read the file.
_SQL_CLIENTS = frozenset(["psql", "mysql", "mariadb", "sqlite3", "mongo",
                          "mongosh", "redis-cli", "clickhouse-client", "cqlsh"])
_SQL_READ_ONLY_RE = re.compile(
    r"^\s*\(*\s*(SELECT|WITH|EXPLAIN|SHOW|DESC(RIBE)?|\\d|\\l|\\dt|PRAGMA)\b",
    re.IGNORECASE)

# Cloud/orchestrator CLIs name a SERVICE and then an OPERATION, so enumerating
# their safe subcommands would mean enumerating every service they have.  The
# operation name is what says whether the call reads or writes, and the read
# vocabulary is small and stable across all of them.  A destructive operation
# never reaches this test: _classify_resource_delete runs first.
#
# An operation that is in NEITHER table -- `aws s3 cp`, `kubectl apply`,
# `gcloud run deploy` -- is UNRESOLVED, which is the correct answer: those
# mutate production and this adapter cannot say by how much.
_CLOUD_CLI_CMDS = frozenset([
    "aws", "gcloud", "az", "gsutil", "s3cmd", "rclone", "doctl", "flyctl",
    "heroku", "vault", "consul", "etcdctl", "eksctl", "kubectl", "oc",
])
_CLOUD_READ_OP_RE = re.compile(
    r"^(ls|list|list-.*|get|get-.*|describe|describe-.*|show|show-.*|head"
    r"|head-.*|cat|status|version|info|help|history|top|logs|log|explain"
    r"|view|search|query|scan|check|validate|plan|diff|whoami|read|lookup"
    r"|current-context|api-resources|api-versions|estimate|preview|summarize)$"
)

# Severity ladder used to pick the winning segment.
_TIER_SEVERITY = {
    "benign": 0,
    "moderate": 1,
    "destructive_broad": 2,
    "destructive_systemic": 3,
}


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

    RFX-144: the command string is DECOMPOSED into segments first and every
    segment is classified; the most severe result wins.  Before this change the
    leading token of the whole string decided, which priced
    `cd /srv/prod && rm -rf data` as a `cd`.
    """
    command = tool_input.get("command") or tool_input.get("cmd") or ""
    command_str = str(command)
    preview = command_str[:200] if command_str else None

    # The fork bomb is checked against the WHOLE string: its `:|:` body would be
    # torn in half by the pipe split, so it must be recognised before any parse.
    if _FORK_BOMB_RE.search(command_str):
        return _classify_bash_delete(command_str, preview)

    segments = _decompose(command_str)
    if not segments:
        # An empty or unparseable command line.  Empty stays `execute` (there is
        # nothing to run); anything non-empty that produced no segment is a
        # string this adapter could not parse, which is the UNRESOLVED case.
        if not command_str.strip():
            return _classify_bash_execute("", preview)
        return _classify_bash_unresolved(command_str, preview,
                                         "command line did not parse")

    results = [_classify_segment(seg, preview) for seg in segments]
    return max(results, key=_segment_severity)


def _segment_severity(result: dict) -> tuple:
    """
    Rank one segment's classification so the most dangerous segment of a chain
    decides the call.  Tier first (it is the axis-derived summary); then verb, so
    that between two segments of equal tier a state-changing one outranks a read
    (`ls; rm /tmp/x` must be governed as the rm, not reported as an ls).
    """
    verb_rank = {"read": 0, "execute": 1, "emit": 2, "delete": 3}
    return (
        _TIER_SEVERITY.get(result["classification_tier"], 1),
        verb_rank.get(result["verb"], 1),
        result.get("magnitude_count", 1),
    )


# ---------------------------------------------------------------------------
# RFX-144 -- shell decomposition
# ---------------------------------------------------------------------------

def _split_top_level(command: str) -> list:
    """
    Split a command line on top-level shell separators, QUOTE-AWARE.

    Separators: `;` `&&` `||` `|` `&` and newline.  A separator inside single or
    double quotes is not a separator -- that is what keeps `python3 -c "a; b"`
    one segment, and it is the difference between parsing a shell chain and
    chopping up an inline program.  Backslash escapes are honoured.

    This is deliberately a scanner and not a regex: the quote state is the whole
    point and a regex cannot carry it.
    """
    out, buf = [], []
    quote = None          # None | "'" | '"'
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if quote:
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
        two = command[i:i + 2]
        if two in ("&&", "||"):
            out.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in (";", "|", "&", "\n"):
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _tokenize(segment: str) -> list:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _strip_wrappers(tokens: list) -> list:
    """
    Remove leading `VAR=value` assignments and prefix wrapper commands, so the
    tokens that remain are the command that actually does something.

    Bounded by the token count: each iteration consumes at least one token.
    """
    i = 0
    n = len(tokens)
    while i < n:
        raw = tokens[i]
        if _ENV_ASSIGN_RE.match(raw):
            i += 1
            continue
        name = os.path.basename(raw).lower()
        if name not in _WRAPPER_PREFIX_CMDS:
            break
        i += 1
        # Consume the wrapper's own flags, and for `timeout 5 cmd` / `nice -n 10
        # cmd` the numeric operand that belongs to the wrapper rather than to the
        # command it runs.
        while i < n and tokens[i].startswith("-"):
            i += 1
        if name in _WRAPPER_NUMERIC_OPERAND and i < n:
            operand = tokens[i]
            if re.match(r"^[0-9]+(\.[0-9]+)?[smhd]?$", operand):
                i += 1
    return tokens[i:]


def _decompose(command: str, depth: int = 0) -> list:
    """
    Return the list of executable segments in a command line, with wrappers
    stripped and `sh -c '<string>'` recursed into.

    Each returned element is a token list, never a string, so no caller has to
    re-parse and no quoting is lost twice.
    """
    segments = []
    for raw in _split_top_level(command):
        tokens = _tokenize(raw)
        stripped = _strip_wrappers(tokens)
        if tokens and not stripped:
            # The segment was NOTHING but a wrapper (`env`, `true`) -- it is that
            # command, not an empty one.
            stripped = tokens
        tokens = stripped
        if not tokens:
            # A segment that is nothing but a redirection (`> /srv/prod/db`) has
            # no command token, but it is still an action.  Keep the raw text so
            # the overwrite check below can see it.
            if raw.strip():
                segments.append(_Segment(raw, []))
            continue
        name = os.path.basename(tokens[0]).lower()
        if name in _SHELL_CMDS:
            inner = _shell_c_argument(tokens)
            if inner is not None:
                if depth >= _MAX_UNWRAP_DEPTH:
                    # Do NOT fall through to classifying the outer `sh` -- that
                    # would price a command by its wrapper, the exact defect.
                    segments.append(_Segment(raw, tokens, unresolvable=True))
                    continue
                nested = _decompose(inner, depth + 1)
                segments.extend(nested if nested else [_Segment(raw, tokens,
                                                                unresolvable=True)])
                continue
        segments.append(_Segment(raw, tokens))
    return segments


# ssh flags that consume the following token as their value, so it is not the
# host and not the start of the remote command.
_SSH_VALUE_FLAGS = frozenset([
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m",
    "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
])


def _ssh_remote_command(tokens: list):
    """
    Return the remote command string from `ssh [flags] [user@]host cmd...`, or
    None when there is no remote command (an interactive session).

    Deliberately does NOT try to reassemble quoting: the tokens are joined with
    spaces and re-split downstream. That loses the distinction between
    `ssh h 'a; b'` and `ssh h a\\; b`, which is fine here -- both are two
    remote commands and both should be judged as the worse of them.
    """
    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in _SSH_VALUE_FLAGS:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        break
    # tokens[i] is the host; anything after it is the remote command.
    if i + 1 >= n:
        return None
    return " ".join(tokens[i + 1:])


def _shell_c_argument(tokens: list):
    """Return the command string passed to `sh -c` / `bash -lc`, or None."""
    for i, tok in enumerate(tokens[1:], start=1):
        if not tok.startswith("-"):
            return None            # `sh script.sh` -- a file, not a string
        # -c, -lc, -ec, --command=...
        if tok.startswith("--command="):
            return tok.split("=", 1)[1]
        if "c" in tok.lstrip("-") and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


class _Segment:
    """One executable piece of a command line: its raw text and its tokens."""

    __slots__ = ("raw", "tokens", "unresolvable")

    def __init__(self, raw: str, tokens: list, unresolvable: bool = False):
        self.raw = raw
        self.tokens = tokens
        self.unresolvable = unresolvable

    @property
    def name(self) -> str:
        return os.path.basename(self.tokens[0]).lower() if self.tokens else ""

    @property
    def subcommand(self) -> str:
        for tok in self.tokens[1:]:
            if not tok.startswith("-"):
                return tok.lower()
        return ""


# ---------------------------------------------------------------------------
# RFX-144 -- per-segment classification
# ---------------------------------------------------------------------------

def _classify_segment(seg: "_Segment", preview: Optional[str]) -> dict:
    """
    Classify ONE segment.  The order is: recognised destruction, then recognised
    emission, then recognised read, then recognised developer operation, then
    UNRESOLVED.  Destruction is checked first because a segment that both reads
    and destroys is a destruction.
    """
    raw = seg.raw
    name = seg.name

    if seg.unresolvable:
        return _classify_bash_unresolved(
            raw, preview, "nested shell deeper than the adapter unwraps")

    # -- recognised destruction ---------------------------------------------
    if name in ("rm", "rmdir", "unlink", "shred"):
        return _classify_bash_delete(raw, preview)

    # The overwrite check runs BEFORE the SQL regexes on purpose.  `truncate -s 0
    # /srv/prod/db.sqlite` was previously caught by _SQL_TRUNCATE_RE -- the SQL
    # keyword regex /\bTRUNCATE\b/i matching the SHELL COMMAND NAME `truncate`.
    # It produced the right verdict for the wrong reason, which means it would
    # have silently stopped working the day that regex was tightened.  It is now
    # caught as what it is: a truncating overwrite.
    overwrite = _classify_overwrite(seg, preview)
    if overwrite is not None:
        return overwrite

    if _GIT_CLEAN_RE.search(raw):
        return _classify_bash_delete(raw, preview)
    if (_SQL_DROP_DATABASE_RE.search(raw) or _SQL_DROP_TABLE_RE.search(raw)
            or _SQL_TRUNCATE_RE.search(raw) or _SQL_DELETE_NO_WHERE.search(raw)):
        return _classify_bash_delete(raw, preview)
    if name == "find" and _FIND_DANGEROUS_RE.search(raw):
        # `find <root> -delete` is a delete over a PREDICATE: the set is whatever
        # matches, which this adapter cannot enumerate.
        return _make_delete(
            blast_radius="broad", sig="rm_recursive",
            tier="destructive_broad", count=1,
            target_ref=seg.tokens[1] if len(seg.tokens) > 1 else None,
            preview=preview,
        )

    resource = _classify_resource_delete(seg, preview)
    if resource is not None:
        return resource

    # -- recognised emission -------------------------------------------------
    if _EMIT_RE.search(raw):
        emitted = _classify_bash_emit(raw, preview)
        # `ssh host '<command>'` is remote command execution wearing an emit
        # hat, and the EMIT class emits `scoped`, so `ssh prod 'rm -rf /srv/data'`
        # was allowed -- an irreversible production destruction that happens to
        # travel over a socket. Credit where due: dev-2 filed this as RFX-158's
        # `gap-remote-execution` row while measuring their own branch, and it is
        # a fail-open of exactly the class this change claims to close, so
        # leaving it would make the claim false.
        #
        # The remote command string is classified the same way `sh -c` is -- it
        # is a command string, and the fact that a socket carries it there does
        # not make it smaller. The severity of the two readings is compared and
        # the worse one wins, with externality kept `outbound` because the bytes
        # do leave. An ssh with no command (an interactive session) is an
        # emission and nothing more.
        if name in ("ssh", "dbclient"):
            remote = _ssh_remote_command(seg.tokens)
            if remote is None:
                # An INTERACTIVE session. `ssh prod ls` is a remote read and is
                # allowed; `ssh prod` opens an unbounded channel that this hook
                # cannot see into and will never be asked about again. Those two
                # differ in exactly the thing the UNRESOLVED class is for --
                # whether the adapter can see what is about to run -- so a bare
                # ssh is UNRESOLVED and not an emission of nothing.
                return _classify_bash_unresolved(
                    raw, preview,
                    "interactive remote session: no command to classify")
            inner = [_classify_segment(s, preview) for s in _decompose(remote)]
            if inner:
                worst = max(inner, key=_segment_severity)
                if _segment_severity(worst) > _segment_severity(emitted):
                    worst = dict(worst)
                    worst["externality"] = "outbound"
                    return worst
        return emitted

    # -- recognised read -----------------------------------------------------
    if name in _READ_COMMANDS:
        return _make_read(preview)
    if name == "find":
        return _make_read(preview)          # dangerous forms handled above
    if name == "git" and seg.subcommand in _READ_GIT_SUBCOMMANDS:
        return _make_read(preview)

    # -- recognised developer operation --------------------------------------
    if _is_dev_safe(seg):
        return _classify_bash_execute(raw, preview)

    # -- UNRESOLVED ----------------------------------------------------------
    return _classify_bash_unresolved(
        raw, preview,
        "no rule for %r" % (name or raw[:40]))


def _is_dev_safe(seg: "_Segment") -> bool:
    """
    Is this segment a RECOGNISED, non-destructive developer operation?

    Returns False for anything not explicitly recognised -- that is the whole
    design (see THE UNRESOLVED CLASS in the module docstring).
    """
    name = seg.name
    if not name:
        return False

    # Interpreters: a module or a script file is recognised; an inline program is
    # not.  See _INLINE_PROGRAM_FLAGS for why the two differ.
    if name in _INTERPRETERS:
        args = seg.tokens[1:]
        if not args:
            return True                      # a bare REPL invocation
        if any(a in _INLINE_PROGRAM_FLAGS for a in args):
            return False
        return True

    # SQL clients: a read query is recognised; a script file is not, because the
    # adapter cannot read the file.  DROP/TRUNCATE/DELETE were already caught by
    # the destruction check before we got here.
    if name in _SQL_CLIENTS:
        if "-f" in seg.tokens or "--file" in seg.tokens:
            return False
        sql = _sql_argument(seg.tokens)
        if sql is None:
            return True                      # interactive session, no statement
        return bool(_SQL_READ_ONLY_RE.match(sql))

    allowed = _DEV_SAFE.get(name)
    if allowed is True:
        return True
    if allowed is not None and seg.subcommand in allowed:
        return True

    # Cloud/orchestrator CLIs: recognise the OPERATION, not the service.
    if name in _CLOUD_CLI_CMDS:
        operands = [t.lower() for t in seg.tokens[1:] if not t.startswith("-")]
        return any(_CLOUD_READ_OP_RE.match(op) for op in operands)

    return False


def _sql_argument(tokens: list):
    """Return the statement passed via -c/--command/-e/--execute, or None."""
    for i, tok in enumerate(tokens):
        if tok in ("-c", "--command", "-e", "--execute"):
            return tokens[i + 1] if i + 1 < len(tokens) else ""
        for flag in ("--command=", "--execute="):
            if tok.startswith(flag):
                return tok.split("=", 1)[1]
    return None


def _classify_resource_delete(seg: "_Segment", preview: Optional[str]):
    """
    A cloud/orchestrator/service-manager invocation that destroys a resource.

    Returns None when the segment is not one.  When it is, blast_radius comes
    from the SHAPE OF THE AFFECTED SET, never from the command's name:
      * a CONTAINER kind (namespace, volume, database, bucket, cluster, ...)
        -> systemic; destroying it destroys an unenumerable set of things inside
      * an unbounded selector (--all, --recursive, a label selector, a wildcard)
        -> broad; the set is a predicate
      * otherwise the named operands are an enumeration and cardinality decides,
        with the same inclusive 20 boundary the rm path uses
    """
    name = seg.name
    if name not in _RESOURCE_DELETE_CMDS:
        return None

    tokens = seg.tokens
    operands = [t for t in tokens[1:] if not t.startswith("-")]

    # Find the token that means "delete".  Either the whole token is a delete
    # verb (`kubectl delete`, `terraform destroy`, `helm uninstall`) or the verb
    # is fused into an operation name (`aws rds delete-db-instance`,
    # `gcloud sql instances delete`).
    verb_index = None
    for idx, tok in enumerate(tokens[1:], start=1):
        low = tok.lower()
        if low in _RESOURCE_DELETE_VERBS:
            verb_index = idx
            break
        if any(low.startswith(v + "-") for v in _RESOURCE_DELETE_VERBS):
            verb_index = idx
            break
    if verb_index is None:
        return None

    # `systemctl stop` is not a delete; only its destructive verbs are, and
    # `stop` is not one of them, so it never reaches here.  `docker rm` does.

    verb_token = tokens[verb_index].lower()
    after = [t for t in tokens[verb_index + 1:] if not t.startswith("-")]
    before = [t.lower() for t in tokens[1:verb_index] if not t.startswith("-")]

    # The resource KIND may sit before the verb (`gcloud sql instances delete`)
    # or after it (`kubectl delete namespace`).  Look in both, plus the fused
    # form (`delete-db-instance`).
    kind_tokens = set(before)
    if after:
        kind_tokens.add(after[0].lower())
    if "-" in verb_token:
        kind_tokens.update(verb_token.split("-")[1:])
    # `aws s3 rm s3://bucket/key` -- the service name carries the kind.
    is_container = bool(kind_tokens & _CONTAINER_RESOURCE_KINDS)

    # `terraform destroy` names no resource at all: it destroys the whole managed
    # state.  That is the broadest container there is.
    if name in ("terraform", "tofu") and verb_token == "destroy":
        is_container = True
    if name in ("helm",) and verb_token in ("uninstall", "delete"):
        is_container = True          # a release is every object it installed

    is_predicate = bool(_PREDICATE_FLAG_RE.search(seg.raw))

    # `kubectl delete pod a b` names the KIND first and then the entities, so the
    # kind token must not be counted as one of them -- 2 pods is 2, not 3.
    if name in ("kubectl", "oc") and len(after) > 1:
        after = after[1:]

    if is_container:
        blast_radius, tier, sig = "systemic", "destructive_systemic", "container_delete"
        count = 1
    elif is_predicate or not after:
        blast_radius, tier, sig = "broad", "destructive_broad", "resource_delete"
        count = max(len(after), 1)
    elif len(after) >= 20:
        blast_radius, tier, sig = "broad", "destructive_broad", "resource_delete"
        count = len(after)
    elif len(after) >= 2:
        blast_radius, tier, sig = "scoped", "moderate", "resource_delete"
        count = len(after)
    else:
        blast_radius, tier, sig = "single", "moderate", "resource_delete"
        count = 1

    return _make(
        verb="delete",
        reversibility="irreversible",
        blast_radius=blast_radius,
        externality="internal",
        magnitude_count=count,
        target_kind="resource",
        target_ref=after[0] if len(after) == 1 else None,
        danger_signature=sig,
        classification_tier=tier,
        command_preview=preview,
        file_path=None,
    )


def _classify_overwrite(seg: "_Segment", preview: Optional[str]):
    """
    A truncating overwrite: `> path`, `dd of=path`, `mkfs`, `truncate -s 0 path`.

    Returns None when the segment is not one.  An overwrite destroys the prior
    contents exactly as irreversibly as an unlink, which the `Write` classifier
    has always recognised (os.path.exists -> irreversible) and the shell forms
    did not.

    blast_radius is a KIND claim and it is RAISE-ONLY: a target that names a
    container of records (`.sqlite`, `.db`, a pgdata dir) is `broad`, a block
    device is `systemic`, and anything else is a single entity -- `single`.  A
    single-entity overwrite in production is allowed by the stock policy pack
    (R4 default-allow); that residue is R4's shape, not a misclassification, and
    it is RFX-128's ticket rather than this one's.
    """
    target = None
    sig = "overwrite_container"

    if _MKFS_RE.search(seg.raw):
        target = seg.tokens[-1] if len(seg.tokens) > 1 else None
        # A filesystem write over a device is not recoverable by an approval.
        return _make_delete(blast_radius="systemic", sig="overwrite_container",
                            tier="destructive_systemic", count=1,
                            target_ref=target, preview=preview)

    dd = _DD_OUTPUT_RE.search(seg.raw)
    explicit = True
    if dd and seg.name == "dd":
        target = dd.group(1)
    elif seg.name == "truncate":
        operands = [t for t in seg.tokens[1:] if not t.startswith("-")]
        # `truncate -s 0 file` -- the size operand may be positional.
        target = operands[-1] if operands else None
    else:
        # A `>` redirection attached to some OTHER command.  Only a target that
        # is a container of data or a device is treated as a destruction here:
        # `pytest > out.log` truncates out.log, and calling that a delete would
        # push routine build output into R5's delete budget for no gain.  A
        # single ordinary file left to the normal path is the same judgement the
        # `rm /tmp/scratch.txt` case already makes.
        explicit = False
        redirect = _TRUNCATE_REDIRECT_RE.search(seg.raw)
        if redirect:
            target = redirect.group(1)

    if not target or target in _DISCARD_SINKS:
        return None

    if _BLOCK_DEVICE_RE.match(target):
        return _make_delete(blast_radius="systemic", sig=sig,
                            tier="destructive_systemic", count=1,
                            target_ref=target, preview=preview)
    if _DATA_CONTAINER_PATH_RE.search(target):
        return _make_delete(blast_radius="broad", sig=sig,
                            tier="destructive_broad", count=1,
                            target_ref=target, preview=preview)
    if not explicit:
        return None
    return _make_delete(blast_radius="single", sig="disk_write",
                        tier="moderate", count=1,
                        target_ref=target, preview=preview)


def _make_read(preview: Optional[str]) -> dict:
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


def _make_delete(blast_radius: str, sig: str, tier: str, count: int,
                 target_ref: Optional[str], preview: Optional[str]) -> dict:
    return _make(
        verb="delete",
        reversibility="irreversible",
        blast_radius=blast_radius,
        externality="internal",
        magnitude_count=max(count, 1),
        target_kind="file" if target_ref and "/" in target_ref else "resource",
        target_ref=target_ref,
        danger_signature=sig,
        classification_tier=tier,
        command_preview=preview,
        file_path=target_ref if target_ref and "/" in target_ref else None,
    )


def _classify_bash_unresolved(command: str, preview: Optional[str],
                              why: str) -> dict:
    """
    The adapter cannot name this command's effect.

    SPEC §2's conservative defaults apply (unknown reversibility ->
    irreversible), with blast_radius `broad` rather than `systemic` so the call
    reaches a human (R2) instead of being refused outright (R3).  See THE
    UNRESOLVED CLASS in the module docstring for why that softening is the
    decidable choice and not a hedge.

    STRICT raises it to `systemic`: an operator who sets the tightening flag is
    asking for "unrecognised commands do not run".
    """
    if _is_strict_mode():
        blast_radius, tier = "systemic", "destructive_systemic"
    else:
        blast_radius, tier = "broad", "destructive_broad"
    return _make(
        verb="execute",
        reversibility="irreversible",
        blast_radius=blast_radius,
        externality="internal",
        magnitude_count=1,
        target_kind="command",
        target_ref=None,
        danger_signature="unclassified_command",
        classification_tier=tier,
        command_preview=preview,
        file_path=None,
    )


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
