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
newline (quote-aware); `sh -c '<inner>'` is expanded in place; the bodies of
command substitutions -- `$(...)`, backticks, `<(...)`, `>(...)` -- are read as
the commands they are (RFX-301); `sudo`, `env`, `timeout`, `nohup`, `xargs` and
friends are peeled off.  Each resulting command is classified on its own and
THE MOST DANGEROUS ONE IS REPORTED.  A command line is a `read` only when every
command on it is a read.

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

Write / Edit / MultiEdit / NotebookEdit, PATH CAP (RFX-338):
  A `file_path` longer than MAX_FILE_PATH_CHARS is not classified at all.  It
  gets the safe-conservative reading (irreversible / systemic, `oversize_path`)
  and hook.py refuses it under `adapter/path_too_long`.  The sensitive-path
  pattern is quadratic on a long subject and the RFX-321 watchdog cannot
  interrupt a regex, so the input is bounded instead.  See MAX_FILE_PATH_CHARS.

Read / Glob / Grep / LS (read):
  reversibility: reversible
  blast_radius:  single
  externality:   internal

WebFetch / WebSearch (read):
  reversibility: reversible
  blast_radius:  single
  externality:   outbound  (the request leaves the system)

Unknown tool -- INCLUDING EVERY mcp__* TOOL (RFX-206):
  This is the branch every MCP server's tools land in, so it is the branch that
  prices a database, a payment processor and a cluster.  It gets its own
  section below.

  FLOOR (what we emit when the call tells us nothing):
    verb:          execute
    reversibility: irreversible
    blast_radius:  broad          <-- was `scoped`; see "why broad" below
    externality:   outbound       <-- was `internal`; RFX-214, see below
    magnitude:     1

  Measured on 2026-08-22 against reeflex-core at 759b83f with the shipped
  policy pack: the old floor (`scoped`) is the ONE variant of this envelope
  that reeflex-core ALLOWS.  A full-table production DELETE, a 9,999,999 EUR
  refund and a list_tables all returned `allow / reeflex.policy/default_allow`.
  Omitting the axes entirely returns `require_approval /
  reeflex.policy/unclassified_action`, and declaring `broad` returns
  `require_approval / reeflex.policy/irreversible_broad_prod`.  So the old
  "conservative default" was strictly WORSE than declaring nothing: it asserted
  three axes nobody had measured, and the values it asserted sat just under
  every threshold R2 and R3 read.

  WHY `broad` AND NOT `systemic`, which this docstring used to claim as the
  safe-conservative default: `systemic` is R3, a terminal deny no human may
  clear.  SPEC §4.0 (RFX-132) settled that question the other way -- an action
  we could not price should ask a human, not refuse forever, because "a gate
  that refuses the unfamiliar gets switched off -- a fail-open with extra
  steps".  `broad` is R2, a hold.  CONSEQUENCE, stated so it is not discovered
  later: no unknown tool can produce a terminal deny from this branch.  It
  produces a hold, or (outside production) an allow.

  WHY NOT OMIT THE AXES and let core's R0 fire: SPEC §2 -- "a missing axis is a
  conformance failure".  Core's R0 is a safety net for non-conformant adapters,
  not an interface for conformant ones.  We stay conformant and make the
  declared value honest instead.

  ESCALATION ABOVE THE FLOOR IS MONOTONE -- evidence read out of tool_name and
  tool_input may only ever RAISE risk, never lower it.  That direction is
  forced, and by three separate findings:
    - RFX-165: an agent must not be able to lower its own risk price by
      supplying LESS information.  Under monotone escalation, omitting
      everything buys the floor and nothing cheaper.
    - RFX-173: the upstream MCP server does not get to mark its own homework.
      A `readOnlyHint`-style "this one is safe" signal is a DE-escalation, so
      it is not in this design at all.  A tool NAMED `list_*` is priced exactly
      like a tool named `delete_*` until something else escalates it -- the
      name can only add risk, never subtract it.
    - RFX-175: read EVERY token of the name, not the first.  `search_and_replace`
      is not a search.

  WHAT tool_input IS ALLOWED TO DO, and why it is not the same trust question
  as RFX-173: tool_input is not metadata ABOUT the call, it IS the call -- the
  same dict is what the MCP server executes.  An agent that understates
  `amount` to look cheap moves less money; an agent that narrows `where` to
  look bounded deletes less.  The lie is self-defeating in a way a server's
  annotation is not.  It is still only ever read to escalate.

  WHAT WE EXTRACT (see _unknown_* helpers):
    verb        `transact` on a money token, `delete` on a destructive token,
                `emit` on a send/publish token, else the `execute` floor.
                This is what makes R5's per-verb budgets able to count these
                calls at all -- a delete priced `execute` never lands in
                cumulative.count_by_verb.delete.
    externality `outbound` -- for money and send/publish, and ALSO as the
                floor (RFX-214).  Feeds R5's external_sends budget.
                The floor is `outbound` and not `internal` because `internal`
                is the one value that budget does not charge, and this branch
                fires precisely when the adapter cannot say what the tool
                does: an operator's send budget must not be bounded by
                traffic we failed to identify.  A tool this adapter KNOWS to
                be internal still declares `internal` -- the change is scoped
                to the ignorance path, or every file read would consume the
                send budget.
    magnitude   the largest bounded set the arguments name (a list length, or a
                count/limit/batch_size), floored at 1.  Feeds R5's
                objects_touched budget, which weighs EVERY action.
    target_ref  a short redacted `k=v` digest of the identifying arguments, so
                the human answering the hold can see WHICH table, bucket or
                namespace.  A hold that says "resource: null" cannot be
                answered.
    params      `amount` / `currency` when the call carries money, so R5's
                money budget can price it (SPEC §4.1.1).  When a money-named
                tool declares NO amount we cannot invent one, so we record
                `amount_declared: false` rather than let the omission read as
                zero -- that omission is the RFX-133/RFX-180 evasion.

  REDACTION IS PART OF THE DESIGN, not a nicety.  tool_input is arbitrary
  third-party JSON and routinely carries credentials.  target_ref is
  transmitted to core and written to the audit log, so we take scalars only,
  never nested structures, skip any key that looks like credential material,
  and cap every value.  "Discard tool_input entirely" was a wrong answer to a
  real question.

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
# The cost cap on Bash classification (RFX-322)
# ---------------------------------------------------------------------------
#
# `classify()` is super-linear in Bash command LENGTH -- the cost is shlex
# tokenisation plus one pass of the segment patterns per segment.  Measured on
# this tree (`echo <n chars>`, CPython 3.9): 10k 0.03s, 50k 0.23s, 100k 0.61s,
# 200k 1.90s, 400k 6.54s; qa--221 measured 700k at 34.15s and 800k at 52.72s
# against the published 0.2.0 wheel.  Past ~700 KB the classifier alone
# overruns the 30 s PreToolUse hook timeout, the runner kills the hook, and the
# tool RUNS (qa--221 Finding B).  A gate that spends 30 s deciding a 700 KB
# command has already lost, whatever it eventually decides.
#
# So the classifier is bounded: past the cap it does not tokenise at all.  It
# returns the SPEC §2 safe-conservative reading of a command it has not read --
# irreversible / systemic, `oversize_command` -- and hook.py refuses the action
# under `adapter/command_too_large` whatever the engine says about it.
#
# WHY 64 KiB.  It is ~180x the longest command in this repo's Bash conformance
# corpus, it costs ~0.3 s to classify, and it is half of Linux's MAX_ARG_STRLEN
# (128 KiB), the point past which a single argument cannot be exec'd at all.
# A command that does not fit in it is not a command anyone wrote by hand.
#
# REEFLEX_CLAUDE_MAX_COMMAND_CHARS may LOWER the cap and may not raise it, for
# the same reason REEFLEX_CLAUDE_HOOK_TIMEOUT may only lower the deadline: a
# bound a customer can set bigger is the defect, not the fix (see deadline.py).
MAX_BASH_COMMAND_CHARS = 65536
_MAX_COMMAND_CHARS_ENV = "REEFLEX_CLAUDE_MAX_COMMAND_CHARS"

# RFX-338.  The same bound, for the same reason, on the OTHER input that reaches
# a backtracking pattern: `file_path`.
#
# RFX-322 capped the Bash path and stopped there, because that is where the
# 700 KB command was.  It left `_classify_write` / `_classify_edit` running
# `_SENSITIVE_PATH_RE` on an UNCAPPED `file_path` -- and that pattern contains
# `docker-compose.*\.ya?ml$`, a `.*` in front of an anchored suffix, which is
# quadratic on a long subject that never satisfies the anchor.  Measured on the
# shipped tree (qa--233, reproduced here): 64 KB 0.22 s, 256 KB 3.36 s, 1 MB
# 50.6 s -- ~3.9x per doubling, in ONE `re.search`.
#
# WHY A CAP AND NOT THE WATCHDOG.  RFX-321's deadline is a `threading.Timer`,
# and CPython's `sre` engine does not release the GIL for the duration of a
# match, so the watchdog thread cannot run until the match returns.  qa--233
# measured the timer firing at +0.01 s against a pure-Python loop and at
# work-end -- independent of the budget -- against a regex.  The deadline
# therefore bounds a slow Python loop and does NOT bound a slow regex: the hook
# is killed by the 30 s PreToolUse runner, and a killed hook means the tool RUNS,
# ungated and with no audit line.  So the bound goes on the INPUT: the watchdog
# cannot be made to cover this by tuning its budget, because the timer thread
# does not get the GIL back until the C-level match returns -- which is what
# qa--233's budget-independence arm measured.
#
# WHY 4096, AND WHY THERE IS NO ENV KNOB.  This is not a judgement call like the
# 64 KiB command cap, so it does not get the command cap's lowering knob: 4096 is
# Linux `PATH_MAX` (including the NUL), the length past which no path can name a
# file at all -- `open()` returns ENAMETOOLONG.  macOS is 1024 and Windows'
# extended limit is 32767 per COMPONENT but 260 unprefixed, so 4096 covers every
# path a real caller can use on any of them.  A `file_path` longer than this is
# not a path; it is a payload wearing the field's name.  Classifying it costs
# ~0.001 s, so nothing is traded away to hold this bound.
MAX_FILE_PATH_CHARS = 4096


def max_bash_command_chars() -> int:
    """The effective Bash-command cap: the built-in ceiling, lowerable by env."""
    raw = os.environ.get(_MAX_COMMAND_CHARS_ENV, "").strip()
    if raw:
        try:
            value = int(raw)
        except (ValueError, TypeError):
            value = 0
        if value > 0:
            return min(value, MAX_BASH_COMMAND_CHARS)
    return MAX_BASH_COMMAND_CHARS


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

# The three subcommands above that accept `--output=PATH`, which writes the
# diff/log text to PATH and destroys whatever was there.  Ground truth off
# disk rather than off the manual (RFX-358): a file holding `PRECIOUS DATA`
# was passed as `--output` to each of the three; all three returned 0 and the
# canary was gone, replaced by diff/commit text.  `status` and `branch` do not
# take the flag, so they are not in here.
#
# `--output=P` and `--output P` are the only spellings git accepts: `-oP`
# exits 129 and `-o P` exits 128, writing nothing.  So this must NOT go through
# `_flag_value(args, "-o", "--output")` the way `sort` does -- that helper also
# matches a bare `-o` and the letter `o` inside any short bundle, and pricing a
# destruction off a spelling git refuses to run states something untrue.
_OUTPUT_WRITING_GIT_SUBCOMMANDS = frozenset([
    "diff", "log", "show",
])


def _git_output_target(args: list):
    """
    Value of `git <sub> --output=PATH` / `--output PATH`, or None.

    Deliberately narrower than `_flag_value`: only the two spellings git
    actually accepts.  See `_OUTPUT_WRITING_GIT_SUBCOMMANDS` for why.
    """
    for i, a in enumerate(args):
        if a == "--output":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("--output="):
            return a.split("=", 1)[1]
    return None


# `git branch` flags that CHANGE a ref rather than list one.  Split by whether
# git will refuse to lose data on its own, measured with the binary (2.52.0)
# rather than reasoned:
#
#     git branch -d  <unmerged>        rc=1    branch survives, git refuses
#     git branch -D  <unmerged>        rc=0    "Deleted branch (was c3a61fe)"
#     git branch -m  <src> <existing>  rc=128  both survive, git refuses
#     git branch -M  <src> <existing>  rc=0    the overwritten ref is gone
#
# So the uppercase pair is the one that can lose commits.  The lowercase pair
# still is not a READ -- it changes a ref -- but pricing it as an irreversible
# destruction would charge ordinary branch hygiene to R5's cumulative delete
# budget, which is the RFX-249 over-blocking cost the account-delete branch in
# `_infra_destructive` already weighs.  They are separated here so the two
# tiers can be priced differently.
_GIT_BRANCH_MUTATE_FLAGS = frozenset([
    "-d", "--delete", "-D", "-m", "--move", "-M", "-c", "--copy", "-C",
    "--set-upstream-to", "-u", "--unset-upstream", "--edit-description",
])
_GIT_BRANCH_FORCE_FLAGS = frozenset(["-D", "-M", "-C", "-f", "--force"])


def _git_branch_flags(branch_args: list):
    """
    (mutates, forces) for the arguments of `git branch`.

    `--set-upstream-to=origin/main` carries its value inline, so the flag name
    is taken from the left of the `=`.  Short flags are read CASE-SENSITIVELY:
    `-d` and `-D` are different commands, and folding them would read a force
    delete as the spelling git refuses -- the same fail-open direction that
    `tee`'s bundle test documents above.
    """
    names = [a.split("=", 1)[0] for a in branch_args]
    mutates = any(n in _GIT_BRANCH_MUTATE_FLAGS for n in names)
    forces = (any(n in _GIT_BRANCH_FORCE_FLAGS for n in names)
              # `--delete --force` / `-d --force` is `-D` spelled out.
              or (mutates and any(n in ("-f", "--force") for n in names)))
    return mutates, forces

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

# RFX-353 — this used to be
#     _FORCE_PUSH_RE = re.compile(r"\bgit\s+push\b.*--force\b|\bgit\s+push\b.*-f\b")
# i.e. "is there a dash-f anywhere on the line after the words `git push`".  It
# is now `_git_push_forces()`, which reads git push's OWN argv.  The measured
# reason (qa--248, ground truth against a local bare repo) is that the letter
# test answers a question about a remote ref without looking at one:
#   git push origin +main:main   -> git prints "(forced update)", allowed
#   git push --mirror origin     -> "- [deleted] doomed",         allowed
#   git push origin :doomed      -> "- [deleted] probe",          allowed
#   git push --delete origin b   -> "- [deleted] doomed2",        allowed
#   git push --dry-run --force   -> remote ref did not move,      held
# All five spellings reach the same `git_force_push` signature rather than a new
# one: the audit line's signature vocabulary is a closed allowlist core-side.
_GIT_PUSH_FORCE_LONG = frozenset([
    "--force", "--force-with-lease", "--mirror", "--delete",
])
# `--force-if-includes` is deliberately absent: it is a SAFETY modifier that only
# has meaning alongside a force flag, and never forces on its own.
_GIT_PUSH_DRY_LONG = frozenset(["--dry-run"])

_PUBLISH_RE = re.compile(r"\b(npm|yarn)\s+publish\b")

# ---------------------------------------------------------------------------
# Bash DELETE patterns
# ---------------------------------------------------------------------------

# RFX-353 — this used to be
#     _GIT_CLEAN_RE = re.compile(r"\bgit\s+clean\b.*-[a-zA-Z]*f[a-zA-Z]*", re.I)
# i.e. "is there an `f` after a dash anywhere on the line".  A PATH OPERAND
# supplies that letter, so `git clean -n src/my-fixtures` — a dry run, which
# printed "Would remove" and left the file in place when measured — was priced
# delete / irreversible / broad and held for approval, while `git clean -n -d`
# was execute / recoverable.  It is now `_git_clean_destroys()`, on git clean's
# own argv, with dry-run dominant: `-n` beat `-f` in all four orders measured
# (`-n -f`, `-f -n`, `-nfd`, `-fnd` — every one left the canary in place).
_GIT_CLEAN_FORCE_LONG = frozenset(["--force"])
_GIT_CLEAN_DRY_LONG = frozenset(["--dry-run"])
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

# RFX-353 — this used to be
#     _RM_RECURSIVE_RE = re.compile(r"\brm\b.*-[a-zA-Z]*r[a-zA-Z]*")
# i.e. "is there a LOWERCASE r after a dash anywhere on the line".  Wrong in
# both directions at once, which is the tell that no argv was ever read:
#   rm -R /home/app/uploads    destroyed the tree when measured, scored
#                              single/none and was ALLOWED (`-R` is the POSIX
#                              synonym of `-r`; so were `-fR` and `-Rf`)
#   rm /home/app/my-report.txt removed one file and left its sibling tree in
#                              place, scored broad/rm_recursive and was HELD —
#                              the caller's FILENAME was the whole difference.
# Recursion is now read off the rm command's own flag tokens by
# `_rm_is_recursive()`.
_RM_RECURSIVE_SHORT = ("r", "R")
_RM_RECURSIVE_LONG = frozenset(["--recursive"])

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

# Account / group destruction (RFX-166).  Deleting a principal removes the
# account row and its credentials; a shell has no undo and no trash for it,
# which is why the shared corpus prices it `irreversible` on both reference
# adapters (reeflex-spec/conformance/reversibility.json::user/single).
_ACCOUNT_DELETE_COMMANDS = frozenset([
    "userdel", "deluser", "groupdel", "delgroup",
])

# ---------------------------------------------------------------------------
# RFX-144 (ported from PR #98, dev-1 round 054) -- a path that names a
# CONTAINER of records rather than one leaf entity.
#
# WHY THIS IS ALLOWED TO EXIST alongside SPEC §4.2, which forbids an adapter
# from reading cardinality off a name: this is a KIND claim, not a cardinality
# claim, and §4.2 permits exactly that ("An adapter MAY use name-derived
# signals to satisfy step 1 ... and MAY use them to raise").  It is therefore
# RAISE-ONLY -- it can make a single-path target `broad`, and it can never make
# an enumerated set smaller.  `rm /srv/prod/db.sqlite` names one file, and that
# one file is a database: the cardinality is still 1, but the KIND of thing
# being destroyed is a container of records.
#
# A block device is worse again -- writing a filesystem over it is not
# something a human approval can undo -- so it raises to `systemic`.
_DATA_CONTAINER_PATH_RE = re.compile(
    r"(\.sqlite3?$|\.db$|\.mdb$|\.sql$|\.dump$|\.bak$|\.tar(\.(gz|bz2|xz|zst))?$"
    r"|\.zip$|\.rdb$|\.aof$|\.frm$|\.ibd$|/pgdata(/|$)|/mysql(/|$))",
    re.IGNORECASE,
)
_BLOCK_DEVICE_RE = re.compile(
    r"^/dev/(?!null$|zero$|urandom$|random$|std(in|out|err)$|tty|fd/)"
)

# `VAR=value` prefix assignment (ported from PR #98).  The identifier-start
# anchor is what keeps this from eating `--flag=value`.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# A redirection operator, optionally with the file descriptor it applies to:
# `>f` `>>f` `<f` `2>f` `2>&1` `&>f` `>|f` `<<<w` `<<EOF`.  Used to peel a
# redirection written BEFORE the command word (RFX-337); no command word can
# begin with one of these, so this cannot swallow a real command.
_REDIRECTION_RE = re.compile(r"^(?:\d+|&)?(?:>>|>\||>&|<<<|<<|<&|>|<)")

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

# RFX-351.  KEYED BY (CLIENT, FLAG), because a flag does not mean the same
# thing in two different programs.  Until this table existed there was ONE set
# -- {-f, --file, --init, -init, --source} -- answered for all ten clients, and
# a uniform answer to a per-command question is wrong in both directions at
# once:
#
#   fail-open   the client IS handed a script file under the spelling its own
#               manual documents, the spelling is not in the shared set, and
#               the statements stay invisible -- which is the whole reason this
#               branch exists.  `sqlcmd -i`, `clickhouse-client --queries-file`,
#               `redis-cli --eval` and `mongosh db drop.js` each fell through to
#               the default Bash execute arm: execute/recoverable/scoped,
#               danger_signature null, target_ref null.  No hold, no human.
#   fail-noisy  `-f` is `--force` for mysql and mariadb and the CODEPAGE option
#               for sqlcmd.  `mysql -f -e 'SELECT 1'` -- inline, fully visible,
#               a read -- was priced irreversible/broad/sql_script_unbounded,
#               the heaviest verdict this branch can produce.  A gate that asks
#               on a SELECT gets switched off, and a switched-off gate protects
#               nobody: the same argument RFX-131/RFX-145 make above.
#
# Flags that take the path as the NEXT argument.  A client absent from this map
# has no flag spelling of its own (mysql/mariadb/mongo read a script through
# the `<` shape, or through the in-client `source` handled below).
_DB_SCRIPT_FLAGS_BY_CLIENT = {
    "psql":              frozenset(["-f", "--file"]),
    "cqlsh":             frozenset(["-f", "--file"]),
    "mongosh":           frozenset(["-f", "--file"]),
    "sqlite3":           frozenset(["-init", "--init"]),
    "sqlcmd":            frozenset(["-i", "--input-file"]),
    "clickhouse-client": frozenset(["--queries-file"]),
    "redis-cli":         frozenset(["--eval"]),
}
# The same spellings written `--flag=VALUE`, per client.
_DB_SCRIPT_PREFIXES_BY_CLIENT = {
    client: tuple(sorted(f + "=" for f in flags if f.startswith("--")))
    for client, flags in _DB_SCRIPT_FLAGS_BY_CLIENT.items()
}
# Clients that take a script file as a bare POSITIONAL argument.  Both mongo
# shells do: `mongosh prod /tmp/drop.js` runs the file and exits.  Matched on
# the extension only, so a database name or a connection string is not one.
_DB_POSITIONAL_SCRIPT_CLIENTS = frozenset(["mongosh", "mongo"])
_DB_POSITIONAL_SCRIPT_SUFFIXES = (".js", ".mongodb")
# In-client "run this file" directives.  These travel INSIDE otherwise visible
# inline SQL -- `mysql -e 'source /tmp/wipe.sql'`, `sqlite3 db '.read f.sql'` --
# so the text is on the command line and the statements still are not.
#
# qa--251: the directive is anchored to a STATEMENT boundary -- the start of the
# argument or a `;` -- and not, as first written, to any whitespace.  `source`
# is an ordinary SQL identifier, so accepting it mid-statement priced seven
# measured everyday reads at the heaviest verdict this branch produces:
# `mysql -e 'SELECT source FROM logs'` and `psql -c 'SELECT source FROM events'`
# both came back irreversible/broad/sql_script_unbounded.  That is the same
# fail-noisy this table was written to remove from `mysql -f -e 'SELECT 1'`, and
# a gate that asks on a SELECT gets switched off.  Anchoring costs nothing in
# the other direction: a directive IS a statement, so every genuine spelling --
# `source f.sql`, `.read f.sql`, `\. f.sql`, and any of them after a `;` -- is
# still at a boundary.  Measured both ways in qa--251's report.
_DB_INLINE_SOURCE_RE = re.compile(
    r"""(?:^|[;'"])\s*(?: \.read | source | \\\. )\s+\S""",
    re.VERBOSE | re.IGNORECASE,
)

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
# Unknown / mcp__* tool vocabulary (RFX-206)
#
# These are ESCALATORS.  A name matching nothing here keeps the floor; a name
# matching something here is priced UP.  Nothing in this section can ever price
# a call DOWN, which is what keeps an upstream server from marking its own
# homework (RFX-173) and an agent from buying a discount by saying less
# (RFX-165).  Matching is on WHOLE TOKENS of the split name, every token, not
# the first -- `search_and_replace` is not a search (RFX-175).
# ---------------------------------------------------------------------------

# Claude Code's OWN built-in tools whose effect is confined to the session:
# they read the agent's own state or scratch surfaces and touch nothing the
# customer owns.  They were absent from every branch above, so they fell to the
# unknown floor -- and once that floor became `broad`, an ordinary ToolSearch
# started asking for human approval in production.  Measured, not assumed: the
# first end-to-end run of this fix was blocked on `ToolSearch`, not on the
# delete it was aimed at.
#
# The right answer to that noise is to make KNOWN tools known, not to soften the
# floor for unknown ones.  This is the "replace with a per-command allow-list"
# upgrade path this module's docstring has always named.
#
# This list is NOT the same trust question as RFX-173.  These are first-party
# tools shipped by the same agent runtime the hook runs inside, enumerated here
# by us -- not third-party tools self-describing as safe.  Nothing an MCP server
# says can add a name to it.
#
# DELIBERATELY ABSENT, because their blast radius is whatever they are asked to
# do: Task/Agent (spawns a subagent), SlashCommand and Skill (run arbitrary
# instructions), KillShell (ends a process). Those keep the unknown floor.
_SESSION_LOCAL_READ_TOOLS = frozenset([
    "toolsearch",      # loads tool schemas into context
    "bashoutput",      # reads output of a shell this session already started
    "todowrite",       # the agent's own task list
    "exitplanmode",    # a mode change in the agent's own UI
])

_UNKNOWN_MONEY_TOKENS = frozenset([
    "refund", "payout", "payment", "pay", "charge", "chargeback", "transfer",
    "transaction", "invoice", "subscription", "withdraw", "withdrawal",
    "disburse", "disbursement", "capture", "settle", "settlement",
])

_UNKNOWN_DESTRUCTIVE_TOKENS = frozenset([
    "delete", "destroy", "drop", "truncate", "purge", "remove", "rm", "erase",
    "wipe", "revoke", "terminate", "kill", "prune", "expire", "unlink",
    "uninstall", "deprovision", "teardown", "reset",
])

_UNKNOWN_EMIT_TOKENS = frozenset([
    "send", "publish", "email", "mail", "notify", "notification", "broadcast",
    "tweet", "sms", "webhook", "dispatch", "deploy", "release", "upload",
])

# Argument keys whose value identifies WHAT is being acted on.  Used to build a
# human-readable target_ref for the hold.  Deliberately excludes `key`, which is
# as often a credential as an identifier.
_UNKNOWN_REF_KEYS = (
    "table", "database", "collection", "bucket", "namespace", "repo",
    "repository", "path", "file_path", "filename", "url", "uri", "arn",
    "queue", "topic", "channel", "cluster", "project", "resource",
    "resource_id", "id", "ids", "name", "where", "filter", "query",
)

# Anything matching this in an argument NAME is treated as credential material:
# never copied into target_ref, never into params.  target_ref is transmitted to
# core and written to the audit log.
_UNKNOWN_SECRET_KEY_RE = re.compile(
    r"(token|password|passwd|pwd|secret|credential|auth|bearer|private|"
    r"api[_-]?key|access[_-]?key|signature|session|cookie|salt)",
    re.IGNORECASE,
)

# Argument keys that state how many entities the call affects.
_UNKNOWN_COUNT_KEYS = (
    "count", "limit", "n", "num", "number", "quantity", "qty",
    "max_results", "maxresults", "batch_size", "batchsize", "size", "top",
)

_UNKNOWN_AMOUNT_KEYS = ("amount", "amount_cents", "value", "total", "price", "sum")
_UNKNOWN_CURRENCY_KEYS = ("currency", "currency_code", "ccy", "curr")

# Splits mcp__stripe__refundAllCharges into
# ["mcp", "stripe", "refund", "all", "charges"].
_UNKNOWN_NAME_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")

_UNKNOWN_REF_MAX_VALUE = 80
_UNKNOWN_REF_MAX_TOTAL = 200
_UNKNOWN_REF_MAX_FIELDS = 3


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
    elif tool_name_lower in _SESSION_LOCAL_READ_TOOLS:
        return _classify_read_tool(tool_input)
    elif tool_name_lower in ("webfetch", "websearch"):
        return _classify_web(tool_input)
    else:
        # Every mcp__* tool lands here, so this branch prices a database, a
        # payment processor and a cluster.  It needs the NAME too (RFX-206);
        # it used to be handed only tool_input, and read neither.
        return _classify_unknown(tool_name, tool_input)


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

    # RFX-322.  BEFORE any tokenising and before any pattern -- including the
    # fork-bomb regex, whose `.*` is itself unbounded work over a long line.
    # Past the cap we do not read the command, and we say so rather than
    # pricing it from a preview we have not parsed: SPEC §2's safe-conservative
    # axes, and a danger_signature that names the reason.  hook.py refuses the
    # action outright on this signature; see deadline.py for why "decide fast"
    # and "decide correctly" are the same requirement here.
    cap = max_bash_command_chars()
    if len(command_str) > cap:
        return _make(
            verb="execute",
            reversibility="irreversible",
            blast_radius="systemic",
            externality="internal",
            magnitude_count=1,
            target_kind="command",
            target_ref=None,
            danger_signature="oversize_command",
            classification_tier="destructive_systemic",
            command_preview=preview,
            file_path=None,
        )

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

    budget = _WalkBudget()
    segments = _shell_segments(command_str, budget=budget)

    # RFX-328/336/337.  The walk ran out before it finished reading the line,
    # so what came back is a PREFIX of the commands this line runs and the
    # unread remainder is exactly where a `rm -rf` would be hidden.  Pricing
    # the prefix is the fail-open; this is the RFX-322 treatment of a command
    # we did not read, under its own signature so the reason is legible.
    if budget.exhausted:
        return _make(
            verb="execute",
            reversibility="irreversible",
            blast_radius="systemic",
            externality="internal",
            magnitude_count=1,
            target_kind="command",
            target_ref=None,
            danger_signature="unwalkable_command",
            classification_tier="destructive_systemic",
            command_preview=preview,
            file_path=None,
        )

    if not segments:
        return _classify_bash_execute(command_str, preview)

    # SQL text can only destroy anything if something on this line will hand it
    # to a database.  Decided once for the whole line, because the client and
    # the statement are routinely in different segments (`echo 'DROP TABLE t'
    # | psql`).  See `_sql_reachable`.
    sql_reachable = _sql_reachable(segments)

    results = [_classify_segment(seg, preview, sql_reachable) for seg in segments]

    # A peeled redirection prefix ran a command AND emptied a file.  The peel
    # reports what it emptied; price that as its own candidate so the severity
    # comparison below sees both halves of the line.  `_peeled_truncations`
    # returns None for every segment without a truncating prefix, which is
    # almost all of them.
    results += [t for t in (_peeled_truncations(seg, preview) for seg in segments)
                if t is not None]

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
        tokens, _, _ = _peel_wrappers(_safe_split(seg))
        if tokens and os.path.basename(tokens[0]).lower() in _DB_CLIENTS:
            return True
    return False


def _severity(cls: dict) -> tuple:
    """
    Order two classifications by how much damage they describe.

    RFX-346.  REVERSIBILITY IS COMPARED BEFORE BLAST RADIUS, and the order is
    the whole point of this function rather than a detail of it.

    `_classify_bash` reports `max(results, key=_severity)` over one candidate
    per shell segment plus one per peeled truncation.  While blast radius was
    compared first, a benign candidate with a WIDER radius outranked an
    irreversible destruction with a NARROWER one whenever the two tied on
    tier -- so the line's whole verdict came from the benign candidate:

        > /srv/prod/secrets.env echo hi           delete /irreversible/single
        true && > /srv/prod/secrets.env echo hi   execute/recoverable /scoped

    A no-op `true &&`, supplied by the audited agent, removed the destruction
    from the answer -- not underpriced but ABSENT, taking `target_ref` with it.
    `true` is an unrecognised command, which is priced `scoped`/`moderate` as a
    deliberately conservative floor (RFX-145); the truncation is `single`/
    `moderate` because it names one file.  Same tier, so `scoped` beat
    `single` and the no-op carried the line.

    Why that is the wrong order and not merely an unlucky one: blast radius
    answers HOW MUCH, reversibility answers WHETHER IT COMES BACK.  Between two
    candidates the operator can only be shown one of, the one that cannot be
    undone is the one a human has to see.  A wide recoverable candidate that is
    genuinely more dangerous than a narrow irreversible one differs on TIER,
    which is still compared first and still decides.

    The exposure was exactly the class of weighty path that prices `moderate`:
    a database path scores `broad`/`destructive_broad` and wins on tier before
    the tie-break is reached, while a secret matched only by
    `_SENSITIVE_PATH_RE` scores `single`/`moderate` and ties with any
    unrecognised command.  Measured over a 5633-case grid enumerated from the
    bash redirection grammar: 28 rows, all `/srv/prod/secrets.env`, spread
    evenly across all seven truncating operators, in `&&` and `{ ; }` context.

    NOT fixed here, and deliberately: a line carrying TWO destructions still
    reports only the winner's `target_ref`, so the verdict is right and the
    record can name nothing (80 rows in the same grid).  That is an
    audit-record defect, not a fail-open, and it is filed separately -- see
    RFX-346's CLASS 2.  Merging refs across candidates changes what every
    destruction reports and needs its own evidence.
    """
    return (
        _TIER_RANK.get(cls["classification_tier"], 1),
        _REV_RANK.get(cls["reversibility"], 2),
        _BLAST_RANK.get(cls["blast_radius"], 1),
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
    raw_tokens = _safe_split(segment)
    tokens, unbounded, _ = _peel_wrappers(raw_tokens)
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
    if _git_clean_destroys(segment):
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

    # --- whole-file content destruction: dd of=, truncate, any `> file` -----
    # The redirection scan runs over the WHOLE segment, so it catches the
    # trailing spelling (`cmd > file`) that a command-word test cannot see.
    #
    # RFX-344.  It runs over the RAW tokens, not the peeled ones.  `>& P cmd`
    # destroys P -- `>&word` with a non-numeric operand is bash's both-streams
    # redirection, ground truth off disk with a canary -- but `_peel_wrappers`
    # consumes a leading redirection AND its target before returning, and
    # `_TRUNCATING_OPERATORS` does not list `>&`, so the peel neither reported
    # it as truncated nor left it here to be found.  The path vanished from
    # both halves of the line and `>& /srv/prod/db.sqlite echo hi` priced
    # `read`/`benign` with `target_ref=None` -- the cheapest verdict there is,
    # on an irreversible production destruction.
    #
    # Scanning the raw tokens rather than adding `>&` to `_TRUNCATING_OPERATORS`
    # is deliberate: the peel records what it emptied WITHOUT consulting
    # `_redirect_target_is_weighty`, so `> build.log echo hi` is already priced
    # a delete while `echo hi > build.log` is benign.  Widening that tuple
    # would extend an existing over-call to a new spelling and charge routine
    # output to R5's cumulative delete budget.  Coming through here instead
    # puts the leading spelling behind the SAME weight gate as the trailing
    # one, so the two agree.  The peel is left exactly as RFX-337 wrote it.
    overwrite_paths = _overwrite_targets(cmd0, args, low)
    redirect_paths = _redirect_overwrite_targets(raw_tokens)
    if redirect_paths is not None:
        overwrite_paths = (overwrite_paths or []) + [
            p for p in redirect_paths if p not in (overwrite_paths or [])
        ]
    if overwrite_paths is not None:
        return _classify_path_delete(
            overwrite_paths, recursive=False, unbounded=unbounded,
            signature="content_overwrite", preview=preview,
        )

    # --- a database script hides its statements from the classifier ----------
    if cmd0 in _DB_CLIENTS and _has_script_file(cmd0, args, low):
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
    # RFX-353: `_EMIT_RE`'s git arm is `\bgit\s+push\b`, so a global option
    # between the two words (`git -C /srv/app push --force`) skipped EMIT
    # entirely and fell through to the default EXECUTE arm. The argv test
    # routes it, which is what makes `_git_push_forces` reachable at all.
    if _EMIT_RE.search(segment) or _git_subcommand_args(segment, "push") is not None:
        return _classify_bash_emit(segment, preview)

    # --- READ ----------------------------------------------------------------
    if cmd0 in _READ_COMMANDS:
        return _read_result(preview)
    if cmd0 == "find":
        # find with -delete / -exec rm was handled by _infra_destructive above.
        return _read_result(preview)
    if cmd0 == "git" and low and low[0] in _READ_GIT_SUBCOMMANDS:
        # RFX-358.  `branch` is in that set for `git branch` the LISTING.  The
        # same subcommand carrying a ref-mutating flag is not a read, and this
        # arm used to swallow it because it keys on the subcommand word alone.
        # The forcing spellings were already priced as destructions by
        # `_infra_destructive` above; the rest fall through to the EXECUTE arm
        # below rather than claiming benign.
        if not (low[0] == "branch" and _git_branch_flags(args[1:])[0]):
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

    # git ref destruction (RFX-358).
    #
    # `branch` is a member of `_READ_GIT_SUBCOMMANDS`, and the READ arm in the
    # dispatcher keys on the subcommand WORD ALONE.  So before this branch
    # existed `git branch -D main` returned read / benign / reversible /
    # danger_signature=none -- the cheapest verdict the classifier has -- on a
    # command that destroys a ref.  Measured end to end, not reasoned: through
    # `build_envelope` into core's real pack it decided
    # `allow / reeflex.policy/read_only_internal`.
    #
    # Only the FORCING spellings are priced as destructions here; see
    # `_GIT_BRANCH_MUTATE_FLAGS` for the binary-measured reason that boundary
    # is git's own and not one this file invented.  The non-forcing mutations
    # return None and fall through to the default EXECUTE arm, which is what
    # the dispatcher's READ arm now declines to swallow.
    #
    # `blast_radius` is `scoped`, matching the account-delete branch below: a
    # named branch is one enumerable ref, and SPEC §4.2 lets a name-derived
    # signal RAISE and never lower.  What this does NOT claim is that the
    # commits are unrecoverable -- `git branch -D` prints the sha and the
    # reflog holds it until it expires.  It is priced with the same
    # `irreversible` the caller hardcodes for every member of this function,
    # and that limit is stated in the RFX-358 report rather than implied here.
    if cmd0 == "git" and low[:1] == ["branch"]:
        mutates, forces = _git_branch_flags(args[1:])
        if mutates and forces:
            return ("git_ref_delete", "scoped", _first_positional(args[1:]))
        return None

    # Account / group destruction -- the principal is gone (RFX-166).
    #
    # Before this branch existed the whole family matched nothing here and fell
    # through to the default Bash EXECUTE arm, which prices `recoverable`.
    # reversibility is one of the two axes R2/R3 read to hold a destructive
    # action, so the adapter was telling core that a deleted account could be
    # restored.  The WordPress adapter has priced the same operation
    # `irreversible` since RFX-164; this is the one row where the two reference
    # adapters still genuinely disagreed, and it disagreed in the direction that
    # under-prices.
    #
    # blast_radius stays `scoped`, which is exactly what the default branch
    # already returned.  SPEC §4.2 lets a name-derived signal RAISE and never
    # lower, and the cardinality of `userdel alice` is not what was wrong here.
    #
    # `deluser alice sudo` / `delgroup alice sudo` name a user AND a group: that
    # is a membership removal, undone by granting the membership again.  It is
    # left to the default branch rather than priced as a destruction, because
    # over-blocking an ordinary permission change is its own defect (RFX-249).
    # `userdel` and `groupdel` take no such second positional, so the test is
    # applied only to the two commands that do.
    if cmd0 in _ACCOUNT_DELETE_COMMANDS:
        if cmd0 in ("deluser", "delgroup") and len(_positional_args(args)) >= 2:
            return None
        return ("account_delete", "scoped", _first_positional(args))

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

    Covers `dd ... of=PATH`, `truncate ... PATH`, and the WRITER FAMILY below
    (`tee`, `cp`, `install`, `mv`, `sort -o`, `tar -cf`).  The file survives;
    all of its previous content does not.

    Redirections are NOT handled here -- they are not a property of the
    command word.  See `_redirect_overwrite_targets`.
    """
    if cmd0 == "dd":
        targets = [a.split("=", 1)[1] for a in args if a.lower().startswith("of=")]
        return targets or None
    if cmd0 == "truncate":
        return _positional_args(args, value_flags=("-s", "--size", "-r", "--reference")) or None
    return _writer_overwrite_targets(cmd0, args, low)


# Commands whose ORDINARY use is writing a file, and which destroy whatever was
# at the destination when they do.  `dd` and `truncate` above are not in here
# because they are not ambiguous: nobody writes `truncate -s 0` as build output,
# so those two are priced from the path alone.  These are the opposite -- `cp`,
# `mv` and `tee` are overwhelmingly routine -- which is why every one of them is
# gated on `_redirect_target_is_weighty` below.
_WRITER_COMMANDS = frozenset([
    "tee", "cp", "install", "mv", "sort", "git",
])

# `-t DIR` / `-d`: the destination is a DIRECTORY, so which file inside it gets
# destroyed cannot be resolved without touching the filesystem -- and this
# classifier never does.  Bail rather than name the directory, which would
# report a destruction of the wrong thing.
_WRITER_DIR_DEST_FLAGS = frozenset([
    "-t", "--target-directory", "-d", "--directory",
])


def _short_bundle_has(arg: str, letter: str) -> bool:
    """Is `letter` set in a short-flag bundle like `-a`, `-ai`, `-cf`?"""
    return (arg.startswith("-") and not arg.startswith("--")
            and letter in arg[1:])


def _flag_value(args: list, short: str, long_: str):
    """
    Value of `-o VAL`, `-oVAL`, `--output VAL`, `--output=VAL` -- and of the
    letter inside a SHORT BUNDLE, which is how `tar -cf PATH` is really
    written.  Missing the bundle spelling is not a near-miss: `-cf` never
    equals `-f`, so the value reads as absent and the destruction prices as
    nothing at all.
    """
    letter = short[1:] if short.startswith("-") else short
    for i, a in enumerate(args):
        if a == short or a == long_:
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith(long_ + "="):
            return a.split("=", 1)[1]
        if a.startswith("--") or not a.startswith("-") or not letter:
            continue
        bundle = a[1:]
        pos = bundle.find(letter)
        if pos < 0:
            continue
        rest = bundle[pos + len(letter):]
        # `-cfPATH` carries its value inline; `-cf PATH` takes the next word.
        if rest:
            return rest
        return args[i + 1] if i + 1 < len(args) else None
    return None


def _writer_overwrite_targets(cmd0: str, args: list, low: list):
    """
    The WRITER FAMILY: whole-file destruction carried by the command's own
    semantics, with NO redirection operator anywhere on the line (RFX-343).

    Measured, not reasoned: every shape below was executed against a real
    /bin/bash and scored by per-target survival of five canary lines.  Only the
    shapes that lost ALL FIVE on EVERY asserted operand are priced here.

    NOT INCLUDED, and each exclusion is a measurement rather than an oversight:

    * `sed -i 1d P` -- 4 of 5 canary lines survived.  It is a PARTIAL edit, and
      this function is contracted to whole-file destruction.  Pricing it here
      would make the contract false.
    * `gzip P` -- P is gone, but its bytes are not: `gunzip` returns them.
      `_classify_path_delete` hardcodes reversibility="irreversible", so
      routing gzip through it would state something measurably untrue.
      It needs a "recoverable but disruptive" pricing this function cannot
      express.
    * `python3 -c "open('P','w')"` -- truncates, but it is the INLINE
      INTERPRETER mechanism (`_infra_destructive`), which extracts no path.
      Without a path there is no way to apply the weighty gate below, and
      without the gate every `open('/tmp/out','w')` in a one-liner becomes an
      irreversible broad destruction.
    * `tar -cf P SRC` -- destroys P, and the gate cannot separate it from
      ordinary work: `.tar` is itself a data-container extension, so gating
      `tar` on path weight prices EVERY `tar -cf dist.tar src` in every build
      script as an irreversible destruction.  Measured, not supposed --
      `ord.tar.cf` flipped allow -> require_approval when `tar` was in this
      set.  The contrived `tar -cf <a-database>` shape is not worth that.
    All four are still open; see the RFX-343 report for the evidence.
    """
    if cmd0 not in _WRITER_COMMANDS:
        return None
    if any(a in _WRITER_DIR_DEST_FLAGS or a.split("=", 1)[0] in _WRITER_DIR_DEST_FLAGS
           for a in low):
        return None

    targets: list = []

    if cmd0 == "tee":
        # Every operand of `tee` is truncated -- `tee A B` destroys BOTH.
        # `-a`/`--append` makes the whole line non-destroying; the bundle test
        # catches `-ai` as well as a bare `-a`.
        #
        # THE BUNDLE TEST READS `args`, NOT `low`.  Short flags are
        # case-sensitive, and folding case here fails OPEN: any bundle
        # carrying an uppercase `A` would read as --append and switch the
        # destruction pricing off.  (The same fold read `tar -C` as `tar -c`
        # while tar was still in this set, which is how it was caught.)
        if "--append" in low or any(_short_bundle_has(a, "a") for a in args):
            return None
        targets = _positional_args(args, value_flags=("--output-error",))

    elif cmd0 in ("cp", "install", "mv"):
        # `SRC... DEST` -- the LAST positional is the destination and the only
        # thing destroyed.  Fewer than two positionals is not a valid
        # invocation, so there is nothing to price.
        positional = _positional_args(
            args, value_flags=("-S", "--suffix", "--backup", "-Z", "--context",
                               "-m", "--mode", "-o", "--owner", "-g", "--group"))
        if len(positional) < 2:
            return None
        targets = [positional[-1]]

    elif cmd0 == "sort":
        # Only `-o` writes in place; a bare `sort P` writes to stdout.
        out = _flag_value(args, "-o", "--output")
        targets = [out] if out else []

    elif cmd0 == "git":
        # `git diff|log|show --output=P` destroys P (RFX-358).  Without this
        # the line took the READ arm and priced benign, because that arm reads
        # the subcommand word and never the flags.
        #
        # The subcommand test is adjacency-bound exactly like that READ arm:
        # `git -c x=y diff --output=P` is not matched here and falls to
        # EXECUTE.  That direction is noisier rather than weaker, and it was
        # measured rather than assumed before being left alone.
        if not low[:1] or low[0] not in _OUTPUT_WRITING_GIT_SUBCOMMANDS:
            return None
        out = _git_output_target(args)
        targets = [out] if out else []

    # THE GATE. `tee build.log` and `cp a.txt b.txt` are ordinary developer
    # work, and charging them to R5's cumulative DELETE budget would exhaust
    # it on routine output -- a cost no single-decision probe can see, which
    # is why it is decided here.  A database, a block
    # device, a system path or a secret is not ordinary output.  This is the
    # SAME predicate `_redirect_overwrite_targets` applies, reused deliberately
    # so the redirect family and the writer family cannot drift apart.
    weighty = [t for t in targets
               if t and not _is_null_sink(t) and _redirect_target_is_weighty(t)]
    return weighty or None


# A redirection token that OPENS ITS TARGET FOR TRUNCATION.  Matches an
# optional fd prefix (`2>`, `{fd}>`), then one of the truncating operators,
# then refuses a following `>` so the appending forms never match:
#
#   matches  >   >|   &>   &>|   >&   1>   2>|   {fd}>   and each with the
#            target attached (`>/srv/db`), because `>P` is one token, not two
#   refuses  >>  &>>  2>>            -- append, prior contents survive
#            <   <>   <<   <<<       -- not writes, or no truncation (`<>`
#                                       opens read-write WITHOUT truncating)
#
# `&>|` is listed BEFORE `&>`: the alternation is tried left to right, so with
# `&>` first the longer operator never gets a chance and the `|` is left glued
# to the front of the path -- `&>|/srv/prod/db.sqlite` yielded a target of
# `|/srv/prod/db.sqlite`, a file that does not exist, so the verdict was right
# and the `target_ref` in the audit line named the wrong thing.  Found by
# RFX-344's before/after sweep, not by reading the pattern.
_TRUNCATING_REDIRECT_RE = re.compile(
    r"^(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[0-9]*)(>\||&>\||&>|>&|>)(?!>)(.*)$"
)

# Writing to these destroys nothing, whatever the redirection says.
_NULL_SINKS = frozenset([
    "/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty",
])


def _is_null_sink(path: str) -> bool:
    return path in _NULL_SINKS or path.startswith("/dev/fd/")


def _redirect_target_is_weighty(path: str) -> bool:
    """
    Is this a file whose truncation is a DESTRUCTION rather than an output?

    `pytest -q > out.log` truncates out.log, and calling that a delete would
    charge routine build output to R5's cumulative delete budget for no gain --
    a cost measured in NO probe that starts from an empty ledger, which is why
    it has to be decided here and not by looking at a single decision.  So an
    ordinary file left of a `>` stays with the command that wrote it, exactly
    as `TestTruncatingOverwrite` has required since RFX-144.

    A database, a block device, a system path or a secret is not an ordinary
    file.  Those are the same predicates `_radius_for_paths` already uses to
    tell `rm /srv/prod/db.sqlite` from `rm /tmp/x`, reused here so the two
    paths cannot drift apart.
    """
    return (_DATA_CONTAINER_PATH_RE.search(path) is not None
            or _BLOCK_DEVICE_RE.match(path) is not None
            or _is_systemic_path(path)
            or _SENSITIVE_PATH_RE.search(path) is not None)


def _redirect_overwrite_targets(tokens: list):
    """
    Return every WEIGHTY path a TRUNCATING redirection opens, or None.

    A redirection is not a command, and it is not required to sit in any
    particular position: `> P cmd`, `cmd > P` and `cmd > P args` all truncate
    P before `cmd` ever runs.  Reading the target off the command word alone
    (which is what this classifier did until RFX-340) sees only the spelling
    that leads with the operator -- the one nobody writes.

    Every target on the line is returned, not just the last one.  In
    `cmd > A > B` only B receives the output, but BOTH files are opened, and
    opening for truncation is what destroys the prior contents.

    `2>&1` and `>&2` are file-descriptor duplications, not files: the target
    is all digits and there is no path to price.
    """
    targets = []
    i = 0
    while i < len(tokens):
        m = _TRUNCATING_REDIRECT_RE.match(tokens[i])
        if m is None:
            i += 1
            continue
        op, attached = m.group(1), m.group(2)
        if attached:
            target = attached
            i += 1
        else:
            # `> P` -- the target is the next token, if there is one.
            if i + 1 >= len(tokens):
                break
            target = tokens[i + 1]
            i += 2
        # `2>&1`, `>&2`: duplicating a descriptor, not opening a file.
        # `>&-`, `2>&-`: CLOSING a descriptor -- also not a file.  `-` is the
        # third and last fd operand bash accepts, so with it the fd forms are
        # covered completely; without it the shape was reaching the weight
        # test and only staying benign because `-` happens not to look
        # weighty, which is an accident rather than a decision.  This changes
        # no measured row (RFX-344).
        if op == ">&" and (target.isdigit() or target == "-"):
            continue
        if not target or _is_null_sink(target):
            continue
        if not _redirect_target_is_weighty(target):
            continue
        if target not in targets:
            targets.append(target)
    return targets or None


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
    if _git_clean_destroys(command):
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
    is_recursive = _rm_is_recursive(command)
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

    # RFX-144 (ported from PR #98) -- KIND, raise-only, and deliberately placed
    # here rather than in `_classify_path_delete` so that `rm /srv/prod/db.sqlite`
    # and `> /srv/prod/db.sqlite` get the SAME reading: this function is the one
    # rule for path sets and is shared by the rm path and the overwrite path.
    # It cannot lower anything -- both branches only ever return broad/systemic,
    # and they sit below `is_systemic` so they can never demote it.
    if any(_BLOCK_DEVICE_RE.match(p) for p in path_args):
        return "systemic", "overwrite_container", "destructive_systemic"
    if any(_DATA_CONTAINER_PATH_RE.search(p) for p in path_args):
        return "broad", "overwrite_container", "destructive_broad"

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
    if _git_push_forces(command):
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


def _oversize_path(verb: str, file_path_str: str) -> dict:
    """
    RFX-338.  The SPEC §2 safe-conservative reading of a `file_path` we refused
    to read, for the Write and Edit families alike.

    ONE function for both call sites on purpose: the failure this closes was two
    copies of the same uncapped `_SENSITIVE_PATH_RE.search` line, and two copies
    of the cap would be free to drift back apart the same way.

    The verb is the caller's, because we DO know it -- the tool name told us, and
    only the target is unreadable.  Everything the path would have told us is
    pinned at the worst case we cannot rule out: we could not run `os.path.exists`
    to see whether this overwrites (it answers False for an overlong path, which
    is precisely the under-classification), and we could not test it for a
    sensitive location.

    `file_path` and `target_ref` are dropped and only a 200-char preview is kept.
    That is not tidiness: `envelope.py` puts `file_path` on the wire and into the
    audit line verbatim, so passing the megabyte through would trade a hung
    classifier for a megabyte POST to core and a megabyte audit record.  hook.py's
    oversize refusal states "the envelope is small" as its premise; this keeps it
    true on the path branch too.
    """
    return _make(
        verb=verb,
        reversibility="irreversible",
        blast_radius="systemic",
        externality="internal",
        magnitude_count=1,
        target_kind="file",
        target_ref=None,
        danger_signature="oversize_path",
        classification_tier="destructive_systemic",
        command_preview=file_path_str[:200],
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

    # RFX-338.  BEFORE `os.path.exists` and BEFORE `_SENSITIVE_PATH_RE` -- the
    # regex is the uninterruptible one, and the stat call cannot answer for a
    # path this long either.  See MAX_FILE_PATH_CHARS for why the watchdog is
    # not an alternative here.
    if len(file_path_str) > MAX_FILE_PATH_CHARS:
        return _oversize_path("create", file_path_str)

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
    # RFX-342.  `NotebookEdit` names its path `notebook_path`, not `file_path`,
    # and its schema is `additionalProperties: false` -- so a real caller CANNOT
    # send `file_path` on that route and this arm read `""` for 100% of real
    # notebook calls, not for an edge.  target_ref then went to core as null:
    # the audit line RFX-206 added so that "a delete was held in production"
    # is answerable did not name the notebook, and R6/R7 -- which match on the
    # ref -- had nothing to match.
    #
    # The tree's only NotebookEdit test could not see this, in either
    # direction, because it fed `file_path` -- the key the CODE reads and a
    # shape the tool does not permit.  A test that supplies the key the
    # implementation reads cannot detect a key-name mismatch.
    file_path = (tool_input.get("file_path")
                 or tool_input.get("notebook_path") or "")
    file_path_str = str(file_path) if file_path else ""

    # RFX-338.  Same cap, same reason, before the same pattern.  This arm serves
    # Edit, MultiEdit AND NotebookEdit, so it is three of the four reachable
    # routes; Write is the fourth.
    if len(file_path_str) > MAX_FILE_PATH_CHARS:
        return _oversize_path("update", file_path_str)

    # RFX-342, second leg.  The Edit family is priced `recoverable` because the
    # inverse of the change is in the call: `Edit`/`MultiEdit` carry
    # `old_string`, so the prior text can be put back from the envelope alone.
    # `NotebookEdit` with `edit_mode="delete"` carries the removed cell's source
    # in NO form -- not in `new_source`, which is the replacement and is absent
    # for a delete -- so that stated reason does not hold for it and the axis is
    # `irreversible`.  Scoped deliberately to delete-mode: `replace` hands back
    # a working-tree notebook whose prior source is in git, which is the same
    # bargain every `Edit` makes, and widening the axis to the whole family is a
    # policy change with a far larger blast radius (flagged on RFX-342, not
    # taken here).
    #
    # This is the leg that makes R6 reachable.  The ref alone does not: measured
    # on the shipped tree, a NotebookEdit spelled with `file_path` carries a
    # correct, protected ref and STILL scores allow/default_allow, because R6
    # reads `irreversible` first.  So a fix that stopped at the key name would
    # have corrected the record and left the hold unreachable.
    mode = str(tool_input.get("edit_mode") or "").strip().lower()
    reversibility = "irreversible" if mode == "delete" else "recoverable"

    # Sensitive path -> scoped blast_radius as a flag
    is_sensitive = bool(file_path_str and _SENSITIVE_PATH_RE.search(file_path_str))
    blast_radius = "scoped" if is_sensitive else "single"
    sig = "sensitive_write" if is_sensitive else "none"
    tier = "moderate"

    return _make(
        verb="update",
        reversibility=reversibility,
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


def _classify_unknown(tool_name: str, tool_input: dict) -> dict:
    """
    Classification for any unrecognized tool -- in practice, every `mcp__*` one.

    Emits a conservative FLOOR and escalates it, monotonically, from whatever
    the name and the arguments actually say.  See the "Unknown tool" section of
    the module docstring for why the floor is `broad`, why escalation only ever
    goes one way, and what redaction this owes the audit log.
    """
    tokens = _unknown_name_tokens(tool_name)
    args = tool_input if isinstance(tool_input, dict) else {}

    # --- verb + externality: the floor, escalated by the strongest signal ----
    # RFX-214: the externality floor is `outbound`, not `internal`.  `internal`
    # is the one value R5's external_sends budget does not charge, and this
    # function is exactly the branch that runs when we could not identify the
    # tool -- so declaring `internal` here told the operator's send budget to
    # ignore precisely the traffic it cannot vouch for.  The money and emit
    # branches below now only confirm this value; they no longer have to raise
    # it, and they are kept because they still set the VERB.
    verb = "execute"
    externality = "outbound"
    money = _unknown_money(args)

    if money is not None or tokens & _UNKNOWN_MONEY_TOKENS:
        verb, externality = "transact", "outbound"
    elif tokens & _UNKNOWN_DESTRUCTIVE_TOKENS:
        # `delete` is what puts this call into cumulative.count_by_verb.delete,
        # which is the only place R5's deletions budget looks.
        verb = "delete"
    elif tokens & _UNKNOWN_EMIT_TOKENS:
        verb, externality = "emit", "outbound"

    # --- axes we cannot measure stay at their most-guarded honest value ------
    # `broad` is a hold (R2), not a terminal deny (R3) -- SPEC §4.0.
    blast_radius = "broad"
    reversibility = "irreversible"

    params_extra = {}
    if money is not None:
        amount, currency = money
        if amount is None:
            # A money-named tool that declares no amount.  We cannot invent the
            # number, and we must not let the silence read as zero: that is the
            # RFX-133/RFX-180 evasion.  Say so, so a policy can act on it.
            params_extra["amount_declared"] = False
        else:
            params_extra["amount"] = amount
            params_extra["amount_declared"] = True
        if currency:
            params_extra["currency"] = currency

    return _make(
        verb=verb,
        reversibility=reversibility,
        blast_radius=blast_radius,
        externality=externality,
        magnitude_count=_unknown_magnitude(args),
        target_kind="resource",
        target_ref=_unknown_target_ref(args),
        danger_signature="unknown_tool",
        # Tier follows blast_radius, per the documented mapping above.  For an
        # unknown tool it states the worst case we could not rule out, not a
        # measurement -- the four-string vocabulary has no word for "unpriced".
        classification_tier="destructive_broad",
        command_preview=None,
        file_path=None,
        params_extra=params_extra or None,
    )


def _unknown_name_tokens(tool_name: str) -> frozenset:
    """
    Lowercase whole-word tokens of a tool name, splitting on punctuation AND
    camelCase.  EVERY token is returned, not the first: reading only the
    leading token is how `search_and_replace` gets priced as a search (RFX-175).
    """
    if not tool_name:
        return frozenset()
    parts = _UNKNOWN_NAME_SPLIT_RE.split(str(tool_name))
    return frozenset(p.lower() for p in parts if p)


def _unknown_money(args: dict):
    """
    Return (amount, currency) if this call looks like it moves money, else None.

    `amount` is None when the call is money-shaped by currency alone -- the
    caller named a currency but no number.  Values are read only to ESCALATE:
    an agent that understates the amount moves less money, so understating is
    self-defeating rather than an evasion.
    """
    amount = None
    currency = None

    for key, value in args.items():
        if not isinstance(key, str) or _UNKNOWN_SECRET_KEY_RE.search(key):
            continue
        lowered = key.lower()
        if amount is None and lowered in _UNKNOWN_AMOUNT_KEYS:
            amount = _unknown_number(value)
        elif currency is None and lowered in _UNKNOWN_CURRENCY_KEYS:
            if isinstance(value, str) and 2 <= len(value.strip()) <= 8:
                currency = value.strip().upper()

    if amount is None and currency is None:
        return None
    return (amount, currency)


def _unknown_number(value):
    """Coerce a scalar to a non-negative float, or None. Booleans are not numbers."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n != n or n in (float("inf"), float("-inf")) or n < 0:
        return None
    return n


def _unknown_magnitude(args: dict) -> int:
    """
    Largest bounded set the arguments name, floored at 1.

    Feeds R5's objects_touched budget, which weighs every action -- a call that
    always reports 1 makes a session of 500 deletes look like a session of 500
    single-row operations.  Escalation only: we take the MAX of what we find and
    never go below the floor of 1.
    """
    largest = 1
    for key, value in args.items():
        if not isinstance(key, str) or _UNKNOWN_SECRET_KEY_RE.search(key):
            continue
        if isinstance(value, (list, tuple, set)):
            largest = max(largest, len(value))
        elif key.lower().replace("-", "_") in _UNKNOWN_COUNT_KEYS:
            n = _unknown_number(value)
            if n is not None and n < 1e9:
                largest = max(largest, int(n))
    return largest


def _unknown_target_ref(args: dict):
    """
    A short, redacted `k=v` digest of the identifying arguments.

    This is the field a human reads when answering the hold.  `resource: null`
    is not something anyone can approve or refuse on.

    Redaction, because this string is transmitted to core and written to the
    audit log: scalars only (never a nested structure, which is where bulk
    payloads and credentials hide), no key that looks like credential material,
    every value truncated, the whole thing capped.
    """
    fields = []
    for key in _UNKNOWN_REF_KEYS:
        if len(fields) >= _UNKNOWN_REF_MAX_FIELDS:
            break
        if key not in args or _UNKNOWN_SECRET_KEY_RE.search(key):
            continue
        value = args[key]
        if isinstance(value, (list, tuple)):
            # A list is a count, not an identifier -- say how many, not what.
            rendered = f"[{len(value)} items]"
        elif isinstance(value, (str, int, float, bool)):
            rendered = str(value)
        else:
            continue
        rendered = rendered.strip()
        if not rendered:
            continue
        if len(rendered) > _UNKNOWN_REF_MAX_VALUE:
            rendered = rendered[:_UNKNOWN_REF_MAX_VALUE] + "..."
        fields.append(f"{key}={rendered}")

    if not fields:
        return None
    return " ".join(fields)[:_UNKNOWN_REF_MAX_TOTAL]


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
    params_extra: Optional[dict] = None,
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
        # Structured, already-redacted additions to the envelope's `params`
        # (SPEC §2: "adapter-specific, structured, typed").  Today this carries
        # amount/currency so R5's money budget can price the action; it is None
        # for every classifier that has nothing to add.
        "params_extra": params_extra,
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
            # `>|` is the clobber-override redirection, not a pipe.  Same
            # exception the `&` branch above already makes for `2>&1` and
            # `&>log`, for the same reason: splitting here cuts a redirection
            # in half and the truncation it performs is never seen.  Measured:
            # `>| P cmd` destroys P's contents in a real bash, and before this
            # the line came apart into `>` and `P cmd`.
            if ch == "|" and "".join(buf).rstrip()[-1:] == ">":
                buf.append(ch)
                i += 1
                continue
            parts.append("".join(buf))
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    parts.append("".join(buf))
    return [p for p in (x.strip() for x in parts) if p]


def _paren_prefix_balance(text: str) -> list:
    """
    Net unquoted paren depth of every PREFIX of `text`: the returned list `p`
    has `len(text) + 1` entries and `p[i]` is the depth of `text[:i]`, ignoring
    any paren inside quotes or behind a backslash.

    This is the single scan `_paren_balance` and `_peel_group` both read, so
    the quoting rules cannot drift between them.

    RFX-335: `_peel_group` used to call the whole-string `_paren_balance` once
    per stripped character, which is O(n^2) on a run of unmatched closers.
    Measured on `7f19d374`: 8000 closers took 6.19s, and a full
    `MAX_BASH_COMMAND_CHARS` run took 417.45s -- against a 30s hook timeout.
    Because the depth of `text[:i]` does not depend on anything after `i`, one
    pass answers every question the peel loop asks: the balance of a window
    `text[lo:hi]` that starts outside quotes is exactly `p[hi] - p[lo]`.
    """
    n = len(text)
    prefix = [0] * (n + 1)
    depth = 0
    quote = None
    i = 0

    while i < n:
        ch = text[i]

        if quote is not None:
            if ch == "\\" and quote == '"' and i + 1 < n:
                prefix[i + 1] = depth
                prefix[i + 2] = depth
                i += 2
                continue
            if ch == quote:
                quote = None
            prefix[i + 1] = depth
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
        elif ch == "\\" and i + 1 < n:
            prefix[i + 1] = depth
            prefix[i + 2] = depth
            i += 2
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1

        prefix[i + 1] = depth
        i += 1

    return prefix


def _paren_balance(text: str) -> int:
    """
    Net unquoted paren depth of `text` -- opens minus closes -- ignoring any
    paren inside quotes or behind a backslash.

    This is what tells a subshell's own closing `)` from the `)` that
    terminates a `$(...)`.  `_split_on_operators` cuts at operators and knows
    nothing about groups, so the close of `(cd /tmp && ls)` is left stranded on
    the last segment (`ls)`, balance -1) while the close of
    `echo $(rm -rf V)` sits in a segment that is balanced (0).  Only the
    stranded one is taken.

    Stated at its measured strength, because the obvious stronger claim is
    wrong: stripping the balanced one as well does NOT currently undo RFX-301.
    `_balanced_paren` returns the remainder on an unterminated substitution, so
    `echo $(rm -rf V` still yields the body, and the whole guard suite stays
    green with this check removed (break W3, round dev-1--153).  It is kept
    because `_peel_group` has no business editing text it does not own, and
    because that degradation in `_balanced_paren` is a property nothing else
    promises to preserve -- not because a measurement shows it changing a
    verdict today.
    """
    return _paren_prefix_balance(text)[-1]


def _peel_group(segment: str) -> str:
    """
    Strip the parentheses of a subshell group, so the command word of the
    segment is the command and not the literal `(rm`.

    RFX-329: one pair of parentheses was the shortest string that escaped the
    classifier entirely.  `(rm -rf /srv/prod/data)` survives
    `_split_on_operators` as a single segment, and `shlex` then tokenises it as
    `['(rm', '-rf', 'V)']`.  `(rm` matches no branch of `_infra_destructive` or
    `_classify_bash_delete`, so the line fell through to the default Bash
    EXECUTE arm and was priced execute/recoverable/scoped -- ALLOW -- while
    bash really deletes the directory.  The target ref was mangled to `V))`
    too, so R6 could not rescue it either.  The brace group `{ rm -rf V; }`,
    which has the same semantics, was priced delete/irreversible/broad, so this
    was specifically the parenthesis form.

    Peeled here rather than in `_split_on_operators` because the splitter's
    output is also what `_substitution_bodies` reads: cutting at `(` would
    break `$(...)` apart and undo RFX-301.

    `((...))` is deliberately NOT peeled.  That is arithmetic evaluation, not a
    subshell -- bash reads `rm` there as a variable name and deletes nothing --
    so pricing it as the inner command would be a false positive.  The
    false-positive floor matters as much as the catch here: a subshell is an
    ordinary thing to write, and `(cd /tmp && ls)` must stay allowed.  It does:
    peeling makes its segments `cd /tmp` and `ls`, both reads.
    """
    text = segment.strip()

    # Nothing to peel, and it keeps the scan below off the hot path for the
    # overwhelming majority of commands, which contain no parenthesis at all.
    if "(" not in text and ")" not in text:
        return text

    # RFX-335: peel by moving a window over ONE prefix-balance scan, instead of
    # re-slicing the string and re-balancing it per stripped character.  The
    # loop structure below is deliberately the same shape as the O(n^2) version
    # it replaces -- `prefix[hi] - prefix[lo]` is what `_paren_balance` of the
    # current text used to return, and `lo`/`hi` are what `.strip()` used to do.
    prefix = _paren_prefix_balance(text)
    lo, hi = 0, len(text)

    while True:
        changed = False

        # `lo` only ever steps over an unquoted `(` or whitespace, so it stays
        # outside quotes -- which is what makes `prefix[hi] - prefix[lo]` the
        # balance of the window rather than of some quoted fragment.
        if hi - lo >= 1 and text[lo] == "(" and not (
            hi - lo >= 2 and text[lo + 1] == "("
        ):
            lo += 1
            while lo < hi and text[lo].isspace():
                lo += 1
            changed = True

        # Only a close with nothing to match it in this segment.
        while hi > lo and text[hi - 1] == ")" and prefix[hi] - prefix[lo] < 0:
            hi -= 1
            while hi > lo and text[hi - 1].isspace():
                hi -= 1
            changed = True

        if not changed:
            break

    return text[lo:hi]


def _shell_c_payload(tokens: list):
    """
    Return the program text of a `sh -c '<inner>'` invocation, else None.

    `eval '<inner>'` is the same construct with different syntax -- a visible
    program string handed to the shell to run -- so it is expanded the same
    way.  Measured before this: `eval "rm -rf /srv/prod/data"` was priced as
    an unrecognised execute and ALLOWED.  Note this covers only the case where
    the program text is VISIBLE; `eval "$CMD"` and `$(echo rm) -rf ...` are
    not, and this classifier does not price them -- the destruction is not in
    the string it is given (see the `gap-` family in conformance.py).
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
            # RFX-144 (dev-1 round 054).  This returned `tokens[i + 1]` and so
            # dropped everything after the first token of the payload.  shlex
            # concatenates adjacent quoted runs, so a nested construct like
            #   sh -c 'sh -c "rm -rf /srv/prod/data"'
            # split into segments whose payload token no longer carried the
            # `rm` -- the line resolved to a bare `sh` and was priced as an
            # unrecognised execute.  PR #98 has the identical bug and caught
            # this case only as a side effect of its fail-closed default, so
            # neither PR actually PARSED this input.  Joining the remainder is
            # what recovers the payload.
            return " ".join(tokens[i + 1:])
    return None


# ---------------------------------------------------------------------------
# What one substitution walk may spend  (RFX-328 / RFX-336 / RFX-337)
# ---------------------------------------------------------------------------
#
# `_shell_segments` used to guard its recursion with `depth < 3`, and `sh -c`
# unwrapping spent the SAME counter, so wrappers and nestings were fungible.
# Five destructive lines got past it, every one of which a real bash really
# runs -- ground truth read off the filesystem, not argued:
#
#     echo $(echo $(echo $(echo $(rm -rf /var/lib/pgsql))))   -> priced benign
#     echo `echo \`rm -rf /var/lib/pgsql\``                   -> priced benign
#     sh -c 'sh -c "echo \$(rm -rf /var/lib/pgsql)"'          -> priced benign
#
# WHY THIS IS A BUDGET AND NOT A BIGGER NUMBER.  RFX-328 asked for a fix that
# says what it bounds and measures the cost at the bound; raising the constant
# fails that test three ways, all measured on main `ba3ccb4`:
#
#   * Depth is the CHEAP axis, and it was the only one bounded.  Walking
#     nesting 3 -> 256 costs 8 ms and yields the same 4 segments.
#   * Breadth is the EXPENSIVE axis, and it was not bounded AT ALL.  One
#     segment holding 800 substitutions produced 801 segments unchecked, and
#     fan-out x depth reached 585 segments / 223 ms from one 58 KB line.
#   * Removing the ceiling does not merely cost cycles.  At nesting depth
#     1000 the walk raises RecursionError, and RFX-323 measured Claude Code's
#     PreToolUse runner FAILING OPEN when the hook crashes -- so the naive fix
#     trades a depth-4 escape for a depth-1000 one.
#
# So the walk is bounded by the work it does rather than by how deep it goes,
# and the bounds are sized against what real commands actually need: over the
# 211 Bash commands in `reeflex-spec/conformance/claude-adapter-bash.json` and
# this package's own suite, the worst case is 4 segments, 87 characters walked
# and nesting depth 2.
#
# AND THE BOUND NO LONGER DECIDES THE OUTCOME, which is the point.  A walk
# that stops early has not READ the command, so the command is not priced from
# the part that was read: `_classify_bash` returns SPEC §2's safe-conservative
# axes under `unwalkable_command`, exactly as RFX-322 already does for a
# command over the size cap.  Writing `$(` 65 times now buys a refusal rather
# than an allow, so no value of these constants is an escape hatch.
# WHICH BOUND ACTUALLY FIRES, measured rather than assumed -- worth stating,
# because a bound nobody can reach is not a bound and should not be described
# as one:
#   * CHARS is the working bound.  It is what stops fan-out x depth (8 wide by
#     4 deep, 58 KB) and deep nesting (8000 levels, 64 KB).
#   * DEPTH stops nesting that is deep but cheap in characters (200 levels,
#     1.6 KB) -- the shape that would otherwise reach CPython's stack.
#   * SEGMENTS is a backstop only: under the 64 KiB command cap nothing
#     reaches it, and no input found in testing ever did.
#
# The segment count is set ABOVE anything the command cap can produce rather
# than tuned down.  At 512 it WAS reached -- by `echo hello && ...` repeated to
# 64 KiB, a completely benign line, which it refused.  That is the gate an
# operator switches off (the argument `_substitution_bodies` already makes
# about `grep`).  The shortest chainable command is ~5 chars with its `&&`, so
# 64 KiB cannot hold more than ~13 100 of them.
#
# COST AT THE BOUND, since RFX-328 asked for it: the worst case reachable
# under the command cap is 359 ms (fan-out 8 x depth 4).  The 64 KiB cap
# itself already costs ~0.3 s by the note above, and the PreToolUse deadline
# is 30 s, so the walk is not what spends it.
_WALK_MAX_SEGMENTS = 16384    # backstop; above the ~13 100 a 64 KiB line chains
_WALK_MAX_CHARS = 262144      # 4x the 64 KiB command cap; ~3000x the worst (87)
_WALK_MAX_DEPTH = 64          # 32x the worst real nesting (2), and ~15x clear
                              # of CPython's default 1000-frame stack limit


class _WalkBudget:
    """
    What one `_shell_segments` walk may spend, and whether it ran out.

    `exhausted` is the load-bearing field.  A caller that cannot tell
    "read the whole line, found nothing destructive" from "stopped looking"
    will report the first when it means the second, which is the fail-open
    this class exists to remove.
    """

    __slots__ = ("segments", "chars", "exhausted")

    def __init__(self) -> None:
        self.segments = _WALK_MAX_SEGMENTS
        self.chars = _WALK_MAX_CHARS
        self.exhausted = False

    def charge(self, segment: str) -> bool:
        """Charge one emitted segment.  False once the walk must stop."""
        self.segments -= 1
        self.chars -= len(segment)
        if self.segments < 0 or self.chars < 0:
            self.exhausted = True
            return False
        return True


def _shell_segments(command: str, depth: int = 0,
                    budget: "Optional[_WalkBudget]" = None) -> list:
    """
    Split a shell command line into the individual commands it will run,
    expanding `sh -c '<inner>'` in place so a wrapped command is classified by
    what it actually runs and not by the wrapper.

    The walk continues to whatever depth the line reaches until `budget` runs
    out; see the comment above `_WalkBudget` for what is bounded and why.
    Callers that need to know whether the whole line was read must pass a
    `budget` in and check `budget.exhausted` -- the returned list cannot say
    so on its own.

    RFX-301: the body of a command substitution is one of those commands, and
    it was not being read.  `echo $(rm -rf /var/lib/pgsql)` was priced
    read/reversible/single/benign -- ALLOW -- while bash really deletes the
    directory (measured, not reasoned: dev-2 round 056 ran all five forms
    against synthetic victim directories; five DESTROYED, the read-only control
    SURVIVED).  The classifier was not failing to SEE the substitution; it was
    reading only the OUTER command word, which is `echo`.

    The bodies are ADDED to the segment list, never substituted for it.  That
    matters: `_classify_bash` reports `max(..., key=_severity)`, so appending
    can only raise a verdict, never lower one.  The one other line-level
    consumer, `_sql_reachable`, is the same direction -- a database client
    inside a substitution re-arms the SQL patterns rather than disarming them.
    """
    if budget is None:
        budget = _WalkBudget()

    if not command.strip():
        return []

    out: list = []
    for segment in _split_on_operators(command):
        # RFX-329.  Before anything reads the command word, take off the
        # parentheses of a subshell group -- they are shell grammar, not part
        # of the command.  Done here so every consumer of a segment sees it:
        # `_classify_segment`, and `_sql_reachable`, which could not see the
        # client in `(psql -c '...')` either.
        segment = _peel_group(segment)
        if not segment:
            continue

        # Charged BEFORE the segment is read, so the budget bounds the work
        # this walk is about to do rather than the work it has already done.
        if not budget.charge(segment):
            return out

        peeled, _, _ = _peel_wrappers(_safe_split(segment))
        inner = _shell_c_payload(peeled)
        if inner and _c_payload_quote(segment) != "'":
            # RFX-337.  The outer shell has consumed these backslashes before
            # the inner shell ever sees the payload; single quotes are the one
            # spelling where it has not.
            inner = _unescape(inner, "$`\"\\")
        bodies = _substitution_bodies(segment)

        if depth >= _WALK_MAX_DEPTH and (inner or bodies):
            # Stopping here would leave a destructive body unread and the line
            # priced from the `echo` wrapping it.  Say the line was not read
            # instead: `_classify_bash` turns `exhausted` into a refusal.
            budget.exhausted = True
            out.append(segment)
            continue

        if inner:
            expanded = _shell_segments(inner, depth + 1, budget)
            out.extend(expanded or [segment])
        else:
            out.append(segment)

        for body in bodies:
            out.extend(_shell_segments(body, depth + 1, budget))
    return out


def _substitution_bodies(text: str) -> list:
    """
    Return the command texts a shell would RUN to expand this segment:
    `$(...)`, `` `...` ``, `<(...)` and `>(...)`.

    Quoting is the whole job here, so it is spelled out rather than regexed:

      * single quotes suppress every expansion, so `echo '$(rm -rf /)'` yields
        nothing -- pricing that as a delete would be a gate that refuses a
        grep, and a gate people switch off protects nobody (RFX-145's
        argument, applied to this fix).
      * double quotes suppress NOTHING for `$(...)` and backticks, so
        `echo "result: $(rm -rf /var/lib/pgsql)"` yields the delete.
      * process substitution is not expanded inside double quotes, so `<(` and
        `>(` are read only outside them.
      * `$((...))` is arithmetic, not a command, and is skipped.  `${VAR}` is
        parameter expansion and is never matched -- only `$(` is.
      * a backslash escape outside single quotes hides the next character, so
        `\\$(rm -rf /)` yields nothing.

    An UNTERMINATED substitution returns the rest of the text as the body.
    That is not defensive coding, it is the common case: `_split_on_operators`
    runs first and cuts at `&&`/`;`/`|` wherever they appear, including inside
    a substitution, so `echo $(cd /srv/prod && rm -rf data)` arrives here as
    `echo $(cd /srv/prod` -- and the tail that carries the `rm` arrives as its
    own segment anyway.  Taking the remainder keeps the reading conservative.

    WHAT THIS DOES NOT READ, stated because a parser that handles five forms
    and calls the family closed is the claim the canon forbids:
      * `$(echo rm) -rf /srv/prod/data`, where the substitution IS the command
        word -- the body `echo rm` is a read, and the word it produces is not
        in the text.  That is the corpus case `gap-command-substitution`
        (RFX-158) and this change does not close it.
      * `$CMD` / `${CMD}` variable indirection (`gap-variable-indirection`).
      * anything whose destructive text is produced at runtime rather than
        written on the line -- `eval "$(curl ...)"` reads the `curl`, not what
        it returns.
    """
    bodies: list = []
    i, n = 0, len(text)
    quote = None

    while i < n:
        ch = text[i]

        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue

        if ch == "\\" and i + 1 < n:
            i += 2
            continue

        if ch == "'" and quote is None:
            quote = "'"
            i += 1
            continue

        if ch == '"':
            quote = None if quote == '"' else '"'
            i += 1
            continue

        if text.startswith("$((", i):
            # Arithmetic expansion: no command runs.  Skip to the closing `))`
            # if it is there, and past the `$((` if it is not.
            close = text.find("))", i + 3)
            i = close + 2 if close != -1 else i + 3
            continue

        if text.startswith("$(", i):
            body, i = _balanced_paren(text, i + 2)
            bodies.append(body)
            continue

        if ch == "`":
            body, i = _to_backtick(text, i + 1)
            # RFX-336.  By the time the shell RUNS this body it has already
            # consumed the backslashes inside it, so honouring them here left
            # a nested backtick unread and the line priced as the `echo`
            # around it.  A `$( )` body is deliberately NOT unescaped -- see
            # `_unescape` for the measurement that separates the two.
            bodies.append(_unescape(body, "$`\\"))
            continue

        if quote is None and (text.startswith("<(", i) or text.startswith(">(", i)):
            body, i = _balanced_paren(text, i + 2)
            bodies.append(body)
            continue

        i += 1

    return [b for b in (x.strip() for x in bodies) if b]


def _unescape(text: str, specials: str) -> str:
    """
    Remove the backslashes a shell consumes before `specials`, so a nested
    command is read the way the shell will run it rather than the way it was
    typed one level up.

    WHICH CONSTRUCTS NEED THIS IS MEASURED, NOT TAKEN FROM THE STANDARD -- a
    real bash against synthetic victim directories, canary read off disk
    afterwards (RFX-336/RFX-337, dev-2 round 071):

        echo `echo \\`rm -rf V\\``      DESTROYED   backtick body: unescape
        echo `echo \\$(rm -rf V)`       DESTROYED   backtick body: unescape
        echo $(echo \\`rm -rf V\\`)     SURVIVED    `$( )` body:   do NOT
        echo $(echo \\$(rm -rf V))      SURVIVED    `$( )` body:   do NOT
        sh -c "echo \\$(rm -rf V)"      DESTROYED   dquoted payload: unescape
        sh -c 'echo \\$(rm -rf V)'      SURVIVED    squoted payload: do NOT

    That asymmetry is the entire reason this is applied at two named call
    sites instead of as a pass over the whole segment: unescaping a `$( )`
    body would price `echo $(echo \\$(rm -rf V))` as a delete, and a gate that
    refuses a line the shell does not run is a gate people switch off.
    """
    if "\\" not in text:
        return text
    out: list = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "\\" and i + 1 < n and text[i + 1] in specials:
            out.append(text[i + 1])
            i += 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _c_payload_quote(segment: str):
    """
    The quote character the `-c` payload of `segment` was written in -- `'`,
    `"`, or None when it was unquoted.

    `shlex` removes the quotes but not the backslashes inside them, and the
    two spellings do not mean the same thing to a shell (measured above), so
    the payload alone cannot say whether its backslashes are still live.
    Without this, `sh -c 'sh -c "echo \\$(rm -rf V)"'` -- which really deletes
    -- was priced benign, because after one unwrap the classifier still saw an
    escaped `$` and the shell did not.

    Scans with quote state so a `-c` inside an argument is not mistaken for
    the flag.  Consulted only when `_shell_c_payload` has already established
    that this segment IS a `sh -c`.
    """
    i, n, quote = 0, len(segment), None
    while i < n:
        ch = segment[i]
        if quote is not None:
            if ch == "\\" and quote == '"' and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        if ch == "-" and (i == 0 or segment[i - 1].isspace()):
            j = i + 1
            while j < n and segment[j].isalpha():
                j += 1
            if segment[i + 1:j] in ("c", "lc", "ic") and j < n and segment[j].isspace():
                while j < n and segment[j].isspace():
                    j += 1
                return segment[j] if j < n and segment[j] in "'\"" else None
            i = j
            continue
        i += 1
    return None


def _balanced_paren(text: str, start: int):
    """
    Read from `start` to the `)` that closes the substitution opened before it,
    counting nested parens and ignoring any that sit inside quotes.

    Returns (body, index_after_the_close).  On an unterminated substitution the
    body is the remainder -- see `_substitution_bodies`.
    """
    depth = 1
    quote = None
    i, n = start, len(text)

    while i < n:
        ch = text[i]

        if quote is not None:
            if ch == "\\" and quote == '"' and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
        elif ch == "\\" and i + 1 < n:
            i += 2
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1

    return text[start:], n


def _to_backtick(text: str, start: int):
    """Read to the next unescaped backtick.  Returns (body, index_after_it)."""
    i, n = start, len(text)
    while i < n:
        if text[i] == "\\" and i + 1 < n:
            i += 2
            continue
        if text[i] == "`":
            return text[start:i], i + 1
        i += 1
    return text[start:], n


# The redirection operators that EMPTY their target before the command runs.
# `>>` appends, `<`/`<<`/`<<<` read, `>&`/`<&` duplicate a descriptor: none of
# them destroys what is already in the file, and that was checked against a real
# shell rather than read off the grammar.  A leading fd number (`2>`) or `&`
# (`&>`) does not change which of these it is.
_TRUNCATING_OPERATORS = (">", ">|")

# Writing here destroys nothing -- these are discards, not files.  Without this
# the fix would price `>/dev/null echo hi`, one of the most common lines there
# is, off the TERMINAL form of `> /dev/null`, which this classifier reads as a
# systemic destruction (`rm_recursive_root`, because `/dev` is a system root).
# That terminal over-classification predates this change and is left alone: it
# is conservative, not fail-open, and it is not this ticket.
_DISCARD_SINKS = ("/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr",
                  "/dev/tty", "/dev/console")


def _truncates(token: str, redirect) -> bool:
    """Does this redirection operator empty its target?"""
    operator = token[:redirect.end()].lstrip("0123456789&")
    return operator in _TRUNCATING_OPERATORS


def _is_discard_sink(target: str) -> bool:
    return target in _DISCARD_SINKS or target.startswith("/dev/fd/")


def _peeled_truncations(segment: str, preview: Optional[str]):
    """
    Price what a redirection prefix emptied, or None if it emptied nothing.

    This is a SECOND candidate for the same segment rather than a branch inside
    `_classify_segment`, because `> f rm -rf /srv` does two destructive things
    and the line is worth the worse of them.  The caller already keeps the most
    severe classification across segments, so this reuses that comparison
    instead of inventing a second one.
    """
    _, _, truncated = _peel_wrappers(_safe_split(segment))
    if not truncated:
        return None
    return _classify_path_delete(
        truncated, recursive=False, unbounded=False,
        signature="content_overwrite", preview=preview,
    )


def _peel_wrappers(tokens: list):
    """
    Strip prefixes that merely run another command and return
    (remaining_tokens, unbounded, truncated).

    `unbounded` is True when the peeled wrapper feeds the inner command a set
    of arguments that only exists at runtime (`xargs`, GNU `parallel`), which
    means no path list in the command string bounds the affected set.

    `truncated` lists the paths a peeled redirection EMPTIES on its way past.
    A redirection prefix is not only grammar: the shell applies it and then
    runs the command, so `> f cmd` truncates `f` AND runs `cmd`.  Peeling it
    without reporting the truncation is how a production database overwrite
    came back benign (found by qa--237 reviewing this branch).  The caller
    prices these alongside the inner command and keeps the worse of the two.
    """
    unbounded = False
    truncated: list = []
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

        # RFX-144 (ported from PR #98) -- a bare `VAR=value` prefix assignment,
        # as in `FOO=1 rm -rf /srv/prod/data`.  `env FOO=1 rm ...` was already
        # peeled via `env`; the bare form was not, so the whole line was priced
        # as an unrecognised execute.  Anchored at an identifier start so it
        # cannot swallow `--flag=value`.
        if _ENV_ASSIGN_RE.match(tokens[i]):
            i += 1
            continue

        # RFX-337.  A redirection is shell grammar, not a command word.  The
        # shell applies `>/dev/null` and then runs `rm`, but the classifier
        # read the redirection AS the command word and priced the line an
        # unrecognised execute:
        #     echo $(>/dev/null rm -rf /var/lib/pgsql)   -> was allowed
        # and it really deletes (ground truth off disk, with `> /dev/null`,
        # `2>/dev/null` and `>>/dev/null` all destroying too).  This is the
        # same shape as the env-assignment prefix directly above -- a prefix
        # the shell consumes before the command begins -- with a different
        # spelling, so it is peeled in the same place.
        redirect = _REDIRECTION_RE.match(tokens[i])
        if redirect:
            # `>/dev/null` carries its target in this token; a bare `>` or
            # `2>` puts it in the next one, which is a filename and not a
            # command word either way.
            nxt = i + 1
            target = tokens[i][redirect.end():]
            if redirect.end() == len(tokens[i]) and nxt < n:
                target = tokens[nxt]
                nxt += 1
            # A redirection with NOTHING after it is not a prefix -- it IS the
            # operation.  `> /srv/prod/db.sqlite` truncates that file and is a
            # delete (RFX-144's `TestTruncatingOverwrite`), so peeling it here
            # would turn a destructive line into an empty command.  Only a
            # redirection that something else follows is a prefix.
            if nxt >= n:
                break
            # ...but a redirection that IS a prefix still truncated its target
            # on the way past, and that half was being dropped.  Record it; the
            # caller prices it next to the inner command.  Ground truth off
            # disk: `> f cmd`, `>f cmd`, `1> f cmd` and `2> f cmd` all destroy
            # `f`'s previous contents while `cmd` runs.
            if _truncates(tokens[i], redirect) and not _is_discard_sink(target):
                truncated.append(target)
            i = nxt
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

    return tokens[i:], unbounded, truncated


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


def _has_script_file(client: str, args: list, low: list) -> bool:
    """
    True when a database client is handed a script FILE instead of inline SQL.

    The statements are then invisible to the classifier, so nothing in the
    command string bounds what the call does to the database.  `-e`/`-c`
    inline SQL is excluded on purpose: that text IS visible and the SQL
    patterns above already read it.

    RFX-351: `client` is a parameter because the answer depends on it.  The
    flag spellings are looked up per client in `_DB_SCRIPT_FLAGS_BY_CLIENT`;
    see the comment there for the two directions the single shared set was
    wrong in.  Three shapes are not flags at all and are checked for every
    client, because the shell -- not the client -- decides two of them:

      `<`        stdin redirect.  Unchanged, and the shape mysql/mariadb/mongo
                 actually use, which is why those three need no flag entry.
      positional `mongosh prod /tmp/drop.js` runs the file and exits.  Matched
                 on the extension so a database name or a connection string is
                 not mistaken for one.
      in-client  `mysql -e 'source f.sql'`, `sqlite3 db '.read f.sql'`.  The
                 directive is visible; the statements it pulls in are not.
    """
    flags = _DB_SCRIPT_FLAGS_BY_CLIENT.get(client, frozenset())
    prefixes = _DB_SCRIPT_PREFIXES_BY_CLIENT.get(client, ())
    positional = client in _DB_POSITIONAL_SCRIPT_CLIENTS
    for i, a in enumerate(low):
        if a in flags and i + 1 < len(args):
            return True
        if prefixes and a.startswith(prefixes):
            return True
        if a == "<" and i + 1 < len(args):
            return True
        if positional and a.endswith(_DB_POSITIONAL_SCRIPT_SUFFIXES):
            return True
        if _DB_INLINE_SOURCE_RE.search(a):
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


def _rm_flag_tokens(command: str) -> list:
    """
    The flag tokens belonging to the `rm` command itself (RFX-353).

    Same walk as `_extract_rm_paths`, kept deliberately beside it so the two
    cannot drift: locate the rm word by basename, stop at `--`, and return the
    tokens that are flags rather than the ones that are paths.  Restricted to
    `rm` — `rmdir`/`unlink`/`shred` have no recursion flag, and the regex this
    replaces only ever fired on `\\brm\\b`, so widening the family here would be
    an unmeasured change riding along with a measured one.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    start = None
    for i, t in enumerate(tokens):
        if os.path.basename(t).lower() == "rm":
            start = i + 1
            break
    if start is None:
        return []

    flags = []
    for t in tokens[start:]:
        if t == "--":
            break
        if t.startswith("-") and t != "-":
            flags.append(t)
    return flags


def _rm_is_recursive(command: str) -> bool:
    """Does this `rm` ask for recursion, in its OWN argv? (RFX-353)"""
    for t in _rm_flag_tokens(command):
        if t in _RM_RECURSIVE_LONG:
            return True
        if any(_short_bundle_has(t, ch) for ch in _RM_RECURSIVE_SHORT):
            return True
    return False


_GIT_GLOBAL_VALUE_OPTS = frozenset([
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
    "--super-prefix", "--config-env",
])


def _git_subcommand_args(command: str, sub: str) -> Optional[list]:
    """
    The argv of `git <sub>` in this segment, or None when it is not one.

    RFX-353: every git check in this module was spelled `\\bgit\\s+push\\b` —
    the subcommand had to be the very next word.  A git GLOBAL option in between
    defeated all of them at once, and `git -C /srv/app push --force origin main`
    was not even routed to EMIT: it came out execute / recoverable / scoped,
    i.e. a literal unambiguous force push scoring BELOW a plain `git push`.

    `_peel_wrappers` runs first so `sudo git push --force` is still a push.
    """
    tokens = _safe_split(command)
    tokens, _, _ = _peel_wrappers(tokens)
    if not tokens or os.path.basename(tokens[0]).lower() != "git":
        return None
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if not t.startswith("-"):
            return tokens[i + 1:] if t.lower() == sub else None
        if t in _GIT_GLOBAL_VALUE_OPTS:
            i += 2               # `-C <path>`, `-c key=value`
            continue
        if "=" in t:
            i += 1               # `--git-dir=/srv/x` carries its own value
            continue
        i += 1
    return None


_GIT_FALSE_VALUES = frozenset(["false", "0", "no", "off", ""])


def _git_config_overrides(command: str) -> list:
    """The `-c key=value` overrides git is given BEFORE its subcommand.

    Same walk as `_git_subcommand_args`, which skips these as global options.
    They matter because one of them switches a refusal off (RFX-353).
    """
    tokens = _safe_split(command)
    tokens, _, _ = _peel_wrappers(tokens)
    if not tokens or os.path.basename(tokens[0]).lower() != "git":
        return []
    out = []
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if not t.startswith("-"):
            break                                  # the subcommand
        if t == "-c" and i + 1 < len(tokens):
            out.append(tokens[i + 1].lower())
            i += 2
            continue
        if t in _GIT_GLOBAL_VALUE_OPTS:
            i += 2
            continue
        if t.startswith("-c") and len(t) > 2 and not t.startswith("--"):
            out.append(t[2:].lower())              # `-ckey=value`
        i += 1
    return out


def _git_clean_force_not_required(command: str) -> bool:
    """`git -c clean.requireForce=false clean -d` deletes with no `-f` at all.

    Measured: with the default config `git clean -d` answers *"clean.requireForce
    is true and -f not given: refusing to clean"* and removes nothing; with the
    override on the command line it prints "Removing probe/" and the canary is
    gone. Found by dev-1--167, whose measurement handover this closes.
    """
    for kv in _git_config_overrides(command):
        key, sep, value = kv.partition("=")
        if key.strip() == "clean.requireforce":
            return (value.strip() if sep else "") in _GIT_FALSE_VALUES
    return False


def _git_clean_destroys(command: str) -> bool:
    """Does this `git clean` actually remove anything? (RFX-353)"""
    args = _git_subcommand_args(command, "clean")
    if args is None:
        return False
    force = _git_clean_force_not_required(command)
    for t in args:
        if t == "--":
            break
        if t in _GIT_CLEAN_DRY_LONG or _short_bundle_has(t, "n"):
            return False         # measured: -n wins over -f in every order
        if (t in _GIT_CLEAN_FORCE_LONG
                or _short_bundle_has(t, "f") or _short_bundle_has(t, "F")):
            # The uppercase spelling is carried over deliberately. `git clean
            # -Fdx` is NOT a git command -- measured, git 2.x answers
            # "error: unknown switch `F'", prints usage and deletes nothing --
            # but two tests in test_classify.py pin it as delete/broad on
            # purpose ("was broken by [a-z]-only regex"). That position is a
            # separate question from this one; RFX-353 is about reading an
            # ARGV instead of a whole line, and flipping someone else's tested
            # call inside it would be an unmeasured change riding along.
            # Raised in the RFX-353 report instead.
            force = True
    return force


def _git_push_forces(command: str) -> bool:
    """Does this `git push` rewrite or remove a remote ref? (RFX-353)"""
    args = _git_subcommand_args(command, "push")
    if args is None:
        return False
    forces = False
    for t in args:
        if t == "--":
            continue
        if t.startswith("--"):
            name = t.split("=", 1)[0]
            if name in _GIT_PUSH_DRY_LONG:
                return False
            if name in _GIT_PUSH_FORCE_LONG:
                forces = True
            continue
        if t.startswith("-") and t != "-":
            if _short_bundle_has(t, "n"):
                return False                       # `-n` is --dry-run
            if _short_bundle_has(t, "f") or _short_bundle_has(t, "d"):
                forces = True                      # `-f` force, `-d` delete
            continue
        if t.startswith("+") or t.startswith(":"):
            # `+refspec` is the force spelling; `:branch` is an empty SOURCE
            # refspec, which deletes the remote branch. Both measured.
            forces = True
    return forces


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
