"""
posture.py -- does the hook cover every tool, or only some of them?

WHY THIS MODULE EXISTS (RFX-325, measured by qa--222 on the published wheel).

`reeflex-claude` 0.1.7's `setup` wrote a PreToolUse matcher that was an
ALLOWLIST of eleven built-in tool names.  Claude Code never invokes a hook for
a tool the matcher does not match, so on such an installation every `mcp__*`
tool, `Task`, `SlashCommand`, `Skill`, `BashOutput` and `KillShell` reached no
gate: the tool ran, the adapter wrote nothing, and core was never asked.  0.2.0
fixed it by shipping `DEFAULT_MATCHER = "*"`.

`pip install -U` does not rewrite `settings.json` and says nothing, so **every
installation made before 0.2.0 still has the old matcher**.  qa--222 measured
the consequence end to end on real `claude` 2.1.268: an upgraded installation
(U1) and an installation with no Reeflex hook at all (F) produced the same
three observables -- tool ran, zero audit records, core asked about nothing.
U1 == F.  An operator cannot tell a governed machine from an ungoverned one.

THE DECISION THIS IMPLEMENTS (owner, 2026-09-17): **warn and run**, not
deny-until-setup and not an opt-out flag.  A narrowing may be deliberate, and
the hook cannot tell deliberate from stale, so it does not get to refuse on
suspicion.  But a warning on a hook's stderr is invisible to almost everyone,
so "warn" here means the narrowing LEAVES A RECORD: one per session, on the
adapter's own audit stream, under its own rule id.  U1 != F afterwards.

WHAT THIS MODULE MAY NEVER DO: change a decision, raise, or make the hook slow.
It is called for its side effect only and every entry point swallows its own
exceptions.  See `note_once()`.

------------------------------------------------------------------------------
HOW THE HOOK LEARNS IT IS NARROWED -- and what that costs per call
------------------------------------------------------------------------------

A PreToolUse hook is a fresh process per tool call and Claude Code tells it
nothing about the matcher it was selected by.  Measured on `claude` 2.1.268
(dev-1--073 evidence `10-hook-environment.txt`): the stdin payload carries
`session_id`, `transcript_path`, `cwd`, `prompt_id`, `permission_mode`,
`tool_name`, `tool_input`, `tool_use_id` -- and nothing about hooks; the
environment carries `CLAUDE_PROJECT_DIR`, `CLAUDE_CODE_SESSION_ID` and friends,
plus whatever the loaded settings' `env` block defines -- and **no variable
names the settings file that was loaded**.

So the hook reads the settings files itself.  Two things keep that off the hot
path:

1. **Once per session, not once per call.**  The first call of a session writes
   a marker keyed by a hash of `session_id`; every later call in that session
   does one `os.path.exists()` on it and returns.  Cost per call after the
   first: **one stat**, measured at ~5 us (`50-per-call-cost.txt`).
2. **Bounded reads.**  At most five candidate paths, each read only if it
   exists and only up to `_MAX_SETTINGS_BYTES`.  Measured cost of the one
   scanning call: ~0.6 ms (same evidence file) -- against a hook whose
   `/v1/decide` round trip is two orders of magnitude larger.

WHY NOT A VERSION MARKER STAMPED BY `setup`?  Because it answers the wrong
question.  A stamp records which version last ran `setup`; what governs is the
matcher that is in the file NOW, and a user may hand-edit it (ours is not the
only hand that writes `settings.json` -- `connect` writes it too, and so do
editors and dotfile managers).  A stamp would read `*` over a file that says
`Bash|Write|...`, which is a false clean bill of health -- the one direction
that must not happen.  So the FILE is the primary evidence and the stamp
(`REEFLEX_CLAUDE_MATCHER`, written into the settings `env` block by `setup`
from 0.2.1) is only consulted when no file names our hook at all.  The stamp
earns its place on exactly one case: Claude Code merges the `env` block of
whichever settings source was loaded, INCLUDING one passed as `--settings
<path>`, and that path is not discoverable from the hook (measured above).

AND THE STAMP IS READ IN ONE DIRECTION ONLY (RFX-325 residual, qa--285).  A
stamp NARROWER than what we ship downgrades the assessment to NARROWED; a
stamp that covers everything does NOT upgrade it to FULL.  The asymmetry is
the same argument as the paragraph above, applied to the case that paragraph
skipped.  "No file names our hook" is not only the `--settings <path>` launch:
it is also, and much more commonly, what an installation with no gate wired
looks like.  Claude Code exports a settings file's `env` block to the
processes it spawns, so the stamp OUTLIVES the hook entry that `setup` wrote
beside it -- delete the entry, keep the block, and the wide stamp is still
there certifying a gate that is gone.  Measured on real `claude` 2.1.268: a
project settings file with an `env` stamp and NO `hooks` key at all produced
`COVERAGE: every tool reaches the gate` and `status --strict` exit 0, on a box
where no settings file wired this hook -- which is RFX-325's own U1 == F shape
inside the instrument RFX-325's fix built to detect it.  So a wide stamp is
read as "not contradicted", never as "verified".

WHAT THIS INSTRUMENT CANNOT SEE, stated rather than discovered later:

* WHICH tools a `claude --settings /some/where.json` launch routes here.  The
  hook cannot find the path, and the stamp that travels with it cannot be
  confirmed against anything, so coverage is UNVERIFIED -- not "fine" and not
  "narrowed".  It is recorded under its own rule id
  (`reeflex.adapter/matcher_unverified`) so it is never read as a measured
  narrowing and never read as silence.  The cost of the paragraph above is
  paid here: a correctly wired `--settings` launch that used to assess FULL
  and stay silent now assesses UNVERIFIED and leaves one record per session.
  That is the trade taken deliberately -- an UNVERIFIED record on a healthy
  installation is a nuisance an operator can close by wiring the hook at a
  fixed location, and a FULL verdict on an ungated one is the failure this
  whole module exists to stop.
* An enterprise-managed settings file at a non-default location.
* Whether Claude Code would in fact have routed a given tool name here: we
  compute coverage with `re.fullmatch`, which is what 2.1.268 was measured to
  do (`20-matcher-semantics.txt`: matcher `ash` does NOT select tool `Bash`,
  while `*` does).  A future Claude Code that changed those semantics would
  make `uncovered` wrong without making the narrowing claim wrong.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .setup_settings import DEFAULT_MATCHER, is_ours

# ---------------------------------------------------------------------------
# Rule ids.  Distinct on purpose: a narrowing we MEASURED and a coverage we
# could not verify are different facts and must not collapse into one row.
# ---------------------------------------------------------------------------

RULE_NARROWED = "reeflex.adapter/matcher_narrowed"
RULE_UNVERIFIED = "reeflex.adapter/matcher_unverified"

# States returned by assess().
STATE_FULL = "full"
STATE_NARROWED = "narrowed"
STATE_UNVERIFIED = "unverified"

# The env var `setup` stamps into settings["env"] from 0.2.1 -- see the module
# docstring for the single case it covers and why it is the fallback, not the
# primary evidence.
MATCHER_STAMP_ENV = "REEFLEX_CLAUDE_MATCHER"

# A matcher that selects every tool.  Claude Code treats "*" as match-all; an
# absent or empty matcher is documented as match-all too, so neither is a
# narrowing.  Anything else is a regex over the tool name.
_FULL_COVERAGE = frozenset({"*", ""})

# Never read more than this from a settings file on the hook path.  A
# pathological file must not stall a tool call.
_MAX_SETTINGS_BYTES = 1 << 20  # 1 MiB

# Session markers older than this are pruned, best effort, when one is written.
_MARKER_TTL_SECONDS = 7 * 24 * 3600

# Tool names used to ILLUSTRATE what a narrowed matcher leaves out.  This is
# not a census of Claude Code's tools and must never be read as one -- the
# whole point of `*` is that the set is open and a governance gate cannot be
# enumerated in advance.  These are the names qa--222 measured escaping, plus
# the built-ins 0.1.7's allowlist omitted.
_ILLUSTRATIVE_TOOLS = (
    "mcp__<server>__<tool>",
    "Task",
    "SlashCommand",
    "Skill",
    "BashOutput",
    "KillShell",
    "ExitPlanMode",
    "TodoWrite",
)


# ---------------------------------------------------------------------------
# Where settings can live
# ---------------------------------------------------------------------------

def candidate_settings_paths() -> List[Path]:
    """
    Every settings file Claude Code is known to load from a FIXED location,
    most specific first.  Deduplicated, order preserved.

    Deliberately NOT included: a path passed as `claude --settings <path>`.
    Nothing in the hook's stdin payload or environment names it (measured --
    see the module docstring), so it cannot be discovered, and guessing would
    be worse than saying so.
    """
    paths: List[Path] = []

    project = os.environ.get("CLAUDE_PROJECT_DIR", "").strip()
    roots = []
    if project:
        roots.append(Path(project))
    try:
        cwd = Path.cwd()
    except OSError:
        cwd = None
    if cwd is not None and cwd not in roots:
        roots.append(cwd)

    for root in roots:
        paths.append(root / ".claude" / "settings.json")
        paths.append(root / ".claude" / "settings.local.json")

    try:
        paths.append(Path.home() / ".claude" / "settings.json")
    except (RuntimeError, OSError):
        pass

    # Enterprise-managed settings, at the documented default locations only.
    if sys.platform == "darwin":
        paths.append(Path("/Library/Application Support/ClaudeCode/managed-settings.json"))
    elif os.name == "nt":  # pragma: no cover -- no Windows box in the fleet
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        paths.append(Path(program_data) / "ClaudeCode" / "managed-settings.json")
    else:
        paths.append(Path("/etc/claude-code/managed-settings.json"))

    seen = set()
    unique: List[Path] = []
    for p in paths:
        key = str(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def _read_settings(path: Path) -> Optional[Dict[str, Any]]:
    """
    Parse one settings file.  Returns None for anything we cannot use -- absent,
    unreadable, oversized, not JSON, not an object.  Never raises: this runs on
    a tool call's critical path and a broken file is the operator's problem to
    see in `reeflex-claude status`, not a reason to disturb the decision.
    """
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_SETTINGS_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) else None


def matchers_in(settings: Dict[str, Any]) -> List[Optional[str]]:
    """
    The matcher of every PreToolUse block that holds one of OUR hook entries.

    A list, not a single value: Claude Code takes the UNION of the hook blocks
    it loads, so an installation can legitimately have our hook wired more than
    once, and coverage is the union of their matchers.  `None` means the block
    had no matcher key at all (match-all).
    """
    out: List[Optional[str]] = []
    hooks_root = settings.get("hooks")
    if not isinstance(hooks_root, dict):
        return out
    pretool = hooks_root.get("PreToolUse")
    if not isinstance(pretool, list):
        return out
    for block in pretool:
        if not isinstance(block, dict):
            continue
        block_hooks = block.get("hooks")
        if not isinstance(block_hooks, list):
            continue
        for item in block_hooks:
            if isinstance(item, dict) and is_ours(item.get("command")):
                matcher = block.get("matcher")
                out.append(matcher if isinstance(matcher, str) else None)
                break
    return out


def is_full_coverage(matcher: Optional[str]) -> bool:
    """True if `matcher` selects every tool name (absent, empty, or `*`)."""
    if matcher is None:
        return True
    return matcher.strip() in _FULL_COVERAGE


def uncovered_examples(matcher: str) -> List[str]:
    """
    Which of `_ILLUSTRATIVE_TOOLS` this matcher does not select.

    `re.fullmatch` because that is what Claude Code 2.1.268 was measured to do:
    matcher `ash` does not select tool `Bash` (evidence `20-matcher-semantics.txt`).
    An invalid regex selects nothing, which is the honest reading -- a matcher
    Claude Code cannot compile gates nothing either.
    """
    try:
        rx = re.compile(matcher)
    except re.error:
        return list(_ILLUSTRATIVE_TOOLS)
    out = []
    for name in _ILLUSTRATIVE_TOOLS:
        probe = name.replace("<server>", "srv").replace("<tool>", "do_it")
        if not rx.fullmatch(probe):
            out.append(name)
    return out


# ---------------------------------------------------------------------------
# The assessment
# ---------------------------------------------------------------------------

def assess() -> Dict[str, Any]:
    """
    Answer "does the matcher this hook runs under cover every tool?" from disk,
    falling back to the `setup`-written stamp when no settings file names us.

    Returns a dict -- always, never raises:
      state    "full" | "narrowed" | "unverified"
      shipped  the matcher this version's `setup` writes
      wired    [{"source": <path or "env:REEFLEX_CLAUDE_MATCHER">,
                 "matcher": <str|None>, "covers_all": bool}, ...]
      uncovered_examples  illustrative tool names no wired matcher selects
      scanned  the candidate paths that existed and parsed
      evidence "settings-file" | "env-stamp" | "none"
    """
    result: Dict[str, Any] = {
        "state": STATE_UNVERIFIED,
        "shipped": DEFAULT_MATCHER,
        "wired": [],
        "uncovered_examples": [],
        "scanned": [],
        "evidence": "none",
    }
    try:
        for path in candidate_settings_paths():
            settings = _read_settings(path)
            if settings is None:
                continue
            result["scanned"].append(str(path))
            for matcher in matchers_in(settings):
                result["wired"].append({
                    "source": str(path),
                    "matcher": matcher,
                    "covers_all": is_full_coverage(matcher),
                })

        if result["wired"]:
            result["evidence"] = "settings-file"
        else:
            # No fixed-location settings file names our hook.  This is the
            # `--settings <path>` launch, among others.  A stamp in the env
            # block travels with whichever file WAS loaded, so it is the only
            # signal available here -- and only installations set up by 0.2.1
            # or later have one.
            stamped = os.environ.get(MATCHER_STAMP_ENV)
            if stamped is not None:
                result["wired"].append({
                    "source": "env:" + MATCHER_STAMP_ENV,
                    "matcher": stamped,
                    "covers_all": is_full_coverage(stamped),
                })
                result["evidence"] = "env-stamp"

        if not result["wired"]:
            result["state"] = STATE_UNVERIFIED
            return result

        if any(w["covers_all"] for w in result["wired"]):
            if result["evidence"] == "env-stamp":
                # RFX-325 residual, measured by qa--285 on real claude 2.1.268.
                # We are here only because NO file at a fixed location names
                # our hook -- which is also what "the gate is not wired" looks
                # like.  A stamp records what `setup` WROTE once; what governs
                # is what is wired NOW.  That is the same reasoning the branch
                # above uses to let a narrow FILE beat a wide stamp, and it
                # does not stop applying when there is no file to compare
                # against -- it gets stronger, because then nothing confirms
                # the stamp at all.  Claude Code exports a loaded settings
                # file's `env` block to every process it spawns, so the stamp
                # outlives the hook entry in that same file: delete the entry,
                # keep the block, and a wide stamp certified a gate that was
                # gone.  A wide stamp can only FAIL TO CONTRADICT coverage; it
                # cannot establish it.  UNVERIFIED, not FULL.
                #
                # Asymmetric on purpose: a NARROW stamp still falls through to
                # STATE_NARROWED below, because that is evidence AGAINST
                # coverage, and the direction that loses a finding is the only
                # one this module has to refuse.
                result["state"] = STATE_UNVERIFIED
                return result
            # Claude Code unions the blocks it loads, so one match-all block is
            # full coverage however narrow its neighbours are.
            result["state"] = STATE_FULL
            return result

        result["state"] = STATE_NARROWED
        covered_by_any = set()
        for w in result["wired"]:
            matcher = w["matcher"] or ""
            missing = set(uncovered_examples(matcher))
            covered_by_any |= (set(_ILLUSTRATIVE_TOOLS) - missing)
        result["uncovered_examples"] = [
            t for t in _ILLUSTRATIVE_TOOLS if t not in covered_by_any
        ]
        return result
    except Exception:  # noqa: BLE001
        # A posture check that throws must not be visible to the decision.
        result["state"] = STATE_UNVERIFIED
        return result


def widen_command(assessment: Dict[str, Any]) -> str:
    """
    The exact `reeflex-claude setup` invocation that would widen the narrowing
    this assessment found -- `--global` when the narrow entry is in the home
    settings file, `--project` otherwise, because `setup` rewrites only the
    file it targets and the wrong flag leaves the narrow one in place.
    """
    try:
        home_settings = str(Path.home() / ".claude" / "settings.json")
    except (RuntimeError, OSError):
        home_settings = ""
    sources = [w.get("source", "") for w in assessment.get("wired", [])]
    if home_settings and sources and all(s == home_settings for s in sources):
        return "reeflex-claude setup --global"
    return "reeflex-claude setup"


# ---------------------------------------------------------------------------
# Once-per-session record
# ---------------------------------------------------------------------------

def _state_dir() -> Path:
    """
    Where the per-session markers live.  Beside the audit log by default, so an
    operator who redirected the audit log to a durable place gets the markers
    there too and a `/tmp` sweep cannot silently re-arm the record.
    """
    configured = os.environ.get("REEFLEX_CLAUDE_STATE_DIR", "").strip()
    if configured:
        return Path(configured)
    audit_log = os.environ.get("REEFLEX_CLAUDE_AUDIT_LOG", "").strip()
    if audit_log:
        parent = os.path.dirname(os.path.abspath(audit_log))
        if parent:
            return Path(parent) / ".reeflex-claude-sessions"
    return Path(tempfile.gettempdir()) / ".reeflex-claude-sessions"


def _marker_path(session_id: str) -> Path:
    """
    Marker file for one session.  The name is a hash, not the session id: the
    id arrives from outside this process and a path is not the place to find
    out it contained a separator.
    """
    digest = hashlib.sha256(session_id.encode("utf-8", "replace")).hexdigest()[:32]
    return _state_dir() / (digest + ".json")


def _prune(state_dir: Path, now: float) -> None:
    """Best-effort removal of markers older than the TTL.  Never raises."""
    try:
        for entry in state_dir.iterdir():
            try:
                if entry.is_file() and now - entry.stat().st_mtime > _MARKER_TTL_SECONDS:
                    entry.unlink()
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass


def note_once(session_id: str, mode: str = "enforce") -> Optional[Dict[str, Any]]:
    """
    Assess coverage once per session and, when it is not full, append ONE
    record to the adapter's audit stream.  Returns the record that was written,
    or None (already done this session / coverage is full / anything at all
    went wrong).

    NEVER raises and NEVER touches the decision -- this is called for its side
    effect and its return value is used by tests and `status`, not by the hook.

    Cost per call after the first of a session: one `os.path.exists`.
    """
    try:
        if not session_id:
            return None
        marker = _marker_path(session_id)
        if marker.exists():
            return None

        assessment = assess()
        record = None
        if assessment["state"] != STATE_FULL:
            record = _build_record(session_id, assessment, mode)
            from .audit import emit_raw
            emit_raw(record)
            _warn_stderr(assessment)

        # Write the marker AFTER the record: a crash between the two repeats
        # the record on the next call, which is a duplicate an operator can
        # see, rather than losing it, which is silence.
        now = time.time()
        try:
            state_dir = marker.parent
            state_dir.mkdir(parents=True, exist_ok=True)
            marker.write_text(
                json.dumps({"state": assessment["state"], "ts": int(now)}),
                encoding="utf-8",
            )
            _prune(state_dir, now)
        except Exception:  # noqa: BLE001
            pass
        return record
    except Exception:  # noqa: BLE001
        return None


def _build_record(session_id: str, assessment: Dict[str, Any], mode: str) -> Dict[str, Any]:
    """
    The record itself.

    It carries `event`, and deliberately carries NO `decision` /
    `permission_decision` key: it is not a verdict on a tool call and a
    consumer that filters decision records on `"decision" in record` -- the
    pattern reeflex-core's own audit stream documents -- must skip it rather
    than count it as one.
    """
    narrowed = assessment["state"] == STATE_NARROWED
    rule = RULE_NARROWED if narrowed else RULE_UNVERIFIED
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if narrowed:
        wired_desc = ", ".join(
            "{0} (from {1})".format(
                "<absent>" if w["matcher"] is None else repr(w["matcher"]), w["source"]
            )
            for w in assessment["wired"]
        )
        reason = (
            "Reeflex: this session is running under a PreToolUse matcher narrower than "
            "the one this version installs. Wired: {wired}. Shipped: {shipped!r}. "
            "Claude Code treats the matcher as an allowlist, so a tool whose name it "
            "does not select reaches no gate at all -- it runs with no decision and no "
            "record. Not selected, for example: {uncovered}. The action was NOT blocked "
            "and no tool call was changed. Widen it with '{fix}', or keep the narrowing "
            "deliberately and expect this record once per session. "
            "[rule={rule}]"
        ).format(
            wired=wired_desc,
            shipped=assessment["shipped"],
            uncovered=", ".join(assessment["uncovered_examples"]) or "(none of the examples)",
            fix=widen_command(assessment),
            rule=rule,
        )
    else:
        # Two different ways to be UNVERIFIED, and the record has to say which:
        # "nothing to read" and "a stamp that cannot be confirmed" send an
        # operator to different places.
        if assessment.get("evidence") == "env-stamp":
            why = (
                "No settings file at a fixed location names this hook. A "
                "{stamp} stamp is present and says {stamped!r}, but a stamp records "
                "what 'setup' once wrote, not what is wired now -- with no file to "
                "confirm it against, a wide stamp cannot establish coverage"
            ).format(
                stamp=MATCHER_STAMP_ENV,
                stamped=next(
                    (w["matcher"] for w in assessment["wired"]
                     if w["source"] == "env:" + MATCHER_STAMP_ENV),
                    None,
                ),
            )
        else:
            why = (
                "No settings file at a fixed location names this hook, and no "
                "{stamp} stamp was present"
            ).format(stamp=MATCHER_STAMP_ENV)
        reason = (
            "Reeflex: this session's PreToolUse coverage could not be verified. {why}, "
            "so the adapter cannot say which tools reach "
            "it -- most commonly a 'claude --settings <path>' launch, whose path the "
            "hook is not told. Coverage may be complete or may not be; this record "
            "says only that it is unknown. Run 'reeflex-claude status' where the agent "
            "runs. [rule={rule}]"
        ).format(why=why, rule=rule)

    return {
        "ts": ts,
        "session_id": "claude:" + session_id,
        "event": "adapter_posture",
        "rule": rule,
        "reason": reason,
        "matcher": {
            "shipped": assessment["shipped"],
            "wired": assessment["wired"],
            "uncovered_examples": assessment["uncovered_examples"],
            "evidence": assessment["evidence"],
            "scanned": assessment["scanned"],
        },
        "remediation": widen_command(assessment),
        "mode": mode,
        "adapter_version": _version(),
    }


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


def _warn_stderr(assessment: Dict[str, Any]) -> None:
    """
    A hook's stderr is invisible to almost everyone -- which is exactly why the
    record above exists and why this is the secondary channel, not the warning.
    Best effort; a closed stderr must not reach the caller.
    """
    try:
        if assessment["state"] == STATE_NARROWED:
            print(
                "[reeflex-claude] WARNING: PreToolUse matcher is narrower than {0!r}; "
                "tools it does not select reach no gate. Run '{1}'. "
                "Recorded once for this session under {2}.".format(
                    assessment["shipped"], widen_command(assessment), RULE_NARROWED
                ),
                file=sys.stderr,
            )
        else:
            print(
                "[reeflex-claude] WARNING: could not verify which tools reach this hook "
                "(no settings file at a fixed location names it). Recorded once for this "
                "session under {0}.".format(RULE_UNVERIFIED),
                file=sys.stderr,
            )
    except Exception:  # noqa: BLE001
        pass
