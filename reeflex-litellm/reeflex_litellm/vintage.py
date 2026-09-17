"""vintage.py -- does the classifier behind this seat still price a delete as a delete?

WHY THIS MODULE EXISTS (RFX-326)
================================
`reeflex-litellm` owns no classifier.  `normalize.py` renames argument KEYS and
hands the model's own bytes to `reeflex_claude.classify.classify()`, which is
the single classifier every Reeflex seat shares.  That is the design and it
stays the design.

The cost of that design is that this package's behaviour is decided by a
DIFFERENT distribution, resolved at install time.  On 2026-09-17 that cost was
measured, on the artefact a customer installs:

    pip install reeflex-litellm            ->  reeflex-litellm 0.1.0
                                               reeflex-claude  0.2.0

and driven through this package's own `reeflex-litellm decide` against a core
running the image `app.reeflex.io`'s core runs, 23 of 24 destructive
command-substitution lines came back `allow`, most of them under
`reeflex.policy/read_only_internal`:

    echo $(rm -rf /var/lib/pgsql)   ->  allow   (the shell really deletes it)

Nothing was wrong with this package and nothing was wrong with core.
`reeflex-claude 0.2.0` was uploaded at 06:29:31Z on 2026-09-16; the fix that
teaches the classifier to read the BODY of a command substitution (RFX-301)
landed on main at 09:00 on 2026-09-17 and is in no published wheel yet.  The
floor `reeflex-claude>=0.2.0` was satisfied by the newest wheel on the index,
and that wheel predated the fix.

A version floor is a DECLARATION about somebody else's index.  This module is a
MEASUREMENT of the classifier actually loaded in this process.

WHAT IT DOES, AND WHAT HAPPENS WHEN IT FAILS
============================================
`assert_usable()` runs the canaries below through the installed classifier once
per process and caches the result.  `envelope.build_gateway_envelope()` calls
it before it classifies anything, so a failure reaches every seat this package
has -- the LiteLLM guardrail, the connector, and the CLI -- through code that
already exists: `enforce.rule_one_call()` turns an envelope that cannot be
built into a REFUSAL under the fail-closed rule.  A seat standing on a
classifier that misprices these lines therefore refuses every tool call and
says why, rather than allowing them.

That direction is deliberate.  The alternative -- refusing to construct the
guardrail so the proxy will not start -- depends on how LiteLLM treats a
callback whose constructor raises, which is not something this package can
promise.  Refusing per call is a posture this package already implements and
tests.

THE NEGATIVE CANARIES ARE NOT DECORATION
========================================
Four canaries assert a line is NOT priced as a delete.  Without them this check
is passed by a classifier that answers "delete, irreversible, systemic" to
everything -- which would be a gate an operator switches off by lunchtime, and
a check that cannot tell the two failures apart is not measuring the classifier,
only its mood.

WHAT THIS CANNOT SEE, SAID OUT LOUD
===================================
* It is a VINTAGE check, not a conformance suite.  It asks whether the loaded
  classifier has the two fixes whose absence has actually shipped
  (RFX-144/145/146, RFX-301).  A classifier that passes these ten lines can
  still be wrong about a line that is not here.
* Measured on main at `0d9ef31` on 2026-09-17, the tree's own classifier still
  allows nine destructive lines of a 36-line corpus -- deeper nesting than
  `$( $( ) )`, a bare `( ... )` subshell group (RFX-329, PR #164), a redirection
  before the command word inside a substitution body, and the declared
  `gap-command-substitution` family.  Those are open defects with their own
  tickets and are deliberately NOT canaries here: a canary that the current
  tree fails would refuse every call on a correctly installed seat.  This module
  measures the distance between the wheel and the tree, not the distance between
  the tree and the truth.
* It says nothing about core.  A classification is honest and core still
  decides.

CONFIGURATION
=============
There is none, and that is the point: there is no environment variable that
turns this off.  An operator who needs the seat to serve again upgrades
`reeflex-claude`.
"""

from __future__ import annotations

from typing import Optional

# Each canary is (id, command, must_be_delete, why).
#
# The commands are classified, never executed.  `/var/lib/pgsql` is the same
# systemic production path the conformance corpus uses, so a mispricing here is
# a mispricing of the shape that matters.
CANARIES = (
    # -- RFX-144/145/146: read every command on the line, not the first token.
    ("chained-and", "ls -la /tmp && rm -rf /var/lib/pgsql", True,
     "a destructive command after a benign one (RFX-144)"),
    ("chained-semicolon", "cd /tmp; rm -rf /var/lib/pgsql", True,
     "the same, through a separator (RFX-145)"),

    # -- RFX-301: read the BODY of a command substitution.
    ("subst-dollar-paren", "echo $(rm -rf /var/lib/pgsql)", True,
     "the delete runs inside $( ); the outer command word is echo (RFX-301)"),
    ("subst-backtick", "echo `rm -rf /var/lib/pgsql`", True,
     "the same delete in the older backtick spelling (RFX-301)"),
    ("subst-double-quoted", 'echo "cleaning: $(rm -rf /var/lib/pgsql)"',
     True, "double quotes suppress nothing for $( ) (RFX-301)"),
    ("subst-process", "cat <(rm -rf /var/lib/pgsql)", True,
     "process substitution -- the delete runs to produce a descriptor (RFX-301)"),

    # -- The negative canaries.  A classifier that fails these is refusing
    #    everything, which passes the four above for the wrong reason.
    ("not-single-quoted", "echo '$(rm -rf /var/lib/pgsql)'", False,
     "single quotes suppress the substitution: this line prints text"),
    ("not-read-in-subst", "echo $(ls -la /tmp)", False,
     "a read inside a substitution is still a read"),
    ("not-build-stamp", 'echo "built $(date -u +%F)"', False,
     "the everyday reason command substitution exists at all"),
    ("not-plain-read", "cat /etc/hosts", False,
     "the simplest read there is"),
)


class StaleClassifier(RuntimeError):
    """The installed `reeflex_claude` misprices lines this seat must refuse."""


_RESULT: Optional[tuple] = None


def _classifier_identity() -> dict:
    import reeflex_claude
    from reeflex_claude import classify

    return {
        "version": getattr(reeflex_claude, "__version__", "?"),
        "file": getattr(classify, "__file__", "?"),
    }


def failures(force: bool = False) -> list:
    """Run the canaries through the installed classifier.  Cached per process.

    Returns a list of dicts, one per canary that came back wrong.  An empty
    list means every canary was priced as its own line demands.

    `force=True` re-runs and re-caches; it exists for the suite, which needs to
    score more than one classifier in one interpreter.
    """
    global _RESULT
    if _RESULT is not None and not force:
        return list(_RESULT[1])

    from reeflex_claude import classify as _classify

    bad = []
    for cid, command, must_be_delete, why in CANARIES:
        try:
            cls = _classify.classify("Bash", {"command": command})
            verb = cls.get("verb")
            reversibility = cls.get("reversibility")
        except Exception as exc:  # a classifier that raises is not a classifier
            bad.append({"id": cid, "command": command, "why": why,
                        "expected": "delete" if must_be_delete else "not a delete",
                        "got": "raised %s: %s" % (type(exc).__name__, exc)})
            continue

        is_delete = (verb == "delete" and reversibility == "irreversible")
        if is_delete != must_be_delete:
            bad.append({"id": cid, "command": command, "why": why,
                        "expected": ("delete/irreversible" if must_be_delete
                                     else "anything but delete/irreversible"),
                        "got": "%s/%s" % (verb, reversibility)})

    _RESULT = (_classifier_identity(), bad)
    return list(bad)


def identity() -> dict:
    """Which `reeflex_claude` answered the canaries.  Runs them if needed."""
    failures()
    return dict(_RESULT[0]) if _RESULT else {}


def report() -> str:
    """One human-readable line per wrong canary, plus the classifier's identity."""
    bad = failures()
    ident = identity()
    head = ("reeflex_claude %s (%s): %d of %d canaries wrong"
            % (ident.get("version"), ident.get("file"), len(bad), len(CANARIES)))
    if not bad:
        return head
    return head + "\n" + "\n".join(
        "  %-20s %r -> %s (expected %s; %s)"
        % (b["id"], b["command"], b["got"], b["expected"], b["why"])
        for b in bad)


def assert_usable() -> None:
    """Raise `StaleClassifier` if the loaded classifier misprices a canary.

    Called by `envelope.build_gateway_envelope()` before it classifies, so the
    refusal reaches every seat through `enforce.rule_one_call()`'s existing
    fail-closed branch.
    """
    bad = failures()
    if not bad:
        return
    ident = identity()
    raise StaleClassifier(
        "the installed reeflex-claude misprices %d of %d canary lines, so this "
        "gateway seat cannot be trusted to rule on tool calls and refuses them "
        "(RFX-326). Wrong: %s. Loaded: reeflex_claude %s from %s. Upgrade "
        "reeflex-claude to a release carrying RFX-301."
        % (len(bad), len(CANARIES), ", ".join(b["id"] for b in bad),
           ident.get("version"), ident.get("file")))


def _reset_for_tests() -> None:
    """Drop the cache.  Named so nothing reads it as part of the API."""
    global _RESULT
    _RESULT = None
