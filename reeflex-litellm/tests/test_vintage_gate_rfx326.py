"""The seat refuses to rule with a classifier that misprices a delete (RFX-326).

`reeflex_litellm/vintage.py` scores the `reeflex_claude` actually loaded in the
process against ten canary lines and `envelope.build_gateway_envelope()` calls
it before classifying anything.  These tests are about what happens when it
says no -- which cannot be proved by installing an old wheel in CI, so the
stale classifier is injected instead.

THE INJECTION IS THE HONEST FORM HERE, AND THE REASON IS WORTH STATING.  The
defect being guarded against is "the classifier behind this seat is a different
distribution from the one this suite was written against", and the suite by
construction has the right one.  So the wrong one is manufactured: a stub whose
`classify()` prices every command as a benign read, which is exactly what
published `reeflex-claude 0.2.0` did with `echo $(rm -rf /var/lib/pgsql)`.  The
real wheel was measured separately, against a real core, and that measurement
is in `code-reports/dev-2--068-evidence/`; this file measures the REACTION.
"""

from __future__ import annotations

import pytest

from reeflex_claude import classify as _real_classify

from reeflex_litellm import enforce, envelope, normalize, vintage


# The injected classifications are REAL ones, produced by the real classifier
# for a different line -- not hand-written dicts.
#
# THE FIRST VERSION OF THIS FILE HAND-WROTE THEM AND TWO TESTS WERE VACUOUS.
# A hand-written dict is missing keys `reeflex_claude.envelope.build_envelope()`
# reads (`danger_signature`, `classification_tier`), so with the remedy removed
# the envelope raised KeyError, `rule_one_call` refused on THAT, and
# `test_every_tool_call_is_REFUSED_while_the_classifier_is_stale` passed on the
# unfixed tree. It was measuring an incomplete fixture. Taking the control
# before trusting the green is what found it.
#
# A real classification of a harmless line is also the truthful model of the
# defect: published `reeflex-claude 0.2.0` did not return a malformed dict for
# `echo $(rm -rf /var/lib/pgsql)`, it returned a perfectly well-formed
# classification of `echo`.
BENIGN_READ = _real_classify.classify("Bash", {"command": "echo hello"})
EVERYTHING_IS_A_DELETE = _real_classify.classify(
    "Bash", {"command": "rm -rf /var/lib/pgsql"})


@pytest.fixture(autouse=True)
def fresh_vintage_cache():
    """The check is cached per process on purpose. Drop it around every test so
    one test's injected classifier cannot decide another test's verdict."""
    vintage._reset_for_tests()
    yield
    vintage._reset_for_tests()


def _call(command: str):
    return normalize.normalize_tool_call({
        "id": "c1", "type": "function",
        "function": {"name": "run_shell",
                     "arguments": '{"cmd": "%s"}' % command.replace('"', '\\"')},
    })


# ---------------------------------------------------------------------------
# The check itself
# ---------------------------------------------------------------------------

def test_the_real_classifier_passes_every_canary():
    """The baseline. Without it, every test below passes on a broken check."""
    assert vintage.failures() == [], vintage.report()


def test_a_classifier_that_reads_only_the_outer_word_is_caught(monkeypatch):
    """The published 0.2.0 shape: substitutions come back as reads."""
    monkeypatch.setattr(_real_classify, "classify",
                        lambda tool, ti: dict(BENIGN_READ))
    bad = vintage.failures(force=True)
    caught = {b["id"] for b in bad}
    assert {"subst-dollar-paren", "subst-backtick", "subst-process",
            "subst-double-quoted"} <= caught, caught
    assert "not-read-in-subst" not in caught, (
        "a classifier that answers `read` to everything must not be reported "
        "as failing the NEGATIVE canaries -- it passes those, which is why the "
        "positive ones exist")


def test_a_classifier_that_refuses_everything_is_caught_too(monkeypatch):
    """The other direction, which a positive-only corpus cannot see.

    A gate that prices `echo $(ls -la /tmp)` as an irreversible systemic delete
    gets switched off, and then governs nothing at all.
    """
    monkeypatch.setattr(_real_classify, "classify",
                        lambda tool, ti: dict(EVERYTHING_IS_A_DELETE))
    caught = {b["id"] for b in vintage.failures(force=True)}
    assert {"not-single-quoted", "not-read-in-subst", "not-build-stamp",
            "not-plain-read"} <= caught, caught


def test_a_classifier_that_raises_is_not_a_classifier(monkeypatch):
    def boom(tool, ti):
        raise TypeError("classify() takes 1 positional argument")

    monkeypatch.setattr(_real_classify, "classify", boom)
    bad = vintage.failures(force=True)
    assert len(bad) == len(vintage.CANARIES)
    assert all("raised TypeError" in b["got"] for b in bad)


def test_the_report_names_the_classifier_it_scored(monkeypatch):
    monkeypatch.setattr(_real_classify, "classify",
                        lambda tool, ti: dict(BENIGN_READ))
    vintage.failures(force=True)
    text = vintage.report()
    assert "reeflex_claude" in text
    assert "canaries wrong" in text


# ---------------------------------------------------------------------------
# What the seat does about it
# ---------------------------------------------------------------------------

def test_building_an_envelope_raises_on_a_stale_classifier(monkeypatch):
    monkeypatch.setattr(_real_classify, "classify",
                        lambda tool, ti: dict(BENIGN_READ))
    vintage.failures(force=True)
    with pytest.raises(vintage.StaleClassifier) as exc:
        envelope.build_gateway_envelope(
            session_id="s1", model="m",
            call=_call("echo $(rm -rf /var/lib/pgsql)"))
    assert "RFX-326" in str(exc.value)


def test_every_tool_call_is_REFUSED_while_the_classifier_is_stale(monkeypatch):
    """The behaviour that matters: fail CLOSED, per call, with a reason.

    `rule_one_call` already turns an envelope it cannot build into a refusal
    under the fail-closed rule, which is why the check lives in `envelope.py`
    and not in three constructors. A seat that allowed these while the
    classifier was mispricing them is the defect; a seat that refuses them is
    the remedy, and it is measured here rather than argued.
    """
    monkeypatch.setattr(_real_classify, "classify",
                        lambda tool, ti: dict(BENIGN_READ))
    vintage.failures(force=True)

    outcome = enforce.rule_one_call(_call("echo $(rm -rf /var/lib/pgsql)"),
                                    session_id="s1", model="m")
    assert outcome.allowed is False
    assert outcome.refusal is not None
    # Name the REASON, not just the refusal. Any bug in envelope building also
    # produces a refusal here, so an assertion on `allowed is False` alone is
    # satisfied by the tree with this remedy deleted -- measured, 2026-09-17.
    assert "RFX-326" in str(outcome.refusal), outcome.refusal


def test_a_harmless_call_is_refused_too_and_that_is_the_point(monkeypatch):
    """No per-command carve-out.

    Refusing only the lines the canaries name would require knowing which lines
    the stale classifier gets wrong -- which is the knowledge the seat has just
    established it does not have. A classifier that cannot be trusted about
    `$( )` is not selectively trustworthy about anything else, so the seat
    refuses everything and says so.
    """
    monkeypatch.setattr(_real_classify, "classify",
                        lambda tool, ti: dict(BENIGN_READ))
    vintage.failures(force=True)

    outcome = enforce.rule_one_call(_call("ls -la /tmp"),
                                    session_id="s1", model="m")
    assert outcome.allowed is False
    assert "RFX-326" in str(outcome.refusal), outcome.refusal


def test_a_healthy_classifier_costs_the_seat_nothing_after_the_first_call():
    """The check is computed once per process, not per tool call."""
    vintage._reset_for_tests()
    calls = {"n": 0}
    real = _real_classify.classify

    def counting(tool, ti):
        calls["n"] += 1
        return real(tool, ti)

    try:
        _real_classify.classify = counting
        vintage.failures()
        after_first = calls["n"]
        assert after_first == len(vintage.CANARIES)
        vintage.failures()
        vintage.failures()
        assert calls["n"] == after_first, (
            "the canaries ran again: the result is not cached, so every tool "
            "call through this seat would pay for %d extra classifications"
            % len(vintage.CANARIES))
    finally:
        _real_classify.classify = real


def test_there_is_no_environment_variable_that_turns_the_check_off():
    """A fail-open switch is the thing this module exists to prevent.

    Asserted on the source rather than by trying spellings: an operator whose
    seat is refusing everything must upgrade `reeflex-claude`, and the absence
    of an escape hatch is a property somebody could helpfully add back.
    """
    import inspect

    src = inspect.getsource(vintage)
    assert "os.environ" not in src and "getenv" not in src, (
        "vintage.py now reads the environment. If that is a deliberate escape "
        "hatch, it is a documented way to run the gateway seat on a classifier "
        "known to misprice deletes -- say so here and in the module docstring, "
        "or take it out.")
