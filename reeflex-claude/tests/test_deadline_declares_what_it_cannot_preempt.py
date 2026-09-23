"""RFX-338 -- deadline.py may not promise an answer the runtime does not let it
give, and its limitations section must name the one case it cannot cover.

WHY THIS TEST EXISTS, AND WHY THE EXISTING SUITES DID NOT CATCH IT.

RFX-338's fix (#169, merged 2026-09-17) bounds `file_path` at
`MAX_FILE_PATH_CHARS` so the Write/Edit routes cannot reach a quadratic regex,
and `test_oversize_path*` pins that BEHAVIOUR.  Those guards are green.  What
they do not touch is the sentence that sent the reader the other way:
deadline.py's module docstring promised "a real answer on stdout before the
runner can kill us -- whatever the socket or the classifier is still doing."

That promise was false as written, and dev-1--157 said so in RFX-338's own
comment thread on 2026-09-17 while deliberately not fixing it ("deadline.py's
docstring remains false as written in the general case").  It then shipped
unchanged in reeflex-claude 0.2.1, published 2026-09-20 -- so it is the answer a
customer reading the installed package gets when they ask what the watchdog
guarantees.  `arm()` schedules a `threading.Timer`; CPython's `sre` engine holds
the GIL for the whole of a single `re.search`; so "whatever the classifier is
still doing" is exactly the case the clock cannot cover.

This test states the INVARIANT rather than pinning prose.  It first MEASURES
whether this module's own `arm()` can preempt a GIL-holding regex, using a
pure-Python arm as the positive control -- without that control, "the timer
fired late" is indistinguishable from a broken rig.  Only if the limitation is
measured to be real does it require the docstring to declare it.  If CPython
ever releases the GIL inside `sre` and the control flips, the prose requirement
lifts with it and this test does not have to be rewritten.
"""

import os
import re
import threading
import time
import unittest

from reeflex_claude import deadline as deadline_mod


def _measure(work):
    """Arm the REAL deadline and run `work`. Returns (budget, fired_at, work_end),
    all relative to the moment the timer was armed."""
    fired = []
    prev = os.environ.get(deadline_mod.HOOK_TIMEOUT_ENV)
    os.environ[deadline_mod.HOOK_TIMEOUT_ENV] = "1.0"
    try:
        deadline_mod.restart_clock()
        budget = deadline_mod.remaining()
        t0 = time.monotonic()
        timer = deadline_mod.arm(lambda _d: fired.append(time.monotonic() - t0))
        try:
            work()
            work_end = time.monotonic() - t0
            # Give a correctly-behaving timer a moment to land after the work
            # returns, so "never fired" is not confused with "fired last".
            deadline = time.monotonic() + 2.0
            while not fired and time.monotonic() < deadline:
                time.sleep(0.01)
        finally:
            if timer is not None:
                timer.cancel()
    finally:
        if prev is None:
            os.environ.pop(deadline_mod.HOOK_TIMEOUT_ENV, None)
        else:
            os.environ[deadline_mod.HOOK_TIMEOUT_ENV] = prev
        deadline_mod.restart_clock()
    return budget, (fired[0] if fired else None), work_end


def _python_work(seconds):
    """A pure-Python CPU loop. It releases the GIL at the interpreter's switch
    interval, so a timer thread CAN run: this is the positive control."""
    def run():
        end = time.monotonic() + seconds
        n = 0
        while time.monotonic() < end:
            n += 1
        return n
    return run


def _regex_work(min_seconds, cap_len=1 << 20):
    """ONE `re.search` that backtracks quadratically, sized on this box until a
    single match exceeds `min_seconds`. Self-calibrating so the test does not
    carry a wall-clock constant that is only true on the box it was written on."""
    pattern = re.compile(r"(?:ab)*c$")
    n = 4000
    subject = "ab" * n
    while True:
        t0 = time.perf_counter()
        pattern.search(subject)
        if time.perf_counter() - t0 >= min_seconds or len(subject) >= cap_len:
            break
        n *= 2
        subject = "ab" * n
    return (lambda: pattern.search(subject)), len(subject)


class DeadlineCannotPreemptAGilHoldingRegex(unittest.TestCase):
    """The measurement half: is the limitation real on this runtime?"""

    def test_control_a_python_loop_is_preempted_by_the_deadline(self):
        budget, fired_at, work_end = _measure(_python_work(2.0))
        self.assertIsNotNone(
            fired_at,
            "POSITIVE CONTROL FAILED: deadline.arm() never fired at all during a "
            "pure-Python workload. Nothing else in this file means anything until "
            "this passes -- a timer that never fires would make the regex arm "
            "below trivially 'late'.")
        self.assertLess(
            fired_at, work_end,
            "POSITIVE CONTROL FAILED: the deadline fired at %.3fs but the "
            "pure-Python work only ended at %.3fs (budget %.3fs). The rig is not "
            "measuring preemption." % (fired_at, work_end, budget))

    def test_a_single_regex_is_not_preempted_by_the_deadline(self):
        work, subject_len = _regex_work(min_seconds=3.0)
        budget, fired_at, work_end = _measure(work)
        self.assertIsNotNone(fired_at, "the timer never fired at all")
        self.assertGreater(
            work_end, budget * 2,
            "the regex arm did not outrun its own budget (work %.3fs vs budget "
            "%.3fs at subject length %d), so this arm proves nothing"
            % (work_end, budget, subject_len))
        self.assertGreaterEqual(
            fired_at, work_end - 0.05,
            "deadline.arm() preempted a single re.search: fired at %.3fs while "
            "the match ran until %.3fs. If CPython now releases the GIL inside "
            "sre, this module's limitation has genuinely lifted -- update the "
            "WHAT THIS MODULE DOES NOT CLOSE section and this test together."
            % (fired_at, work_end))


class DocstringDeclaresTheLimitation(unittest.TestCase):
    """The claim half: given the limitation is real, the module must say so."""

    def _doc(self):
        doc = deadline_mod.__doc__ or ""
        self.assertTrue(doc.strip(), "deadline.py has no module docstring")
        return doc

    def _split_on_the_heading(self):
        """(everything before the limitations heading, everything after it)."""
        doc = self._doc()
        heading = "WHAT THIS MODULE DOES NOT CLOSE"
        self.assertEqual(
            doc.count(heading), 1,
            "expected exactly one %r heading in deadline.py's docstring, found "
            "%d -- this test anchors on it and a duplicate would make the "
            "section it scores ambiguous." % (heading, doc.count(heading)))
        before, after = doc.split(heading, 1)
        return before, after

    def _limitations_section(self):
        return self._split_on_the_heading()[1]

    def _promise_half(self):
        return self._split_on_the_heading()[0]

    def test_the_promise_is_not_unconditional(self):
        doc = self._doc()
        self.assertNotIn(
            "whatever the socket or the classifier is still doing", doc,
            "deadline.py promises an answer 'whatever the socket or the "
            "classifier is still doing'. The arm above measures that a single "
            "re.search is NOT preempted, so that sentence is an absolute the "
            "module cannot deliver -- it is the sentence RFX-338 was filed "
            "against, and it shipped in reeflex-claude 0.2.1.")

    def test_the_promise_half_points_at_its_own_bound(self):
        """The test above is a NEGATIVE assertion on one sentence, so it only
        sees that sentence coming back. Measured by qa--337 on the shipped tree:
        replacing the bounded promise with "kill us -- no matter what the socket
        or the classifier is doing" -- the same absolute in different words --
        left all five tests in this file green. A cross-reference is what
        survives a rewrite: an author who rephrases the promise and keeps the
        pointer has still told the reader where the bound is.

        LIMIT, stated rather than implied: an absolute that ALSO keeps the
        pointer passes both tests. What is closed is the shape the defect
        actually took -- a promise written as if the section did not exist. A
        marker list of quantifiers was tried and rejected: "whatever" occurs
        legitimately in this half ("clamped under whatever is left of the
        deadline"), so scoring the word would fire on correct prose.
        """
        head = self._promise_half()
        self.assertIn(
            "limitations section", head,
            "the half of deadline.py's docstring that makes the promise no "
            "longer points the reader at the section that bounds it. The "
            "measured limitation is that a threading.Timer cannot preempt a "
            "GIL-holding regex; a promise that does not carry a pointer to its "
            "own limitations section reads as unconditional however it is "
            "phrased, which is the defect RFX-338 was filed against.")

    def test_the_limitations_section_names_the_gil_case(self):
        section = self._limitations_section()
        for token in ("GIL", "re.search", "RFX-338"):
            self.assertIn(
                token, section,
                "deadline.py's WHAT THIS MODULE DOES NOT CLOSE section does not "
                "mention %r. The measured limitation is that a threading.Timer "
                "cannot preempt a GIL-holding regex; a limitations section that "
                "omits it leaves the reader with the unconditional promise this "
                "ticket removed." % token)

    def test_the_declaration_points_at_the_real_remedy(self):
        section = self._limitations_section()
        self.assertIn(
            "MAX_FILE_PATH_CHARS", section,
            "the limitation is declared but the reader is not told what actually "
            "bounds it. The durable bound on regex time is bounding the INPUT, "
            "and classify.py's MAX_FILE_PATH_CHARS is the instance RFX-338 "
            "landed; naming it is what stops the declaration reading as "
            "'unfixable'.")


if __name__ == "__main__":
    unittest.main()
