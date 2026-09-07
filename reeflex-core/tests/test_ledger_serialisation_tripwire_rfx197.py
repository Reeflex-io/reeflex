"""
test_ledger_serialisation_tripwire_rfx197.py — the coupling between RFX-197
(the cumulative ledger's read-decide-write is not atomic) and RFX-198 (core
serves one request at a time and collapses under concurrency).

WHY THIS FILE EXISTS.

R5's cumulative budget is the whole substance of the product's anti-fragmentation
claim ("fragmentation buys nothing" — docs/why-reeflex.md; the n8n package ships
a demo named demo2-fragmentation-doesnt-work). decide.process() enforces it as a
read-decide-write:

    decide.py  cumulative = compute_cumulative(session_id, _WINDOW_SECONDS)   # read
    decide.py  opa_result = evaluate(opa_input)                               # decide
    decide.py  append_entry(session_id, envelope)                             # write

ledger.py's `_lock` is taken INSIDE compute_cumulative and INSIDE append_entry.
It does NOT span the three steps. Two decisions on the same session_id that
overlap would therefore both read the same prior cumulative, both compare
(prior + current) against the limit, and both be allowed — the budget would
under-count by exactly the overlap.

MEASURED (qa--030, 2026-08-22, against the release image built from the root
Dockerfile at main 7f9ebf8): that race does NOT occur. Six barrier-released
simultaneous /v1/decide calls on one session let through exactly 20 deletes,
identical to the sequential control.

It does not occur for ONE REASON ONLY: app/server.py builds
`http.server.HTTPServer`, which is single-threaded, so requests never overlap.
That is a property of the dev-server choice, not a designed guard, and nothing
in the codebase records that the budget's correctness depends on it.

RFX-198's most obvious fix is to make the server concurrent (ThreadingHTTPServer,
or an ASGI server with workers). Doing that ALONE silently converts a guarantee
that currently holds into one that does not. This test is the tripwire: it passes
today, and it goes red the moment the server becomes concurrent without the
ledger gaining a guard that spans the read-decide-write.

It is deliberately an invariant, not an assertion that the server must stay
single-threaded: EITHER the server serialises, OR the ledger exposes a
per-session guard. Satisfying either arm makes it pass.
"""

import inspect
import socketserver
import unittest

from app import ledger, server


# The name a fix for RFX-197 is expected to introduce: a context manager (or
# equivalent) that a caller holds across compute_cumulative -> evaluate ->
# append_entry for one session_id. Any of these satisfies the invariant.
_GUARD_NAMES = ("session_guard", "session_lock", "hold_session", "atomic_session")


def _server_class_used_by_run():
    """The server class app.server.run() actually constructs.

    Read out of run()'s source rather than by calling it, because run() binds a
    socket and blocks in serve_forever().
    """
    src = inspect.getsource(server.run)
    for name in ("ThreadingHTTPServer", "ForkingHTTPServer", "HTTPServer"):
        if f"http.server.{name}(" in src or f"{name}(" in src:
            return getattr(__import__("http.server", fromlist=[name]), name)
    raise AssertionError(
        "could not determine which server class app.server.run() builds; this "
        "tripwire cannot evaluate its invariant and must not silently pass"
    )


def _ledger_exposes_a_cross_call_guard() -> bool:
    return any(hasattr(ledger, n) for n in _GUARD_NAMES)


class TestLedgerSerialisationTripwire(unittest.TestCase):

    def test_server_serialises_or_ledger_guards_the_session(self):
        """EITHER requests never overlap, OR the ledger can be held across them.

        If this fails, someone made core concurrent (good, RFX-198) without
        making the cumulative budget atomic (RFX-197). In that state R5
        under-counts under concurrent load and an agent evades the
        anti-fragmentation budget by issuing its calls in parallel instead of
        in sequence — no restart and no second replica required.
        """
        cls = _server_class_used_by_run()
        concurrent = issubclass(cls, (socketserver.ThreadingMixIn,
                                      socketserver.ForkingMixIn))
        guarded = _ledger_exposes_a_cross_call_guard()

        self.assertTrue(
            (not concurrent) or guarded,
            msg=(
                "app.server.run() now builds %s, which serves requests "
                "concurrently, but app.ledger exposes none of %s.\n\n"
                "R5's cumulative budget is enforced as a read-decide-write in "
                "decide.process():\n"
                "    cumulative = compute_cumulative(session_id, ...)\n"
                "    opa_result = evaluate(opa_input)\n"
                "    append_entry(session_id, envelope)\n"
                "ledger._lock is taken inside the first and third calls only, so "
                "it does not span them. With a concurrent server, two decisions "
                "on one session_id read the same prior cumulative and both pass "
                "a budget that should have held the second.\n\n"
                "Fix RFX-197 (a guard held across all three steps, or a "
                "transactional store) before or with RFX-198 — not after."
                % (cls.__name__, list(_GUARD_NAMES))
            ),
        )

    def test_the_read_and_the_write_are_still_two_unguarded_calls(self):
        """Pin the shape the tripwire above is reasoning about.

        If decide.process() stops calling compute_cumulative and append_entry as
        separate module-level calls — because the budget moved into a
        transactional store, say — this test fails and the tripwire's premise
        needs re-reading rather than trusting.
        """
        from app import decide

        src = inspect.getsource(decide.process)
        self.assertIn("compute_cumulative(", src)
        self.assertIn("append_entry(", src)
        # process() calls append_entry twice: once on the verified-approval
        # fast path (which never consults OPA, so it does no read-decide-write)
        # and once after eval. It is the SECOND one that closes the unguarded
        # window this file is about, so compare against the last occurrence.
        self.assertLess(
            src.index("compute_cumulative("),
            src.rindex("append_entry("),
            "an append_entry must still follow compute_cumulative in process()",
        )


if __name__ == "__main__":
    unittest.main()
