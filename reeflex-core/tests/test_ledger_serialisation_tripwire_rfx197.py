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

At the time that was measured it did not occur for ONE REASON ONLY: app/server.py
built `http.server.HTTPServer`, which is single-threaded, so requests never
overlapped. That was a property of the dev-server choice, not a designed guard.

WHAT HAS HAPPENED SINCE, and why this file was rewritten (dev-1--217,
2026-09-22). Both halves of the coupling moved:

  RFX-198 landed. app/server.py now builds `PooledHTTPServer`, a bounded
  ThreadPoolExecutor; the deployed core reports
  `"server":{"concurrency":"pool","workers":32}` on /healthz. Requests DO
  overlap now.

  RFX-197 landed too, in the same merge train. decide.process() holds
  `ledger.session_guard(session_id)` across compute_cumulative -> evaluate ->
  append_entry, with a per-stripe RLock AND a POSIX record lock, so the cycle
  is atomic across threads and across processes.

So the second arm is what carries the invariant today, and that is the correct
outcome — the ordering rule on RFX-197 ("fix the guard before or with RFX-198,
never after") was respected.

THIS FILE DID NOT NOTICE EITHER EVENT. `_server_class_used_by_run` matched the
substring "HTTPServer(" against "PooledHTTPServer(" and kept answering
`http.server.HTTPServer`, which is not a mixin subclass — so `concurrent` was
False for every possible tree and the invariant became a tautology that could
not fail for any input. Measured 2026-09-22 against the shipped image
ghcr.io/reeflex-io/reeflex-core:v0.2.2: with session_guard renamed out of
_GUARD_NAMES, so that BOTH arms were violated, this file was still green.

The behavioural half of that measurement, on the same image, .118, spare port:
8 barrier-released simultaneous /v1/decide calls on one session, budget 20,
step 5 -> exactly 4 allowed, peak 8 in flight. Same probe against the same
image with session_guard's body replaced by a bare `yield` -> 8 allowed, 40
deletes through, ZERO holds, while the SEQUENTIAL control still held at 20.
That is what this tripwire is protecting and what it could no longer see.

It remains an invariant, not an assertion that the server must stay
single-threaded: EITHER the server serialises, OR decide.process() holds a
per-session guard ACROSS the read and the write. Satisfying either arm makes
it pass. What changed is that both terms are now read from behaviour — a
class's dispatch, and the AST span of the `with` block — rather than from a
substring and a module attribute name.
"""

import ast
import http.server
import inspect
import socketserver
import textwrap
import unittest

from app import decide, ledger, server


# The name a fix for RFX-197 is expected to introduce: a context manager (or
# equivalent) that a caller holds across compute_cumulative -> evaluate ->
# append_entry for one session_id. Any of these satisfies the invariant.
_GUARD_NAMES = ("session_guard", "session_lock", "hold_session", "atomic_session")


def _constructor_names(src: str) -> list:
    """Every identifier `src` CALLS, as exact identifiers.

    Separate from the resolver below so the substring bug that made this file
    vacuous has a unit test of its own: "PooledHTTPServer" must come back as
    "PooledHTTPServer" and never as "HTTPServer".
    """
    tree = ast.parse(textwrap.dedent(src))
    names = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        if isinstance(n.func, ast.Name):
            names.append(n.func.id)
        elif isinstance(n.func, ast.Attribute):
            names.append(n.func.attr)
    return names


def _server_class_used_by_run():
    """The server class app.server.run() actually constructs.

    Read out of run()'s source rather than by calling it, because run() binds a
    socket and blocks in serve_forever().

    RESOLVED BY AST, AND OUT OF `app.server`, NOT OUT OF `http.server`.
    The first version of this helper substring-matched run()'s source for
    "HTTPServer(" and returned `http.server.HTTPServer`. RFX-198 replaced the
    stdlib server with `PooledHTTPServer(...)` -- whose name CONTAINS
    "HTTPServer(" -- so the helper kept answering `http.server.HTTPServer`
    about a 32-worker pool, and the invariant below silently went constant.
    A name that merely ends in the substring must not resolve to the stdlib
    class it is not.
    """
    for name in _constructor_names(inspect.getsource(server.run)):
        if not name.endswith("Server"):
            continue
        cls = getattr(server, name, None) or getattr(
            __import__("http.server", fromlist=[name]), name, None
        )
        if isinstance(cls, type) and issubclass(cls, socketserver.BaseServer):
            return cls
    raise AssertionError(
        "could not determine which server class app.server.run() builds; this "
        "tripwire cannot evaluate its invariant and must not silently pass"
    )


def _serves_requests_concurrently(cls) -> bool:
    """Whether `cls` can have two requests in flight at once.

    Asked as a PROPERTY OF THE CLASS, not as a list of known class names.
    `socketserver.BaseServer.process_request` calls finish_request inline on
    the accept thread -- that, and only that, is what makes requests serialise.
    Every way of not serialising (ThreadingMixIn, ForkingMixIn, RFX-198's
    bounded ThreadPoolExecutor, an asyncio bridge someone writes next year)
    has to override it to hand the request somewhere else.
    """
    if issubclass(cls, (socketserver.ThreadingMixIn, socketserver.ForkingMixIn)):
        return True
    return cls.process_request is not socketserver.BaseServer.process_request


def _guard_spans_the_read_decide_write() -> bool:
    """Whether decide.process() actually HOLDS a guard across the cycle.

    Not `hasattr(ledger, "session_guard")`. A module-level name proves a guard
    was written, not that the read and the write happen inside it, and the
    thing this file's invariant is about is the span. Checked on the AST of
    decide.process: some `with <guard>(...)` block must contain BOTH the
    compute_cumulative call and an append_entry call.
    """
    if not any(hasattr(ledger, n) for n in _GUARD_NAMES):
        return False

    tree = ast.parse(textwrap.dedent(inspect.getsource(decide.process)))

    def called_names(node) -> set:
        return {
            n.func.id
            for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }

    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        holds_guard = any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Name)
            and item.context_expr.func.id in _GUARD_NAMES
            for item in node.items
        )
        if not holds_guard:
            continue
        inside = called_names(node)
        if "compute_cumulative" in inside and "append_entry" in inside:
            return True
    return False


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
        concurrent = _serves_requests_concurrently(cls)
        guarded = _guard_spans_the_read_decide_write()

        self.assertTrue(
            (not concurrent) or guarded,
            msg=(
                "app.server.run() now builds %s, which serves requests "
                "concurrently, but no %s block in decide.process() spans both "
                "compute_cumulative and append_entry.\n\n"
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

    def test_the_invariant_still_has_two_terms_that_can_both_take_both_values(self):
        """The test this file did not have, and the reason it went quiet.

        `(not concurrent) or guarded` is only a tripwire while BOTH terms can
        change. Between 2026-08-22 and this round, `concurrent` was False for
        every conceivable tree: the resolver substring-matched "HTTPServer("
        against RFX-198's "PooledHTTPServer(" and answered
        `http.server.HTTPServer`, which is not a mixin subclass. The assertion
        above therefore could not fail for ANY input — measured on 2026-09-22
        by renaming session_guard out of _GUARD_NAMES on a tree whose server
        is a 32-worker pool: both arms violated, tripwire still green.

        So: pin the discriminator against the stdlib in BOTH directions, and
        pin that a subclass name is not read as the stdlib class it merely
        ends with.
        """
        self.assertFalse(
            _serves_requests_concurrently(http.server.HTTPServer),
            "plain HTTPServer finishes the request on the accept thread; if "
            "this reads concurrent the discriminator is stuck on True",
        )
        self.assertTrue(
            _serves_requests_concurrently(http.server.ThreadingHTTPServer),
            "ThreadingHTTPServer serves requests concurrently; if this reads "
            "serial the discriminator is stuck on False and the invariant "
            "above is a tautology",
        )

        names = _constructor_names(
            "def run():\n"
            "    server = PooledHTTPServer((host, port), H, workers=32)\n"
        )
        self.assertIn("PooledHTTPServer", names)
        self.assertNotIn(
            "HTTPServer", names,
            "a class whose name ENDS in HTTPServer must not resolve to "
            "http.server.HTTPServer — that substring match is exactly what "
            "silenced this tripwire through RFX-198",
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
