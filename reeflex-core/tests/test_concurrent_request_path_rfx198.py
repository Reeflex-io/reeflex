"""
test_concurrent_request_path_rfx198.py — RFX-198: core must serve more than one
decision at a time, and must refuse overload with an ANSWER rather than silence.

WHAT WAS MEASURED BEFORE THE FIX, on the customer artefact (the root
Dockerfile) at origin/main 1b80c8b, identical read envelopes, one client host:

    rung                 wall  answered   dec/sec     p50     worst    >5s    >10s
    SEQUENTIAL   120     6.0s   120/120      19.9    50ms      66ms      0       0
    CONCURRENT     4     0.2s     4/4        18.9   123ms     209ms      0       0
    CONCURRENT    16     1.4s    16/16       11.3   448ms    1407ms      0       0
    CONCURRENT   120    53.8s   120/120       2.2  7393ms   53807ms     64      36

Concurrency made the engine NINE TIMES SLOWER per decision than doing the same
work one call at a time. `http.server.HTTPServer` (not ThreadingHTTPServer)
served one request at a time, and `request_queue_size` was never set, so the
listen backlog was socketserver.TCPServer's default of FIVE.

WHY THAT IS A SAFETY DEFECT AND NOT ONLY A PERFORMANCE ONE. Every shipped
adapter fails CLOSED when core does not answer in time -- reeflex-claude 5s,
reeflex-wordpress 5s, reeflex-mcp 10s. That default is correct. Its consequence
is that a saturated core does not wave work through, it REFUSES: at width 120,
64 of 120 legitimate decisions came back slower than the 5s adapter deadline
and 36 slower than the 10s one, with no policy consulted and no audit line
saying why. A less patient client sees the same load as hard connection resets
instead. The operator's only pressure-relief valve is to switch the adapter
from enforce to observe, which turns the product off -- so an availability
failure of the enforcement plane converts, in one step, into no enforcement.

THE FIX IS A BOUNDED POOL, NOT ThreadingHTTPServer. Every decision forks an
`opa eval` subprocess (app/opa.py), so thread-per-connection means
subprocess-per-connection: a burst that used to be refused at the socket would
instead fork the box to death, which is the same denial with a worse blast
radius. The bound is on concurrent policy evaluations.

These tests pin each of those claims so the defect cannot come back:

  T_run_builds_a_pooled_server     run() constructs PooledHTTPServer. Checked
                                   structurally (AST), because a refactor back
                                   to HTTPServer would leave every behavioural
                                   test here passing against a server the
                                   product does not actually build.
  T_not_thread_per_connection      PooledHTTPServer does NOT inherit
                                   ThreadingMixIn, and does not carry a
                                   `daemon_threads` attribute that would imply
                                   it does.
  T_two_requests_overlap_in_time   THE TEST THAT FAILS ON MAIN. Two clients,
                                   one handler that cannot finish until BOTH
                                   have arrived. Under a single-threaded server
                                   the second never arrives and the barrier
                                   times out.
  T_pool_bound_is_enforced         with N workers, no more than N handlers ever
                                   run at once -- the bound is real, so the
                                   OPA-subprocess count is bounded too.
  T_backlog_set_before_activate    request_queue_size must be assigned BEFORE
                                   TCPServer.server_activate() calls listen(),
                                   or the socket listens with the old default
                                   of 5 and the fix silently does nothing.
                                   Behavioural AND structural.
  T_overload_is_shed_with_503      past max_pending, a caller gets a PARSEABLE
                                   503 naming "overloaded" with Retry-After --
                                   not a reset, not a hang. The whole argument
                                   for shedding is that the caller learns which
                                   refusal this was.
  T_shed_is_counted_separately     health() reports shed_total and, separately,
                                   shed_undelivered. "Refused and told why" and
                                   "refused silently" are different facts about
                                   the same outage, and neither was obtainable
                                   before.
  T_worker_and_pending_bounds      the env overrides and their clamps, including
                                   garbage falling back to the default rather
                                   than to zero workers (which would be a
                                   total outage from a typo).
  T_request_timeout_is_applied     run() sets a handler timeout. A bounded pool
                                   REQUIRES one: without it a client that
                                   connects and says nothing holds a worker
                                   forever, so N silent clients are a cheap
                                   total outage.
  T_freeze_flip_fires_once         decide._check_freeze_flip's compare-then-
                                   assign is one critical section. The operator
                                   kill switch must be reported ONCE per flip,
                                   not once per thread that noticed it.

Run:
  cd reeflex-core
  python -m unittest tests.test_concurrent_request_path_rfx198 -v
"""

from __future__ import annotations

import ast
import http.client
import inspect
import json
import os
import pathlib
import socket
import socketserver
import threading
import unittest

from app import server as srv


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_APP_DIR = pathlib.Path(srv.__file__).resolve().parent


def _server_source() -> str:
    return (_APP_DIR / "server.py").read_text(encoding="utf-8")


class _Probe(unittest.TestCase):
    """Base with a helper that runs a PooledHTTPServer on an ephemeral port."""

    def _serve(self, handler_cls, *, workers, max_pending, backlog=128):
        server = srv.PooledHTTPServer(
            ("127.0.0.1", 0),
            handler_cls,
            workers=workers,
            backlog=backlog,
            max_pending=max_pending,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def _stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)

        self.addCleanup(_stop)
        return server, server.server_address[1]


def _get(port, path="/", timeout=15):
    """One request. Returns (status, body_text) or ('ERR', repr) -- never raises.

    A transport failure is a RESULT here, not an error: "the caller got no
    answer" is precisely one of the outcomes under test.
    """
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.getheaders())
    except Exception as exc:  # noqa: BLE001
        return "ERR", repr(exc), {}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# structural: the product must actually BUILD the concurrent server
# ---------------------------------------------------------------------------

class TestServerConstruction(unittest.TestCase):

    def test_run_builds_a_pooled_server(self):
        """run() must construct PooledHTTPServer, not http.server.HTTPServer.

        Structural on purpose. Every behavioural test in this file constructs
        the pool directly, so all of them would still pass if run() were
        refactored back to a single-threaded HTTPServer -- and the shipped
        product would be single-threaded again with a green suite.
        """
        tree = ast.parse(_server_source())
        run_fn = next(
            (n for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name == "run"),
            None,
        )
        self.assertIsNotNone(run_fn, "app/server.py has no run()")

        constructed = set()
        for node in ast.walk(run_fn):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name):
                    constructed.add(f.id)
                elif isinstance(f, ast.Attribute):
                    constructed.add(f.attr)

        self.assertIn(
            "PooledHTTPServer", constructed,
            "run() does not construct PooledHTTPServer -- core is back to "
            "serving one decision at a time (RFX-198)",
        )
        self.assertNotIn(
            "HTTPServer", constructed,
            "run() constructs a bare HTTPServer: one decision at a time, "
            "listen backlog 5 (RFX-198)",
        )

    def test_not_thread_per_connection(self):
        """Bounded pool, NOT ThreadingMixIn.

        Unbounded threads mean unbounded concurrent `opa eval` subprocesses.
        Also asserts the absence of `daemon_threads`: that attribute is read
        only by ThreadingMixIn, so setting it on a class that does not inherit
        ThreadingMixIn states a shutdown guarantee it does not provide.
        """
        self.assertTrue(issubclass(srv.PooledHTTPServer, socketserver.TCPServer))
        self.assertNotIn(
            socketserver.ThreadingMixIn,
            inspect.getmro(srv.PooledHTTPServer),
            "PooledHTTPServer inherits ThreadingMixIn -- the pool bound, and "
            "with it the bound on concurrent OPA subprocesses, is gone",
        )
        self.assertFalse(
            hasattr(srv.PooledHTTPServer, "daemon_threads"),
            "daemon_threads is read only by ThreadingMixIn; setting it here "
            "implies a shutdown guarantee this class does not provide",
        )

    def test_backlog_set_before_activate_structurally(self):
        """request_queue_size must be assigned BEFORE super().__init__().

        TCPServer.server_activate() calls socket.listen(self.request_queue_size)
        during construction. Assigning afterwards listens with the inherited
        default of 5 and changes nothing -- a fix that reads correctly and does
        not work. Nothing behavioural can see the difference reliably, so the
        ordering is pinned here.
        """
        tree = ast.parse(_server_source())
        cls = next(
            (n for n in tree.body
             if isinstance(n, ast.ClassDef) and n.name == "PooledHTTPServer"),
            None,
        )
        self.assertIsNotNone(cls)
        init = next(
            (n for n in cls.body
             if isinstance(n, ast.FunctionDef) and n.name == "__init__"),
            None,
        )
        self.assertIsNotNone(init)

        assign_line = None
        super_line = None
        for node in ast.walk(init):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if (isinstance(t, ast.Attribute)
                            and t.attr == "request_queue_size"
                            and assign_line is None):
                        assign_line = node.lineno
            if isinstance(node, ast.Call):
                f = node.func
                if (isinstance(f, ast.Attribute) and f.attr == "__init__"
                        and isinstance(f.value, ast.Call)
                        and isinstance(f.value.func, ast.Name)
                        and f.value.func.id == "super"
                        and super_line is None):
                    super_line = node.lineno

        self.assertIsNotNone(assign_line, "request_queue_size is never assigned")
        self.assertIsNotNone(super_line, "__init__ never calls super().__init__")
        self.assertLess(
            assign_line, super_line,
            "request_queue_size is assigned AFTER super().__init__(), so "
            "listen() already ran with the default backlog of 5 (RFX-198)",
        )


# ---------------------------------------------------------------------------
# behavioural: concurrency is real, and bounded
# ---------------------------------------------------------------------------

class TestConcurrency(_Probe):

    def test_two_requests_overlap_in_time(self):
        """THE TEST THAT FAILS ON MAIN.

        The handler cannot complete until TWO requests are inside it at once.
        Under http.server.HTTPServer the second request is not accepted until
        the first returns, so the barrier times out and both clients fail.
        """
        barrier = threading.Barrier(2)
        reached = []

        class H(srv.http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                try:
                    barrier.wait(timeout=10)
                    reached.append(1)
                    body = b'{"overlapped":true}'
                except threading.BrokenBarrierError:
                    body = b'{"overlapped":false}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):  # silence
                pass

        _, port = self._serve(H, workers=4, max_pending=64)

        out = [None, None]

        def client(i):
            out[i] = _get(port)

        ts = [threading.Thread(target=client, args=(i,)) for i in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=30)

        self.assertEqual(
            len(reached), 2,
            "two requests never overlapped: the server is serving one at a "
            "time (RFX-198). results=%r" % (out,),
        )
        for i, r in enumerate(out):
            self.assertEqual(r[0], 200, "client %d: %r" % (i, r))
            self.assertIn("true", r[1])

    def test_pool_bound_is_enforced(self):
        """With N workers, never more than N handlers in flight.

        This is the bound that keeps a burst from forking N concurrent
        `opa eval` subprocesses. Asserts both directions: the cap holds, AND
        concurrency actually happens (a cap of 2 that only ever runs 1 would
        satisfy the cap and mean the pool is not working).
        """
        workers = 2
        n_clients = 10
        lock = threading.Lock()
        state = {"live": 0, "peak": 0}
        gate = threading.Event()

        class H(srv.http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                with lock:
                    state["live"] += 1
                    state["peak"] = max(state["peak"], state["live"])
                # Hold the worker until enough clients have piled up that a
                # too-large pool would be visible in `peak`.
                gate.wait(timeout=5)
                with lock:
                    state["live"] -= 1
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        _, port = self._serve(H, workers=workers, max_pending=n_clients * 4)

        results = [None] * n_clients
        threads = []
        for i in range(n_clients):
            def client(i=i):
                results[i] = _get(port, timeout=30)
            t = threading.Thread(target=client)
            threads.append(t)
            t.start()

        # Let the pool fill, then release.
        deadline = threading.Event()
        deadline.wait(1.5)
        gate.set()
        for t in threads:
            t.join(timeout=40)

        self.assertLessEqual(
            state["peak"], workers,
            "pool bound breached: %d handlers ran at once with workers=%d -- "
            "that many concurrent OPA subprocesses (RFX-198)"
            % (state["peak"], workers),
        )
        self.assertGreater(
            state["peak"], 1,
            "never more than one handler ran at once: the pool is not "
            "actually serving concurrently (RFX-198)",
        )
        ok = [r for r in results if r and r[0] == 200]
        self.assertEqual(len(ok), n_clients,
                         "not every queued client was answered: %r" % (results,))

    def test_backlog_is_applied_to_the_socket(self):
        """The constructed server carries the backlog we asked for."""
        server, _ = self._serve(
            _Quiet200, workers=4, max_pending=32, backlog=97)
        self.assertEqual(server.request_queue_size, 97)
        self.assertEqual(
            server.health()["listen_backlog"], 97,
            "the backlog is not reported, so an operator cannot tell whether "
            "the 5-deep default is still in force",
        )

    def test_request_timeout_is_applied(self):
        """A bounded pool requires a handler timeout.

        Without one, a client that opens a connection and never finishes its
        request line holds its worker forever -- so N silent clients are a
        cheap total outage. Under the old single-threaded server this was
        already fatal and so changed nothing; under a pool of N it is the
        cheapest way to occupy all N.
        """
        self.assertGreater(
            srv._REQUEST_TIMEOUT_SECONDS, 0,
            "no request timeout: a silent client holds a worker forever",
        )
        src = _server_source()
        self.assertIn(
            "_DecideHandler.timeout = _REQUEST_TIMEOUT_SECONDS", src,
            "run() does not apply the request timeout to the handler, so the "
            "configured value is inert",
        )

        # Behavioural: a worker occupied by a silent client is released, and a
        # later honest client is still served.
        class H(srv.http.server.BaseHTTPRequestHandler):
            timeout = 0.5

            def do_GET(self):  # noqa: N802
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        _, port = self._serve(H, workers=1, max_pending=8)

        # Occupy the single worker with a connection that says nothing.
        silent = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.addCleanup(silent.close)

        status, body, _ = _get(port, timeout=20)
        self.assertEqual(
            status, 200,
            "an honest client was not served while one silent connection was "
            "open: the worker was held indefinitely (RFX-198). got %r"
            % (body,),
        )


class _Quiet200(srv.http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# ---------------------------------------------------------------------------
# behavioural: overload is refused with an ANSWER
# ---------------------------------------------------------------------------

class TestLoadShedding(_Probe):

    def _saturate(self, n_clients=8):
        """One worker, max_pending=1, handler pinned open -> everything else sheds."""
        gate = threading.Event()
        self.addCleanup(gate.set)

        class H(srv.http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                gate.wait(timeout=10)
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server, port = self._serve(H, workers=1, max_pending=1)

        results = [None] * n_clients
        threads = []
        for i in range(n_clients):
            def client(i=i):
                results[i] = _get(port, timeout=20)
            t = threading.Thread(target=client)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=30)
        return server, results, gate

    def test_overload_is_shed_with_a_readable_503(self):
        """A shed caller gets a PARSEABLE 503 naming overloaded, not a reset.

        The entire argument for shedding is that the caller learns WHICH
        refusal this was -- policy or load. A shed the caller cannot read is
        worth no more than the connection reset it replaced.
        """
        _, results, _ = self._saturate()

        sheds = [r for r in results if r and r[0] == 503]
        self.assertGreater(
            len(sheds), 0,
            "nothing was shed under saturation -- callers are still queued or "
            "reset silently. results=%r" % (results,),
        )

        status, body, headers = sheds[0]
        try:
            parsed = json.loads(body)
        except Exception as exc:  # noqa: BLE001
            self.fail("shed body is not JSON (%r): %r" % (exc, body))

        self.assertEqual(
            parsed.get("error"), "overloaded",
            "the shed response does not name the failure as load, so an "
            "operator cannot separate it from a policy denial: %r" % (parsed,),
        )
        self.assertIn("reason", parsed)
        low = {k.lower(): v for k, v in headers.items()}
        self.assertIn(
            "retry-after", low,
            "no Retry-After on a 503: the caller is told to fail but not when "
            "it may try again. headers=%r" % (headers,),
        )
        self.assertEqual(
            low.get("content-type"), "application/json; charset=utf-8",
            "a shed must parse like every other refusal: %r" % (headers,),
        )

    def test_shed_is_counted_separately(self):
        """shed_total, and separately shed_undelivered, on health().

        A refusal for load and a refusal by policy looked identical from every
        surface before this. And "refused and told why" is a different fact
        from "refused silently", so folding the two counts together would hide
        exactly the case the shed path was written to remove.
        """
        server, results, _ = self._saturate()
        health = server.health()

        for key in ("concurrency", "workers", "listen_backlog", "max_pending",
                    "pending", "shed_total", "shed_undelivered"):
            self.assertIn(key, health, "health() lost %r" % (key,))

        self.assertEqual(health["concurrency"], "pool")
        observed_sheds = len([r for r in results if r and r[0] == 503])
        self.assertGreaterEqual(
            health["shed_total"], observed_sheds,
            "shed_total (%r) is lower than the number of 503s clients actually "
            "read (%d): the counter under-reports the outage"
            % (health["shed_total"], observed_sheds),
        )
        self.assertGreater(health["shed_total"], 0)
        self.assertLessEqual(health["shed_undelivered"], health["shed_total"])


# ---------------------------------------------------------------------------
# the bounds themselves
# ---------------------------------------------------------------------------

class TestBounds(unittest.TestCase):

    def setUp(self):
        self._saved = {k: os.environ.get(k)
                       for k in ("REEFLEX_MAX_WORKERS", "REEFLEX_MAX_PENDING")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_worker_and_pending_bounds(self):
        os.environ.pop("REEFLEX_MAX_WORKERS", None)
        default = srv._max_workers()
        self.assertGreaterEqual(default, 4, "a 1-core box must still serve a burst")
        self.assertLessEqual(
            default, 32,
            "unclamped worker default: on a many-core box this is that many "
            "concurrent `opa eval` subprocesses",
        )

        os.environ["REEFLEX_MAX_WORKERS"] = "7"
        self.assertEqual(srv._max_workers(), 7)

        # Garbage and zero must fall back to the default, NOT to zero workers:
        # a typo in an env var must not be a total outage.
        for bad in ("", "   ", "abc", "0", "-3", "1.5"):
            os.environ["REEFLEX_MAX_WORKERS"] = bad
            self.assertEqual(
                srv._max_workers(), default,
                "REEFLEX_MAX_WORKERS=%r did not fall back to the default" % (bad,),
            )

        os.environ.pop("REEFLEX_MAX_PENDING", None)
        self.assertEqual(srv._max_pending(4), 32)
        os.environ["REEFLEX_MAX_PENDING"] = "11"
        self.assertEqual(srv._max_pending(4), 11)
        for bad in ("", "abc", "0", "-1"):
            os.environ["REEFLEX_MAX_PENDING"] = bad
            self.assertEqual(
                srv._max_pending(4), 32,
                "REEFLEX_MAX_PENDING=%r did not fall back" % (bad,),
            )

    def test_shed_response_is_prerendered_and_wellformed(self):
        wire = srv._OVERLOADED_WIRE
        self.assertIsInstance(wire, bytes)
        head, _, body = wire.partition(b"\r\n\r\n")
        self.assertIn(b"503", head.split(b"\r\n")[0])
        self.assertIn(b"Retry-After:", head)
        self.assertIn(b"X-Content-Type-Options: nosniff", head)
        parsed = json.loads(body.decode())
        self.assertEqual(parsed["error"], "overloaded")
        # Content-Length must match the body actually sent, or the client
        # blocks waiting for bytes that never come -- an unreadable shed.
        declared = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                declared = int(line.split(b":", 1)[1].strip())
        self.assertEqual(
            declared, len(body),
            "Content-Length %r != body length %d: the client hangs waiting for "
            "the rest of a refusal" % (declared, len(body)),
        )


# ---------------------------------------------------------------------------
# decide.py: the kill switch must be reported once per flip
# ---------------------------------------------------------------------------

class TestFreezeFlipUnderConcurrency(unittest.TestCase):
    """The compare-then-assign in _check_freeze_flip is one critical section.

    The bool ASSIGNMENT was always atomic under the GIL -- the comment this
    replaced said so, and was right about that. The read-modify-write around
    it never was; it was safe only because app/server.py served one request at
    a time. Making the request path concurrent promotes this from unreachable
    to reachable, and REEFLEX_FREEZE is the operator kill switch: the one
    event that must reach the webhook, the audit log and the SIEM exactly once
    per flip.
    """

    def test_freeze_flip_fires_once_per_flip(self):
        from app import decide as dec

        fires = []
        fire_lock = threading.Lock()
        original = dec._try_fire_freeze_flipped

        def counting(freeze_on):
            with fire_lock:
                fires.append(freeze_on)

        dec._try_fire_freeze_flipped = counting
        saved_state = dec._last_freeze_state
        self.addCleanup(
            lambda: setattr(dec, "_try_fire_freeze_flipped", original))

        def restore():
            dec._last_freeze_state = saved_state
        self.addCleanup(restore)

        n = 24
        for flip_to in (True, False):
            fires.clear()
            dec._last_freeze_state = not flip_to
            barrier = threading.Barrier(n)

            def worker():
                barrier.wait(timeout=10)
                dec._check_freeze_flip(flip_to)

            threads = [threading.Thread(target=worker) for _ in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)

            self.assertEqual(
                len(fires), 1,
                "the kill switch flip to %r was reported %d times by %d "
                "concurrent callers -- the compare-then-assign is not atomic "
                "(RFX-198)" % (flip_to, len(fires), n),
            )
            self.assertEqual(fires[0], flip_to)
            self.assertEqual(dec._last_freeze_state, flip_to)

    def test_freeze_lock_is_a_real_lock(self):
        from app import decide as dec

        self.assertTrue(
            hasattr(dec._freeze_lock, "acquire"),
            "_freeze_lock is not a lock (it used to be None, with a comment "
            "explaining that the GIL made one unnecessary)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
