"""
test_gate_credential_rfx224.py — portal-issued, gate-scoped credentials on
POST /v1/decide.

Runs the REAL _DecideHandler on an ephemeral port (the `test_auth.py` shape)
AND a REAL stub portal on a second ephemeral port, because the thing under
test is a network round trip and a monkeypatched `_introspect` would test
nothing but its own mock. The stub records every request it receives, which is
what lets the cache tests count calls instead of believing a docstring.

WHAT EACH CASE IS FOR:

  INERT BY DEFAULT — with REEFLEX_GATE_INTROSPECTION_URL unset, an `rfx_ac_`
      bearer is refused exactly like any other wrong token, and the stub portal
      is never called. This is the compatibility case and it is FIRST, because
      every existing deployment is in it.
  THE HAPPY PATH — active credential + matching X-Reeflex-Gate -> 200 with a
      decision, and the shared REEFLEX_AUTH_TOKEN was never presented.
  THE THREE REFUSALS, EACH SEPARATELY — 401 for a credential the portal will
      not confirm, 403 gate_mismatch for one replayed on another gate, 403
      gate_not_declared for one presented with no gate at all. Three different
      facts, three different answers; a suite that only checked "refused"
      would pass with all three collapsed into 401.
  FAIL CLOSED — portal unreachable and portal answering nonsense both refuse.
      A governance engine that accepted a credential it could not validate
      would be worse than one that refuses.
  THE CACHE — a positive answer is reused (call count does not grow) and a
      NEGATIVE one is not (a credential minted a moment ago must work on its
      first use).
  THE SHARED TOKEN STILL WINS — with both configured, REEFLEX_AUTH_TOKEN is
      accepted with no introspection call at all, and needs no gate header.
  HOLDS ROUTES DO NOT ACCEPT IT — the submitting role and the approving role
      stay apart, which is the same containment `_authorized`'s
      `allow_resolver_tokens` docstring argues for in the other direction.

Run:
  cd reeflex-core
  python -m unittest tests.test_gate_credential_rfx224 -v
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app import gate_credential
from app.server import _DecideHandler

# Obvious throwaway values, NOT real secrets.
SHARED_TOKEN = "reeflex-test-shared-token-not-a-secret"
LIVE_CREDENTIAL = "rfx_ac_" + "L" * 43
OTHER_CREDENTIAL = "rfx_ac_" + "O" * 43
DEAD_CREDENTIAL = "rfx_ac_" + "D" * 43
GARBAGE_CREDENTIAL = "rfx_ac_" + "G" * 43

GATE_A = "11111111-1111-4111-8111-111111111111"
GATE_B = "22222222-2222-4222-8222-222222222222"


def _minimal_envelope() -> dict:
    """Read-only / reversible / single / internal — the same envelope
    `test_auth.py` uses, so a refusal here is unambiguously about auth and not
    about a policy that dislikes the action."""

    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:gate-credential-test",
            "on_behalf_of": "user:synthetic",
            "session_id": f"gc_test_{uuid.uuid4().hex[:12]}",
        },
        "action": {"namespace": "test", "verb": "read", "ability": "test/read"},
        "target": {"kind": "entity", "ref": None, "environment": "staging"},
        "params": {},
        "magnitude": {"count": 1},
        "axes": {
            "reversibility": "reversible",
            "blast_radius": "single",
            "externality": "internal",
        },
        "approval": {"present": False, "by": None, "role": None},
        "trajectory_ref": None,
        "context": {},
        "meta": {
            "timestamp": "2026-06-29T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


class _StubPortalHandler(http.server.BaseHTTPRequestHandler):
    """The portal's `POST /api/v1/agent/introspect`, answering the way the real
    one does: HTTP 200 either way, `{"active": false}` uniformly for every
    failure. Deliberately faithful on that point -- a stub that answered 401
    for an unknown credential would let core's code pass a test the real portal
    would fail it on."""

    # Set by the test class.
    calls: list = []
    answers: dict = {}
    mode = "normal"

    def log_message(self, *args) -> None:  # noqa: N802 - silence the test log
        pass

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            body = {}
        token = body.get("token", "")
        type(self).calls.append(
            {
                "path": self.path,
                "token": token,
                # The real portal takes the credential in the BODY and expects
                # no Authorization header; recorded so a test can prove core
                # does not send one (a header is what lands in access logs).
                "authorization": self.headers.get("Authorization"),
            }
        )

        if type(self).mode == "garbage":
            self._send(200, b"this is not json")
            return
        if type(self).mode == "http_500":
            self._send(500, b'{"error":"boom"}')
            return

        answer = type(self).answers.get(token)
        if answer is None:
            self._send(200, json.dumps({"active": False}).encode("utf-8"))
            return
        self._send(200, json.dumps(answer).encode("utf-8"))

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestGateScopedCredential(unittest.TestCase):
    _core: http.server.HTTPServer
    _portal: http.server.HTTPServer
    _core_url: str
    _introspect_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls._core = http.server.HTTPServer(("127.0.0.1", 0), _DecideHandler)
        cls._core_url = f"http://127.0.0.1:{cls._core.server_address[1]}"
        threading.Thread(target=cls._core.serve_forever, daemon=True).start()

        cls._portal = http.server.HTTPServer(("127.0.0.1", 0), _StubPortalHandler)
        cls._introspect_url = (
            f"http://127.0.0.1:{cls._portal.server_address[1]}/api/v1/agent/introspect"
        )
        threading.Thread(target=cls._portal.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._core.shutdown()
        cls._portal.shutdown()

    def setUp(self) -> None:
        _StubPortalHandler.calls = []
        _StubPortalHandler.mode = "normal"
        _StubPortalHandler.answers = {
            LIVE_CREDENTIAL: {
                "active": True,
                "gate_id": GATE_A,
                "org_id": "33333333-3333-4333-8333-333333333333",
                "environment": "staging",
                # Far enough out that it never shortens the cache TTL in these
                # tests; the "never cache past the credential's own deadline"
                # behaviour has its own case below.
                "expires_at": "2099-01-01T00:00:00+00:00",
            },
            OTHER_CREDENTIAL: {
                "active": True,
                "gate_id": GATE_B,
                "org_id": "33333333-3333-4333-8333-333333333333",
                "environment": "staging",
                "expires_at": "2099-01-01T00:00:00+00:00",
            },
            # DEAD_CREDENTIAL is deliberately absent -> the stub answers
            # `{"active": false}`, exactly as the real portal does for a
            # revoked, expired, unknown or revoked-gate credential.
        }
        os.environ["REEFLEX_AUTH_TOKEN"] = SHARED_TOKEN
        os.environ.pop("REEFLEX_GATE_INTROSPECTION_URL", None)
        os.environ.pop("REEFLEX_GATE_INTROSPECTION_CACHE_SECONDS", None)
        gate_credential.clear_cache()

    def tearDown(self) -> None:
        for name in (
            "REEFLEX_AUTH_TOKEN",
            "REEFLEX_GATE_INTROSPECTION_URL",
            "REEFLEX_GATE_INTROSPECTION_CACHE_SECONDS",
        ):
            os.environ.pop(name, None)
        gate_credential.clear_cache()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _opt_in(self, *, cache_seconds: str = "0") -> None:
        """Point core at the stub portal. Cache OFF by default in these tests:
        a cache is state, and state shared between test methods is how a suite
        starts depending on its own execution order. The two cache cases turn
        it on explicitly."""

        os.environ["REEFLEX_GATE_INTROSPECTION_URL"] = self._introspect_url
        os.environ["REEFLEX_GATE_INTROSPECTION_CACHE_SECONDS"] = cache_seconds
        gate_credential.clear_cache()

    def _post_decide(self, *, bearer: str | None = None, gate: str | None = None):
        payload = json.dumps(_minimal_envelope()).encode("utf-8")
        req = urllib.request.Request(
            f"{self._core_url}/v1/decide", data=payload, method="POST"
        )
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Content-Length", str(len(payload)))
        if bearer is not None:
            req.add_header("Authorization", f"Bearer {bearer}")
        if gate is not None:
            req.add_header("X-Reeflex-Gate", gate)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                return exc.code, json.loads(raw)
            except Exception:  # noqa: BLE001
                return exc.code, {"_raw": raw}

    # ------------------------------------------------------------------
    # Inert by default -- the compatibility case, first
    # ------------------------------------------------------------------

    def test_without_the_setting_a_portal_credential_is_just_a_wrong_token(self) -> None:
        """Every deployment that exists today is in this case. The credential
        is refused 401 exactly as any other unrecognised bearer would be, and
        THE PORTAL IS NEVER CALLED -- which is the part that matters, because
        it means taking this build adds no outbound traffic and no new
        dependency to anybody who has not opted in."""

        status, body = self._post_decide(bearer=LIVE_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "unauthorized"})
        self.assertEqual(_StubPortalHandler.calls, [])

    def test_with_auth_switched_off_entirely_nothing_changed_either(self) -> None:
        """`REEFLEX_AUTH_TOKEN` unset means auth disabled, and that
        short-circuits before any of this. Checked because the opposite would
        be a silent tightening of a documented backward-compatible mode."""

        os.environ.pop("REEFLEX_AUTH_TOKEN", None)
        self._opt_in()

        status, body = self._post_decide()

        self.assertEqual(status, 200)
        self.assertIn("decision", body)
        self.assertEqual(_StubPortalHandler.calls, [])

    # ------------------------------------------------------------------
    # The happy path
    # ------------------------------------------------------------------

    def test_a_live_credential_with_its_own_gate_declared_gets_a_decision(self) -> None:
        self._opt_in()

        status, body = self._post_decide(bearer=LIVE_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 200, body)
        self.assertIn("decision", body)
        self.assertEqual(len(_StubPortalHandler.calls), 1)
        call = _StubPortalHandler.calls[0]
        self.assertEqual(call["token"], LIVE_CREDENTIAL)
        self.assertTrue(call["path"].endswith("/api/v1/agent/introspect"))
        # The credential travels in the BODY. If core sent it as its own
        # Authorization header instead, an intermediary's access log would
        # record a live credential, which is the reason the portal endpoint
        # takes it in the body at all.
        self.assertIsNone(call["authorization"])

    # ------------------------------------------------------------------
    # The three refusals, each on its own
    # ------------------------------------------------------------------

    def test_a_credential_the_portal_will_not_confirm_is_401(self) -> None:
        self._opt_in()

        status, body = self._post_decide(bearer=DEAD_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "unauthorized"})

    def test_a_credential_replayed_on_another_gate_is_403_and_says_which(self) -> None:
        """THE SCOPE. `OTHER_CREDENTIAL` is live and the portal confirms it --
        for gate B. Declared as gate A it is refused, and with 403 rather than
        401 because "we know you and you are not that gate" is a different
        fact from "we do not know you"."""

        self._opt_in()

        status, body = self._post_decide(bearer=OTHER_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 403, body)
        self.assertEqual(body["reason"], "gate_mismatch")
        self.assertEqual(body["error"], "forbidden")
        # The detail helps an operator and leaks nothing: it does not name the
        # gate the credential DOES belong to, which would turn a stolen
        # credential into a way to enumerate a tenant's gates.
        self.assertNotIn(GATE_B, json.dumps(body))

        # ...and the SAME credential, declared honestly, is accepted. Without
        # this half the assertion above would also pass if every credential
        # were refused.
        status_ok, body_ok = self._post_decide(bearer=OTHER_CREDENTIAL, gate=GATE_B)
        self.assertEqual(status_ok, 200, body_ok)

    def test_a_scoped_credential_with_no_gate_declared_is_403_not_a_free_pass(self) -> None:
        """The declaration is REQUIRED, not optional. If a missing header meant
        "accepted with no scope", the scope would be advisory and an attacker
        would simply omit it."""

        self._opt_in()

        status, body = self._post_decide(bearer=LIVE_CREDENTIAL)

        self.assertEqual(status, 403, body)
        self.assertEqual(body["reason"], "gate_not_declared")
        self.assertIn("X-Reeflex-Gate", body["detail"])
        # Refused BEFORE the network call -- one of the four cheap local checks.
        self.assertEqual(_StubPortalHandler.calls, [])

    def test_an_empty_gate_header_is_the_same_as_no_gate_header(self) -> None:
        self._opt_in()
        status, body = self._post_decide(bearer=LIVE_CREDENTIAL, gate="   ")
        self.assertEqual(status, 403, body)
        self.assertEqual(body["reason"], "gate_not_declared")

    # ------------------------------------------------------------------
    # Fail closed
    # ------------------------------------------------------------------

    def test_an_unreachable_portal_refuses_rather_than_admits(self) -> None:
        """The availability coupling this design introduces, asserted in the
        direction it must fail. Port 1 on localhost is closed."""

        os.environ["REEFLEX_GATE_INTROSPECTION_URL"] = "http://127.0.0.1:1/introspect"
        os.environ["REEFLEX_GATE_INTROSPECTION_CACHE_SECONDS"] = "0"
        gate_credential.clear_cache()

        status, body = self._post_decide(bearer=LIVE_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "unauthorized"})

    def test_a_portal_answering_nonsense_refuses(self) -> None:
        self._opt_in()
        _StubPortalHandler.mode = "garbage"

        status, _body = self._post_decide(bearer=LIVE_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 401)

    def test_a_portal_answering_an_http_error_refuses(self) -> None:
        self._opt_in()
        _StubPortalHandler.mode = "http_500"

        status, _body = self._post_decide(bearer=LIVE_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 401)

    def test_active_with_no_gate_id_refuses(self) -> None:
        """A portal that says `active` without saying what the credential is
        scoped to has authenticated it and not scoped it. Refused, because
        "authenticated but unscoped" is the property this whole module exists
        to avoid."""

        self._opt_in()
        _StubPortalHandler.answers[LIVE_CREDENTIAL] = {"active": True}

        status, _body = self._post_decide(bearer=LIVE_CREDENTIAL, gate=GATE_A)

        self.assertEqual(status, 401)

    # ------------------------------------------------------------------
    # The cache
    # ------------------------------------------------------------------

    def test_a_positive_answer_is_reused_and_a_negative_one_is_not(self) -> None:
        """Both halves in one test because they are one decision.

        A cached POSITIVE keeps the round trip off the per-decision path. A
        cached NEGATIVE would break the case this feature exists for: a
        credential minted seconds ago and used immediately, where a remembered
        "no" would refuse it for the whole TTL with no way for the customer to
        know why.
        """

        self._opt_in(cache_seconds="60")

        for _ in range(3):
            status, _ = self._post_decide(bearer=LIVE_CREDENTIAL, gate=GATE_A)
            self.assertEqual(status, 200)
        self.assertEqual(len(_StubPortalHandler.calls), 1, "positive answer not cached")

        before = len(_StubPortalHandler.calls)
        for _ in range(3):
            status, _ = self._post_decide(bearer=DEAD_CREDENTIAL, gate=GATE_A)
            self.assertEqual(status, 401)
        self.assertEqual(
            len(_StubPortalHandler.calls) - before, 3, "a negative answer was cached"
        )

    def test_the_cache_never_outlives_the_credentials_own_deadline(self) -> None:
        """A credential with two seconds left must not be honoured for the
        full cache TTL -- otherwise `expires_at` is a suggestion. Asserted
        through the module's own cache rather than by sleeping, because a test
        that sleeps 60 seconds is a test that gets deleted."""

        self._opt_in(cache_seconds="600")
        gate_credential._cache_put(
            LIVE_CREDENTIAL, GATE_A, credential_expires_in=1.5
        )
        with gate_credential._cache_lock:
            _gate, expires_at = gate_credential._cache[
                gate_credential._cache_key(LIVE_CREDENTIAL)
            ]
        import time

        remaining = expires_at - time.monotonic()
        self.assertLessEqual(remaining, 1.6, remaining)

    def test_an_already_expired_credential_is_not_cached_at_all(self) -> None:
        self._opt_in(cache_seconds="600")
        gate_credential._cache_put(LIVE_CREDENTIAL, GATE_A, credential_expires_in=-5)
        self.assertIsNone(gate_credential._cache_get(LIVE_CREDENTIAL))

    def test_the_raw_credential_is_not_a_cache_key(self) -> None:
        """Not a security boundary -- anything with our memory has the request
        too -- but it makes a heap dump, a traceback `repr()` and an accidental
        log of the cache non-disclosing for free."""

        self._opt_in(cache_seconds="60")
        gate_credential._cache_put(LIVE_CREDENTIAL, GATE_A, credential_expires_in=None)
        with gate_credential._cache_lock:
            keys = list(gate_credential._cache)
        self.assertTrue(keys)
        for key in keys:
            self.assertNotIn(LIVE_CREDENTIAL, key)

    # ------------------------------------------------------------------
    # The shared token still wins, and holds routes do not accept these
    # ------------------------------------------------------------------

    def test_the_operators_own_token_is_accepted_with_no_introspection_call(self) -> None:
        """Order is the compatibility guarantee: `REEFLEX_AUTH_TOKEN` is tried
        first, needs no gate header, and costs no round trip. So an operator's
        own traffic is unaffected by the portal being reachable or not."""

        self._opt_in()

        status, body = self._post_decide(bearer=SHARED_TOKEN)

        self.assertEqual(status, 200, body)
        self.assertIn("decision", body)
        self.assertEqual(_StubPortalHandler.calls, [])

    def test_a_gate_credential_is_not_a_key_to_the_holds_routes(self) -> None:
        """The submitting role and the approving role stay apart. Same
        containment `_authorized`'s `allow_resolver_tokens` docstring argues
        for in the other direction: an approver's credential is not a key to
        `/v1/decide`, and an agent's is not a key to resolving its own holds.
        """

        self._opt_in()

        req = urllib.request.Request(f"{self._core_url}/v1/holds", method="GET")
        req.add_header("Authorization", f"Bearer {LIVE_CREDENTIAL}")
        req.add_header("X-Reeflex-Gate", GATE_A)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code

        self.assertEqual(status, 401)
        self.assertEqual(_StubPortalHandler.calls, [])

    def test_healthz_is_still_unauthenticated(self) -> None:
        self._opt_in()
        with urllib.request.urlopen(f"{self._core_url}/healthz", timeout=10) as resp:
            self.assertEqual(resp.status, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
