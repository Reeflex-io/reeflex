"""
test_credentials_rfx224.py -- the engine credential store, and the two places
that read it: `enforce` (the hook's own path) and `connect` (which writes it).

WHY A REAL LOOPBACK SERVER FOR THE `enforce` HALF. What is under test is a
REQUEST: does the Authorization header carry the stored credential, and does
`X-Reeflex-Gate` carry the gate. A test that asserted on a mocked `urlopen`
would prove the mock's shape. The stub records the headers it received, so the
assertions are about bytes on a socket.

WHAT IS DELIBERATELY NOT TESTED HERE: that core accepts the credential. That
belongs to core's own suite (`reeflex-core/tests/test_gate_credential_rfx224.py`)
and lives in a different distribution -- which is exactly the seam that let a
LiteLLM config fragment ship naming a class that did not exist (RFX-224, dev-1
round 061). So this file asserts what the CLIENT sends and stores, and says so
rather than implying more.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from reeflex_claude import credentials
from reeflex_claude.enforce import call_core_and_map

# Obvious throwaway values, NOT real secrets.
CRED_A = "rfx_ac_" + "A" * 43
CRED_B = "rfx_ac_" + "B" * 43
GATE_A = "11111111-1111-4111-8111-111111111111"
GATE_B = "22222222-2222-4222-8222-222222222222"


class _EnvSandbox:
    """Set env vars for the duration of a test and put the previous values
    back. The store's path is env-overridable for exactly this reason: a suite
    that wrote to the real `~/.reeflex` would fail differently on somebody
    else's machine, and could overwrite a credential they were using."""

    def __init__(self, **values):
        self._values = values
        self._saved = {}

    def __enter__(self):
        for key, value in self._values.items():
            self._saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return self

    def __exit__(self, *_exc):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------

class TestCredentialStore(unittest.TestCase):

    def test_the_file_is_owner_only_and_so_is_its_directory(self):
        """The whole reason this is a file and not `settings.json`. Checked as
        MODE BITS rather than by trusting `mkstemp`: the mode is set before the
        rename precisely so there is no window at the default umask, and a
        window is all a shared build box needs."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "home" / ".reeflex" / "credentials.json"
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(path)):
                written = credentials.store(
                    core_url="https://core.test", gate_id=GATE_A, token=CRED_A
                )

            self.assertEqual(written, path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_a_second_gate_does_not_evict_the_first(self):
        """One machine onboarding a staging gate and a production gate against
        the same engine is the ordinary case. A single-slot file would silently
        overwrite one with the other, and the symptom would be a 403
        `gate_mismatch` from an engine -- a long way from the cause."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(path)):
                credentials.store(
                    core_url="https://core.test", gate_id=GATE_A, token=CRED_A
                )
                credentials.store(
                    core_url="https://core.test", gate_id=GATE_B, token=CRED_B
                )

                self.assertEqual(
                    credentials.lookup(core_url="https://core.test", gate_id=GATE_A),
                    CRED_A,
                )
                self.assertEqual(
                    credentials.lookup(core_url="https://core.test", gate_id=GATE_B),
                    CRED_B,
                )

    def test_re_onboarding_the_same_gate_replaces_rather_than_appends(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(path)):
                credentials.store(
                    core_url="https://core.test", gate_id=GATE_A, token=CRED_A
                )
                credentials.store(
                    core_url="https://core.test", gate_id=GATE_A, token=CRED_B
                )
                self.assertEqual(
                    credentials.lookup(core_url="https://core.test", gate_id=GATE_A),
                    CRED_B,
                )
            body = json.loads(path.read_text())
            self.assertEqual(len(body["credentials"]), 1)
            # And the superseded value is GONE, not merely shadowed by a later
            # entry the lookup happens to find first.
            self.assertNotIn(CRED_A, path.read_text())

    def test_the_same_gate_against_two_engines_is_two_entries(self):
        """Keyed by the PAIR. One gate legitimately appears against two
        engines (a self-hosted core and the hosted one, during a migration)."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(path)):
                credentials.store(core_url="https://a.test", gate_id=GATE_A, token=CRED_A)
                credentials.store(core_url="https://b.test", gate_id=GATE_A, token=CRED_B)
                self.assertEqual(
                    credentials.lookup(core_url="https://a.test", gate_id=GATE_A), CRED_A
                )
                self.assertEqual(
                    credentials.lookup(core_url="https://b.test", gate_id=GATE_A), CRED_B
                )

    def test_storing_refuses_to_replace_a_file_it_cannot_read(self):
        """The file may hold credentials for OTHER gates that are still in
        use. Losing those to a tidy-up would brick agents this run was never
        asked about, so an unreadable store is a hard failure on WRITE."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            path.write_text("{ this is not json")
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(path)):
                with self.assertRaises(credentials.CredentialStoreError) as caught:
                    credentials.store(
                        core_url="https://core.test", gate_id=GATE_A, token=CRED_A
                    )
            self.assertIn("Refusing to replace", str(caught.exception))
            # Untouched.
            self.assertEqual(path.read_text(), "{ this is not json")

    def test_lookup_never_raises_and_answers_none(self):
        """It runs inside the PreToolUse hook, whose stdout is a JSON protocol
        and whose failure mode must be a decision, not a traceback. No
        credential means core answers 401 and `enforce` fails CLOSED, which is
        the direction a governance gate is allowed to fail in."""

        with TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope" / "credentials.json"
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(missing)):
                self.assertIsNone(
                    credentials.lookup(core_url="https://core.test", gate_id=GATE_A)
                )

            corrupt = Path(tmp) / "credentials.json"
            corrupt.write_text("not json at all")
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(corrupt)):
                self.assertIsNone(
                    credentials.lookup(core_url="https://core.test", gate_id=GATE_A)
                )

            wrong_shape = Path(tmp) / "shape.json"
            wrong_shape.write_text('{"credentials": "a string, not a list"}')
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(wrong_shape)):
                self.assertIsNone(
                    credentials.lookup(core_url="https://core.test", gate_id=GATE_A)
                )

    def test_a_locally_expired_credential_is_still_returned(self):
        """Documented and deliberate: the authority on validity is the engine,
        not this machine's clock. Dropping it here would turn a 30-second clock
        skew into "no credential at all", and the two failures look identical
        from the outside while having completely different remedies."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(path)):
                credentials.store(
                    core_url="https://core.test", gate_id=GATE_A, token=CRED_A,
                    expires_at="2000-01-01T00:00:00+00:00",
                )
                self.assertEqual(
                    credentials.lookup(core_url="https://core.test", gate_id=GATE_A),
                    CRED_A,
                )

    def test_the_non_secret_context_is_stored_and_the_secret_is_one_field(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(REEFLEX_CREDENTIALS_FILE=str(path)):
                credentials.store(
                    core_url="https://core.test", gate_id=GATE_A, token=CRED_A,
                    expires_at="2026-10-08T00:00:00+00:00",
                    portal_url="https://portal.test", gate_name="acme-prod",
                    environment="production",
                )
            entry = json.loads(path.read_text())["credentials"][0]
            self.assertEqual(entry["gate_name"], "acme-prod")
            self.assertEqual(entry["environment"], "production")
            self.assertEqual(entry["portal_url"], "https://portal.test")
            self.assertTrue(entry["written_at"])
            # The secret is in exactly one field, so a human can open this file
            # to see which credential is which without reading the value.
            carriers = [k for k, v in entry.items() if CRED_A in str(v)]
            self.assertEqual(carriers, ["token"])


# ---------------------------------------------------------------------------
# What `enforce` puts on the wire
# ---------------------------------------------------------------------------

class _RecordingCore(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *_args):
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        type(self).seen.append(
            {
                "authorization": self.headers.get("Authorization"),
                "gate": self.headers.get("X-Reeflex-Gate"),
            }
        )
        body = b'{"decision":"allow","reason":"ok","rule":"stub/allow","obligations":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestWhatEnforceSends(unittest.TestCase):

    def setUp(self):
        _RecordingCore.seen = []
        self._srv = HTTPServer(("127.0.0.1", 0), _RecordingCore)
        self._url = f"http://127.0.0.1:{self._srv.server_address[1]}"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self._srv.shutdown()

    def _decide(self):
        # A minimal envelope: what goes IN does not matter here, only the
        # headers that come out.
        return call_core_and_map({"action": {"verb": "read"}})

    def test_the_stored_credential_is_presented_and_the_gate_is_declared(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(
                REEFLEX_CREDENTIALS_FILE=str(path),
                REEFLEX_CORE_URL=self._url,
                REEFLEX_GATE_ID=GATE_A,
                REEFLEX_CORE_TOKEN=None,
            ):
                credentials.store(core_url=self._url, gate_id=GATE_A, token=CRED_A)
                decision, _reason, _rule, reachable, _obl = self._decide()

        self.assertEqual(decision, "allow")
        self.assertTrue(reachable)
        self.assertEqual(_RecordingCore.seen[0]["authorization"], f"Bearer {CRED_A}")
        self.assertEqual(_RecordingCore.seen[0]["gate"], GATE_A)

    def test_the_operators_own_token_wins_over_the_store(self):
        """An operator running their own engine keeps their own credential.
        Asserted with BOTH present, which is the only configuration in which
        the precedence is observable."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(
                REEFLEX_CREDENTIALS_FILE=str(path),
                REEFLEX_CORE_URL=self._url,
                REEFLEX_GATE_ID=GATE_A,
                REEFLEX_CORE_TOKEN="the-operators-own-not-a-secret",
            ):
                credentials.store(core_url=self._url, gate_id=GATE_A, token=CRED_A)
                self._decide()

        self.assertEqual(
            _RecordingCore.seen[0]["authorization"],
            "Bearer the-operators-own-not-a-secret",
        )
        # ...and the gate is STILL declared: it is not a secret, an engine that
        # does not care ignores it, and one that does needs it.
        self.assertEqual(_RecordingCore.seen[0]["gate"], GATE_A)

    def test_the_gate_of_one_onboarding_does_not_pick_up_anothers_credential(self):
        """The store is keyed by the pair, and `enforce` looks up by the pair.
        With a credential on file for gate B only, a hook configured for gate A
        presents NOTHING rather than gate B's -- which would be the client-side
        version of the replay core answers 403 to."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(
                REEFLEX_CREDENTIALS_FILE=str(path),
                REEFLEX_CORE_URL=self._url,
                REEFLEX_GATE_ID=GATE_A,
                REEFLEX_CORE_TOKEN=None,
            ):
                credentials.store(core_url=self._url, gate_id=GATE_B, token=CRED_B)
                self._decide()

        self.assertIsNone(_RecordingCore.seen[0]["authorization"])
        self.assertEqual(_RecordingCore.seen[0]["gate"], GATE_A)

    def test_with_no_gate_id_nothing_changed_from_before_this_feature(self):
        """The compatibility case: an agent set up by `reeflex-claude setup`
        (not `connect`) has no `REEFLEX_GATE_ID`, sends no gate header, and
        looks up no credential."""

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            with _EnvSandbox(
                REEFLEX_CREDENTIALS_FILE=str(path),
                REEFLEX_CORE_URL=self._url,
                REEFLEX_GATE_ID=None,
                REEFLEX_CORE_TOKEN=None,
            ):
                credentials.store(core_url=self._url, gate_id=GATE_A, token=CRED_A)
                self._decide()

        self.assertIsNone(_RecordingCore.seen[0]["authorization"])
        self.assertIsNone(_RecordingCore.seen[0]["gate"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
