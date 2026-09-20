"""
test_healthz_revision_rfx89.py — RFX-89 (core half): a core that will not say
what build it is cannot be watched by anything without shell access.

WHAT WAS MEASURED BEFORE THIS CHANGE (dev-1--185, 2026-09-20T05:25Z, one
unauthenticated GET against https://api-dev.reeflex.io — the production core):

    top-level /healthz keys: status, ledger, holds, server
    no key containing "revision", "version", "build" or "commit"

    docker inspect reeflex-core (read-only, on .118)
      org.opencontainers.image.revision = e175e4e527bf361ae510839f04021614...

So the commit WAS known to the image and knowable only with shell access to
the VM — which is RFX-89's sentence, "a product that sells auditability cannot
say what it is running", and the mechanism by which api-dev's ~34-day drift
(RFX-88) was invisible to every automated surface we had.

AND THE CONSEQUENCE, MEASURED ON THE MACHINE BUILT TO CATCH IT. reeflex-app
ships a daily deploy-drift job (RFX-90). Pointed at the production core it
answers:

    DEPLOY-DRIFT: FAIL (the deployment reports no build revision (`revision`
    absent or empty on /healthz), so it cannot be compared to any commit —
    this is drift by default, not a pass)

...every day, unfixably, which is why that workflow's closing comment
deliberately does NOT wire api-dev in. The one deployment whose drift is the
reason the checker exists is the one it cannot watch.

WHAT THESE TESTS PIN, and why each is here rather than implied by the others:

  T_absent_when_unset       a build that was not told its commit serves NO
                            `revision` key. The consumer reads absent as
                            DRIFT; a fabricated or defaulted value would be a
                            self-report that lies, which is worse than none.
  T_unsubstituted_build_arg the literal shapes a careless build leaves behind
                            (`$GIT_SHA`, `unknown`, `HEAD`, `""`) are refused.
                            Without this the drift checker reports "revision
                            $GIT_SHA is not a commit in this repository" and
                            sends the reader hunting for a lost branch instead
                            of for a build step that forgot an argument.
  T_served_when_set         the honest case, and the proof this is not a
                            constant absence that would pass T_absent forever.
  T_the_two_bodies_differ   the structural one: a build that says what it is
                            and one that does not must be TELLABLE APART from
                            outside. This is the test that fails on main,
                            where both bodies are equal.
  T_discloses_nothing_else  /healthz is unauthenticated. Adding build identity
                            must add build identity and nothing else — no
                            framework version, no Python version, no hostname,
                            no path (RFX-89 requirement 3).
  T_not_core_version        `revision` must not be CORE_VERSION. That string
                            read "0.1.13" across v0.1.13, v0.1.14, v0.1.15 AND
                            main, so serving it would answer the question with
                            a value that cannot distinguish two builds — the
                            defect wearing the fix's clothes.
"""

import json
import os
import threading
import unittest
import urllib.error
import urllib.request

from app.buildinfo import REVISION_ENV, build_revision
from app.server import _DecideHandler

# Synthetic, and never a commit in this repository: these tests assert the
# SHAPE core serves, not that any particular commit exists.
_SHA_FULL = "a" * 40
_SHA_SHORT = "abc1234"


class _RevisionSandbox(unittest.TestCase):
    """Restores every environment variable these tests touch."""

    def setUp(self) -> None:
        self._saved = {
            k: os.environ.get(k) for k in (REVISION_ENV, "REEFLEX_AUTH_TOKEN")
        }

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @staticmethod
    def _set(value) -> None:
        if value is None:
            os.environ.pop(REVISION_ENV, None)
        else:
            os.environ[REVISION_ENV] = value


class TestBuildRevision(_RevisionSandbox):
    """app.buildinfo.build_revision() — the value, before it is served."""

    def test_absent_when_unset(self) -> None:
        self._set(None)
        self.assertEqual(build_revision(), "")

    def test_unsubstituted_build_arg_is_refused(self) -> None:
        """Every one of these is what a real build leaves behind when the
        `--build-arg GIT_SHA=` is forgotten, mistyped, or expanded by a shell
        that does not have the variable."""
        for junk in ("", "   ", "$GIT_SHA", "${GIT_SHA}", "unknown", "HEAD",
                     "main", "v0.2.2", "not-a-sha", "g" * 40, "abc", "0" * 41):
            self._set(junk)
            self.assertEqual(
                build_revision(), "",
                "REEFLEX_BUILD_REVISION=%r was served as if it were a commit" % junk,
            )

    def test_a_git_object_name_is_accepted_at_both_lengths(self) -> None:
        for good in (_SHA_FULL, _SHA_SHORT, "0123456789abcdef"):
            self._set(good)
            self.assertEqual(build_revision(), good)

    def test_case_and_whitespace_are_normalised_not_rejected(self) -> None:
        """`docker build --build-arg` and a deploy script's `$(git rev-parse)`
        both routinely carry a trailing newline; an uppercase sha is still a
        sha. Refusing these would turn an honest build into a silent DRIFT."""
        self._set("  %s\n" % _SHA_FULL.upper())
        self.assertEqual(build_revision(), _SHA_FULL)

    def test_it_is_not_core_version(self) -> None:
        """The specific wrong fix. CORE_VERSION is a release string, is
        version-stable across builds by construction, and answering RFX-89
        with it would look fixed and measure nothing."""
        from app._version import CORE_VERSION

        self._set(None)
        self.assertEqual(build_revision(), "")
        self.assertNotEqual(build_revision(), CORE_VERSION)
        # and it is not silently coerced into one either
        self._set(CORE_VERSION)
        self.assertEqual(
            build_revision(), "",
            "a version string was accepted as a commit: %r" % CORE_VERSION,
        )


class TestHealthzRevision(_RevisionSandbox):
    """The fact as an operator, an auditor or a monitor reads it: one GET."""

    _srv: "object"
    _base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        import http.server

        # /healthz is unauthenticated either way; popping the token keeps this
        # class independent of whatever else ran first.
        os.environ.pop("REEFLEX_AUTH_TOKEN", None)
        cls._srv = http.server.HTTPServer(("127.0.0.1", 0), _DecideHandler)
        cls._base_url = "http://127.0.0.1:%d" % cls._srv.server_address[1]
        threading.Thread(target=cls._srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._srv.shutdown()

    def _healthz(self):
        req = urllib.request.Request("%s/healthz" % self._base_url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_absent_when_the_build_did_not_say(self) -> None:
        self._set(None)
        status, body = self._healthz()
        print("\n[T_absent_when_unset] top-level keys: %s" % sorted(body))
        self.assertEqual(status, 200)
        self.assertNotIn("revision", body)
        # still a liveness probe: absence must not cost the 200 the image's
        # own HEALTHCHECK depends on.
        self.assertEqual(body.get("status"), "ok")

    def test_served_when_the_build_said(self) -> None:
        self._set(_SHA_FULL)
        status, body = self._healthz()
        print("[T_served_when_set] revision=%s" % body.get("revision"))
        self.assertEqual(status, 200)
        self.assertEqual(body.get("revision"), _SHA_FULL)

    def test_the_two_deployments_are_tellable_apart(self) -> None:
        """THE STRUCTURAL ONE. On main both bodies are equal and no check
        without shell access can distinguish a build that names its commit
        from one that does not. This is what makes api-dev watchable."""
        self._set(None)
        _s1, silent = self._healthz()
        self._set(_SHA_FULL)
        _s2, speaking = self._healthz()
        print("[T_tellable_apart] silent=%s speaking=%s"
              % (sorted(silent), sorted(speaking)))
        self.assertNotEqual(
            json.dumps(silent, sort_keys=True),
            json.dumps(speaking, sort_keys=True),
            "a core that names its build and one that does not are "
            "indistinguishable on /healthz — RFX-89 unfixed",
        )
        self.assertEqual(set(speaking) - set(silent), {"revision"})

    def test_it_discloses_the_commit_and_nothing_else(self) -> None:
        """/healthz is unauthenticated (server.py: 'always unauthenticated').
        RFX-89 requirement 3: the git sha only — core already scrubs its
        Server banner and this must not undo that."""
        import platform
        import sys

        self._set(_SHA_FULL)
        _status, body = self._healthz()
        blob = json.dumps(body)
        for leak in (sys.version.split()[0], platform.python_implementation(),
                     platform.node(), os.getcwd()):
            if not leak:
                continue
            self.assertNotIn(
                leak, blob,
                "/healthz leaked %r alongside the build revision" % leak,
            )

    def test_an_unsubstituted_build_arg_reaches_nobody(self) -> None:
        """End to end, not just at build_revision(): the literal `$GIT_SHA`
        must not appear on the wire."""
        self._set("$GIT_SHA")
        _status, body = self._healthz()
        self.assertNotIn("revision", body)
        self.assertNotIn("GIT_SHA", json.dumps(body))


if __name__ == "__main__":
    unittest.main(verbosity=2)
