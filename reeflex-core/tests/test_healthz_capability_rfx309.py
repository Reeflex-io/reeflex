"""
test_healthz_capability_rfx309.py — RFX-309: a core that cannot accept an
approval must stop reading as healthy.

WHAT WAS MEASURED BEFORE THE FIX (dev-1--075, on .118, on production's own
image id sha256:2f18d19f… = ghcr.io/reeflex-io/reeflex-core:v0.2.1, the image
`reeflex-core` on :8090 / api-dev.reeflex.io runs).  Two containers, SAME image,
differing in EXACTLY ONE environment variable:

    ARM 1  production's shape: REQUIRE_VERIFIED_APPROVER=true, no resolver map
             decide   -> require_approval, hold raised
             resolve  -> HTTP 403 principal_not_verified
                         (why=verification_not_configured)
             hold     -> still pending
             resubmit -> DENY / reeflex_hold_not_approved
    ARM 2  control: identical PLUS one bound approver credential
             resolve  -> HTTP 200, approved, verified=true, source=credential
             resubmit -> ALLOW

    GET /healthz on the two: BYTE-IDENTICAL, 0 differing lines.

So the deployment that cannot perform the product's central function and the
one that can were indistinguishable from outside.  That is not a hypothetical:
api-dev ran in ARM 1's configuration for eight days, 551 of the 593 holds in
its ledger ended `expired`, its last resolution was 2026-08-22 — and /healthz,
the deploy-drift check (which compares code revision) and the release gate
(which scores an artefact, not a deployment) were green for every one of them.

WHAT THESE TESTS PIN, and why each one is here rather than being implied by
the others:

  T_production_shape            the exact configuration api-dev runs reports
                                resolvable=false with the reason code the 403
                                already uses.  The regression test for the
                                measured state.
  T_bound_credentials           a deployment that binds approvers reports
                                resolvable=true and HOW MANY.  Without this the
                                fact could be a constant `false` and pass.
  T_opt_out                     REQUIRE_VERIFIED_APPROVER=false with no map is
                                resolvable but NOT verified.  "Accepted" and
                                "verified" are different facts and the block
                                must not fold them into one boolean.
  T_report_and_refusal_agree    THE STRUCTURAL ONE.  For every configuration,
                                what /healthz REPORTS and what
                                resolve_approver() actually DOES are compared by
                                EXECUTION — the invariant is "resolvable is true
                                iff some credential is in fact accepted".  A
                                health fact that re-implements the rule it
                                reports on is a model of the code, not the code,
                                and drifts from it in silence.
  T_healthz_distinguishes       the in-process replay of the measurement above:
                                two configurations, one /healthz, the bodies
                                must DIFFER.  This is the test that fails on
                                main — on main there is no `holds` key at all
                                and the two bodies are equal.
  T_live_rotation               the map is re-read per request, so a rotation
                                that drops the last binding turns the fact
                                false with no restart.  An operator who rotates
                                approvers at 3am is the likeliest way back into
                                the RFX-309 state.
  T_no_token_material           /healthz is UNAUTHENTICATED.  A boolean, a
                                reason, a setting and a COUNT — never a token,
                                never an approver identity.  This is the guard
                                against a future "improvement" that lists them.
  T_liveness_first              the block must never be what makes /healthz
                                fail: the image's HEALTHCHECK depends on it.
  T_ttl_reported                the other half of the finding — how long a hold
                                waits before it expires unanswered.

Run:
  cd reeflex-core
  python -m unittest tests.test_healthz_capability_rfx309 -v
"""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import threading
import unittest
import urllib.error
import urllib.request

from app.principal import (
    CAPABILITY_CREDENTIALS_BOUND,
    CAPABILITY_NOT_CONFIGURED,
    CAPABILITY_UNVERIFIED_ACCEPTED,
    PrincipalRefused,
    approval_capability,
    resolve_approver,
)
from app.server import _DecideHandler

# Synthetic. Never a credential of any deployment; `zz-test-` is the fleet
# convention for a string that exists only inside a test process.
_BOUND_A = "zz-test-rfx309-token-a"
_BOUND_B = "zz-test-rfx309-token-b"
_STRANGER = "zz-test-rfx309-unbound-stranger"
_APPROVER_A = "approver-a@zz-test.invalid"
_APPROVER_B = "approver-b@zz-test.invalid"

_MAP_ONE = json.dumps({_BOUND_A: {"type": "human", "id": _APPROVER_A}})
_MAP_TWO = json.dumps({
    _BOUND_A: {"type": "human", "id": _APPROVER_A},
    _BOUND_B: {"type": "human", "id": _APPROVER_B},
})

_TOKENS_ENV = "REEFLEX_RESOLVER_TOKENS"
_STRICT_ENV = "REEFLEX_REQUIRE_VERIFIED_APPROVER"
_TTL_ENV = "REEFLEX_HOLD_TTL_SECONDS"

#: The four configurations a deployment can be in, as
#: (label, strict env value or None, resolver map or None).
_CONFIGURATIONS = [
    ("production's shape: strict, no map", "true", None),
    ("strict + one bound approver", "true", _MAP_ONE),
    ("opt-out, no map (the 0.1.x behaviour)", "false", None),
    ("opt-out + one bound approver", "false", _MAP_ONE),
    ("unset (the 0.2.0 default is strict), no map", None, None),
]


def _apply(strict: str | None, mapping: str | None) -> None:
    for env, value in ((_STRICT_ENV, strict), (_TOKENS_ENV, mapping)):
        if value is None:
            os.environ.pop(env, None)
        else:
            os.environ[env] = value


class _EnvSandbox(unittest.TestCase):
    """Restores every environment variable these tests touch."""

    def setUp(self) -> None:
        self._saved = {
            k: os.environ.get(k)
            for k in (_TOKENS_ENV, _STRICT_ENV, _TTL_ENV, "REEFLEX_AUTH_TOKEN")
        }

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestApprovalCapability(_EnvSandbox):
    """The fact itself, without HTTP in the way."""

    def test_production_shape_reports_unresolvable(self) -> None:
        """strict + no map -> resolvable false, with the 403's own reason code."""
        _apply("true", None)
        cap = approval_capability()
        print("\n[T_production_shape] %s" % json.dumps(cap, sort_keys=True))
        self.assertFalse(
            cap["resolvable"],
            "a core with REQUIRE_VERIFIED_APPROVER on and no resolver map "
            "refuses every resolution; it must not report resolvable=true",
        )
        self.assertEqual(cap["reason"], CAPABILITY_NOT_CONFIGURED)
        self.assertEqual(cap["verified_approvers"], 0)
        self.assertTrue(cap["require_verified_approver"])

    def test_unset_strict_is_the_same_as_true(self) -> None:
        """Unset reads as the 0.2.0 default (strict), so it is equally unresolvable."""
        _apply(None, None)
        cap = approval_capability()
        print("\n[T_production_shape/unset] %s" % json.dumps(cap, sort_keys=True))
        self.assertFalse(cap["resolvable"])
        self.assertEqual(cap["reason"], CAPABILITY_NOT_CONFIGURED)

    def test_bound_credentials_report_resolvable_and_how_many(self) -> None:
        """A deployment that binds approvers says so, and says how many."""
        _apply("true", _MAP_TWO)
        cap = approval_capability()
        print("\n[T_bound_credentials] %s" % json.dumps(cap, sort_keys=True))
        self.assertTrue(cap["resolvable"])
        self.assertEqual(cap["reason"], CAPABILITY_CREDENTIALS_BOUND)
        self.assertEqual(
            cap["verified_approvers"], 2,
            "the count is what makes a map that silently shrank visible",
        )

    def test_opt_out_is_resolvable_but_not_verified(self) -> None:
        """Accepted and verified are different facts; the block keeps them apart."""
        _apply("false", None)
        cap = approval_capability()
        print("\n[T_opt_out] %s" % json.dumps(cap, sort_keys=True))
        self.assertTrue(
            cap["resolvable"],
            "with the opt-out set, an asserted approver IS accepted -- the "
            "approval path is open, it is merely unverified",
        )
        self.assertEqual(cap["reason"], CAPABILITY_UNVERIFIED_ACCEPTED)
        self.assertFalse(cap["require_verified_approver"])
        self.assertEqual(cap["verified_approvers"], 0)

    # ------------------------------------------------------------------
    # The structural test: the report and the refusal, compared by running
    # both rather than by reading both.
    # ------------------------------------------------------------------

    def test_report_and_refusal_never_disagree(self) -> None:
        """`resolvable` is true IFF some credential is in fact accepted.

        Derivation checked by execution.  If a later change moves the rule in
        resolve_approver() -- a fourth state, a different default, a new env --
        and does not move approval_capability() with it, this fails here
        instead of on a customer's deployment eight days later.
        """
        rows = []
        for label, strict, mapping in _CONFIGURATIONS:
            _apply(strict, mapping)
            cap = approval_capability()

            # Ask the real decision function: is there ANY credential it
            # accepts as an approver? Every bound token, plus a stranger.
            candidates = [_STRANGER]
            if mapping:
                candidates = list(json.loads(mapping).keys()) + [_STRANGER]

            accepted: list[str] = []
            refusals: dict[str, str] = {}
            for bearer in candidates:
                bound = json.loads(mapping).get(bearer) if mapping else None
                asserted_id = bound["id"] if bound else _APPROVER_A
                try:
                    # stderr is redirected because the opt-out path WARNs by
                    # design; the warning is asserted elsewhere, not here.
                    with contextlib.redirect_stderr(io.StringIO()):
                        resolve_approver(bearer, "human", asserted_id)
                    accepted.append(bearer)
                except PrincipalRefused as exc:
                    refusals[bearer] = exc.remedy.get("why", exc.error)

            actually_resolvable = bool(accepted)
            rows.append((label, cap["resolvable"], actually_resolvable,
                         cap["reason"], sorted(set(refusals.values()))))

            self.assertEqual(
                cap["resolvable"], actually_resolvable,
                "%s: /healthz reports resolvable=%s but resolve_approver() "
                "accepted %d of %d credentials (refusals: %s). The health fact "
                "and the code that decides have drifted apart."
                % (label, cap["resolvable"], len(accepted), len(candidates),
                   refusals),
            )
            if not actually_resolvable:
                self.assertIn(
                    cap["reason"], set(refusals.values()),
                    "%s: the reason /healthz gives (%r) is not one the refusal "
                    "itself gives (%r) -- an operator greps one word across "
                    "both surfaces" % (label, cap["reason"], refusals),
                )

        print("\n[T_report_and_refusal_agree]")
        for label, reported, actual, reason, whys in rows:
            print("  %-46s reported=%-5s actual=%-5s reason=%-30s refusals=%s"
                  % (label, reported, actual, reason, whys))


class TestHealthzBlock(_EnvSandbox):
    """The fact as a customer/operator/monitor actually reads it: one GET."""

    _srv: http.server.HTTPServer
    _base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        # /healthz is unauthenticated either way; popping the token keeps this
        # class independent of whatever else ran first.
        os.environ.pop("REEFLEX_AUTH_TOKEN", None)
        cls._srv = http.server.HTTPServer(("127.0.0.1", 0), _DecideHandler)
        cls._base_url = "http://127.0.0.1:%d" % cls._srv.server_address[1]
        threading.Thread(target=cls._srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._srv.shutdown()

    def _healthz(self) -> tuple[int, dict]:
        req = urllib.request.Request("%s/healthz" % self._base_url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    @staticmethod
    def _comparable(body: dict) -> str:
        """The body minus the two fields that differ for reasons unrelated to
        capability: the per-process ledger epoch and the live pending gauge."""
        d = json.loads(json.dumps(body))
        if isinstance(d.get("ledger"), dict):
            d["ledger"]["epoch_id"] = "<per-process>"
        if isinstance(d.get("server"), dict):
            d["server"]["pending"] = "<gauge>"
        return json.dumps(d, sort_keys=True, indent=1)

    def test_healthz_distinguishes_the_two_deployments(self) -> None:
        """The in-process replay of the .118 measurement: the bodies must differ.

        On main this fails: there is no `holds` key, so a core that can approve
        and a core that cannot serve the same bytes.
        """
        _apply("true", None)
        status_1, body_1 = self._healthz()
        _apply("true", _MAP_ONE)
        status_2, body_2 = self._healthz()

        print("\n[T_healthz_distinguishes]")
        print("  cannot approve -> %s" % json.dumps(body_1.get("holds"), sort_keys=True))
        print("  can approve    -> %s" % json.dumps(body_2.get("holds"), sort_keys=True))

        self.assertEqual(status_1, 200)
        self.assertEqual(status_2, 200)
        self.assertNotEqual(
            self._comparable(body_1), self._comparable(body_2),
            "a deployment that refuses every approval and one that accepts "
            "them must not serve identical /healthz bodies -- that is the "
            "whole of RFX-309",
        )
        self.assertFalse(body_1["holds"]["resolvable"])
        self.assertTrue(body_2["holds"]["resolvable"])

    def test_healthz_tracks_a_live_rotation(self) -> None:
        """The map is read per request, so dropping the last binding shows up."""
        _apply("true", _MAP_ONE)
        _, before = self._healthz()
        _apply("true", json.dumps({}))  # a rotation that emptied the map
        _, after = self._healthz()
        print("\n[T_live_rotation] before=%s after=%s"
              % (json.dumps(before["holds"], sort_keys=True),
                 json.dumps(after["holds"], sort_keys=True)))
        self.assertTrue(before["holds"]["resolvable"])
        self.assertFalse(
            after["holds"]["resolvable"],
            "an emptied resolver map leaves the deployment unable to approve; "
            "no restart intervenes, so neither may the report",
        )

    def test_healthz_discloses_no_token_material(self) -> None:
        """Unauthenticated route: a boolean, a reason, a setting, a count."""
        _apply("true", _MAP_TWO)
        _, body = self._healthz()
        raw = json.dumps(body)
        print("\n[T_no_token_material] holds=%s"
              % json.dumps(body["holds"], sort_keys=True))
        for secret in (_BOUND_A, _BOUND_B, _APPROVER_A, _APPROVER_B):
            self.assertNotIn(
                secret, raw,
                "/healthz is unauthenticated and must never carry token "
                "material or approver identities; found %r" % secret,
            )
        self.assertEqual(
            set(body["holds"]),
            {"resolvable", "reason", "require_verified_approver",
             "verified_approvers", "ttl_seconds"},
            "the holds block's shape is a wire fact operators and the deploy "
            "check read; adding to it is a decision, not an accident",
        )

    def test_healthz_reports_the_ttl_a_hold_waits(self) -> None:
        """How long an unanswered hold has before it expires."""
        _apply("true", None)
        os.environ.pop(_TTL_ENV, None)
        _, default_body = self._healthz()
        os.environ[_TTL_ENV] = "900"
        _, set_body = self._healthz()
        print("\n[T_ttl_reported] default=%s configured=%s"
              % (default_body["holds"]["ttl_seconds"],
                 set_body["holds"]["ttl_seconds"]))
        self.assertEqual(
            default_body["holds"]["ttl_seconds"], 4 * 3600,
            "api-dev sets no TTL, so the 4h default is the window its holds "
            "expire in; the report must show the value actually in force",
        )
        self.assertEqual(set_body["holds"]["ttl_seconds"], 900)

    def test_healthz_stays_200_and_unauthenticated(self) -> None:
        """Liveness first: the image's HEALTHCHECK depends on this route."""
        os.environ["REEFLEX_AUTH_TOKEN"] = "zz-test-rfx309-operator"
        try:
            _apply("true", "{not json at all")  # a malformed map, on purpose
            status, body = self._healthz()
            print("\n[T_liveness_first] status=%s holds=%s"
                  % (status, json.dumps(body.get("holds"), sort_keys=True)))
            self.assertEqual(
                status, 200,
                "a broken resolver map must not take the liveness probe down",
            )
            self.assertEqual(body.get("status"), "ok")
            self.assertFalse(
                body["holds"]["resolvable"],
                "a map core cannot parse binds no credential, so the honest "
                "report is the same one an absent map gets -- not resolvable",
            )
        finally:
            os.environ.pop("REEFLEX_AUTH_TOKEN", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
