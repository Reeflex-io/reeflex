"""
test_principal_verification.py — RFX-CORE-2: the four-eyes guarantee.

Regression guard for the bypass where `POST /v1/holds/{id}/resolve` took the
approving principal from the REQUEST BODY and recorded it as fact. Confirmed
live on api-dev v0.1.13 with the published eval token
(scripts/attack-probe-rfx-core-2.py):

  A1  one credential raised a hold as `agent:dev-1-synthetic-attacker`, approved
      it as `human:leo.david`, and rode the approval to `allow` on an
      irreversible + broad + production action.  Recorded
      decided_by: "human:leo.david".
  A2  an envelope with no `agent.id` (SPEC §2 does not require one) made the
      actor_is_approver check vacuous -- it compared against "".
  A3  agent.id "svc-bot" approved itself as "SVC-BOT": raw `==` missed it, and
      so did decide.py's check 6 on resubmission.  Verdict: allow.
  A4  the approver was `user:alice`, the very principal the agent declared it
      was acting on behalf of -- self-approval at one remove.

These tests exercise the units (app/principal.py) plus the two comparison sites
that consume them, without needing a live server or OPA.

unittest.TestCase style on purpose: gate.py runs this suite with
`unittest discover`, which collects nothing from bare pytest functions.
"""

from __future__ import annotations

import os
import unittest

from app import principal
from app.principal import (
    PrincipalRefused,
    actor_identities,
    is_self_approval,
    normalize_identity,
    principal_for_token,
    resolve_approver,
)

_ENV_KEYS = ("REEFLEX_RESOLVER_TOKENS", "REEFLEX_REQUIRE_VERIFIED_APPROVER")


class _EnvIsolated(unittest.TestCase):
    """Save/restore the two env vars this module reads, per test."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _envelope(agent_id=None, on_behalf_of=None, session_id="sess-1"):
    agent = {"session_id": session_id}
    if agent_id is not None:
        agent["id"] = agent_id
    if on_behalf_of is not None:
        agent["on_behalf_of"] = on_behalf_of
    return {"agent": agent}


class TestIdentityNormalization(unittest.TestCase):

    def test_case_and_whitespace_fold(self):
        for raw in ("svc-bot", "SVC-BOT", "  Svc-Bot  ", "sVc-BoT\n"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_identity(raw), "svc-bot")

    def test_invisible_characters_fold(self):
        # A zero-width space / BOM inside an id is invisible in a log line,
        # which is exactly what made it useful for slipping past a raw `==`.
        self.assertEqual(normalize_identity("svc​bot"), "svcbot")
        self.assertEqual(normalize_identity("﻿svc-bot"), "svc-bot")

    def test_non_strings_are_unusable_not_crashing(self):
        for raw in (None, 12, [], {}, True):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_identity(raw), "")


class TestActorIdentitySet(unittest.TestCase):

    def test_all_three_actor_fields_are_disqualified(self):
        ids = actor_identities(_envelope(
            agent_id="agent:cursor", on_behalf_of="user:alice",
            session_id="sess-42",
        ))
        for expected in ("agent:cursor", "cursor", "user:alice", "alice",
                         "sess-42"):
            self.assertIn(expected, ids)

    def test_session_id_is_the_fallback_when_agent_id_absent(self):
        # A2: SPEC §2 does not require agent.id, so the guard must not become
        # vacuous for a conformant adapter that omits it.
        ids = actor_identities(_envelope(agent_id=None, session_id="sess-42"))
        self.assertEqual(ids, {"sess-42"})

    def test_malformed_agent_is_empty_not_an_exception(self):
        self.assertEqual(actor_identities({}), set())
        self.assertEqual(actor_identities({"agent": "not-a-dict"}), set())
        self.assertEqual(actor_identities({"agent": {}}), set())


class TestSelfApprovalDetection(unittest.TestCase):
    """The four live attacks, at the comparison that should have caught them."""

    def test_a3_case_variant_of_the_same_identity_is_caught(self):
        env = _envelope(agent_id="svc-bot")
        self.assertTrue(is_self_approval(env, "human", "SVC-BOT"))
        self.assertTrue(is_self_approval(env, "human", "  svc-bot  "))
        self.assertTrue(is_self_approval(env, "human", "Svc-Bot"))

    def test_a3_invisible_character_variant_is_caught(self):
        env = _envelope(agent_id="svcbot")
        self.assertTrue(is_self_approval(env, "human", "svc​bot"))

    def test_a4_approving_as_the_human_the_agent_acts_for_is_caught(self):
        env = _envelope(agent_id="agent:cursor", on_behalf_of="user:alice")
        self.assertTrue(is_self_approval(env, "human", "user:alice"))
        self.assertTrue(is_self_approval(env, "human", "alice"))

    def test_a2_session_identity_is_caught_when_agent_id_absent(self):
        env = _envelope(agent_id=None, session_id="sess-42")
        self.assertTrue(is_self_approval(env, "human", "sess-42"))

    def test_type_prefixed_and_bare_forms_both_match(self):
        env = _envelope(agent_id="agent:cursor")
        self.assertTrue(is_self_approval(env, "agent", "cursor"))
        self.assertTrue(is_self_approval(env, "human", "agent:cursor"))

    def test_a_genuinely_different_human_is_not_a_self_approval(self):
        # The guard must still let a real second pair of eyes through.
        env = _envelope(agent_id="agent:cursor", on_behalf_of="user:alice")
        for approver in ("bob", "user:bob", "leo.david", "carol@example.com"):
            with self.subTest(approver=approver):
                self.assertFalse(is_self_approval(env, "human", approver))


class TestCredentialBinding(_EnvIsolated):

    TOKENS = (
        '{"tok-alice": {"type": "human", "id": "alice@example.com"},'
        ' "tok-bob":   {"type": "human", "id": "bob@example.com"}}'
    )

    def test_unconfigured_means_no_token_verifies(self):
        self.assertIsNone(principal_for_token("tok-alice"))

    def test_configured_token_maps_to_its_principal(self):
        os.environ["REEFLEX_RESOLVER_TOKENS"] = self.TOKENS
        self.assertEqual(
            principal_for_token("tok-alice"),
            {"type": "human", "id": "alice@example.com"},
        )
        self.assertIsNone(principal_for_token("tok-nope"))
        self.assertIsNone(principal_for_token(""))
        self.assertIsNone(principal_for_token(None))

    def test_malformed_map_yields_no_bindings(self):
        for raw in ("not json", "[]", '"a string"', '{"tok": "not-an-object"}',
                    '{"tok": {"type": "", "id": ""}}', '{"": {"type":"h","id":"i"}}'):
            with self.subTest(raw=raw):
                os.environ["REEFLEX_RESOLVER_TOKENS"] = raw
                self.assertIsNone(principal_for_token("tok"))

    def test_verified_principal_comes_from_the_credential(self):
        os.environ["REEFLEX_RESOLVER_TOKENS"] = self.TOKENS
        got = resolve_approver("tok-alice", "human", "alice@example.com")
        self.assertEqual(got["id"], "alice@example.com")
        self.assertTrue(got["verified"])
        self.assertEqual(got["source"], "credential")

    def test_a1_asserting_someone_elses_identity_is_refused(self):
        # The core of the live A1 attack: the caller names a human it is not.
        os.environ["REEFLEX_RESOLVER_TOKENS"] = self.TOKENS
        with self.assertRaises(PrincipalRefused) as ctx:
            resolve_approver("tok-alice", "human", "leo.david")
        self.assertEqual(ctx.exception.error, "principal_mismatch")

    def test_a1_unbound_credential_is_refused_once_binding_is_configured(self):
        os.environ["REEFLEX_RESOLVER_TOKENS"] = self.TOKENS
        with self.assertRaises(PrincipalRefused) as ctx:
            resolve_approver("some-other-token", "human", "leo.david")
        self.assertEqual(ctx.exception.error, "principal_not_verified")

    def test_case_variant_of_the_bound_identity_is_accepted_as_itself(self):
        # Not an attack: the caller IS alice, spelled differently. The
        # authoritative value written to the record is still the bound one.
        os.environ["REEFLEX_RESOLVER_TOKENS"] = self.TOKENS
        got = resolve_approver("tok-alice", "human", "ALICE@EXAMPLE.COM")
        self.assertEqual(got["id"], "alice@example.com")
        self.assertTrue(got["verified"])


class TestTypeIsJudgedOnTheBoundPrincipal(_EnvIsolated):
    """A caller may not borrow a principal TYPE it is not bound to.

    The resolution-policy check necessarily runs before verification (the
    asserted type is all that exists that early), so it is re-asserted on the
    authoritative type afterwards -- otherwise a credential bound as `agent`
    could clear a human-only rule by writing `"type": "human"`.
    """

    def test_bound_type_wins_over_the_asserted_type(self):
        os.environ["REEFLEX_RESOLVER_TOKENS"] = \
            '{"tok-bot": {"type": "agent", "id": "triage-bot"}}'
        # Same id, borrowed type: verification accepts it as itself...
        got = resolve_approver("tok-bot", "human", "triage-bot")
        # ...but reports the BOUND type, which is what the policy re-check sees.
        self.assertEqual(got["type"], "agent")
        self.assertEqual(got["id"], "triage-bot")
        self.assertTrue(got["verified"])


class TestStrictMode(_EnvIsolated):

    def test_strict_mode_refuses_an_unverifiable_approver(self):
        os.environ["REEFLEX_REQUIRE_VERIFIED_APPROVER"] = "true"
        with self.assertRaises(PrincipalRefused) as ctx:
            resolve_approver("any-token", "human", "leo.david")
        self.assertEqual(ctx.exception.error, "principal_not_verified")

    def test_strict_mode_accepts_a_verified_approver(self):
        os.environ["REEFLEX_REQUIRE_VERIFIED_APPROVER"] = "true"
        os.environ["REEFLEX_RESOLVER_TOKENS"] = \
            '{"tok-alice": {"type": "human", "id": "alice"}}'
        got = resolve_approver("tok-alice", "human", "alice")
        self.assertTrue(got["verified"])

    def test_strict_flag_parsing(self):
        for raw, expected in (("true", True), ("TRUE", True), ("1", True),
                              ("yes", True), ("false", False), ("", False),
                              ("nope", False)):
            with self.subTest(raw=raw):
                os.environ["REEFLEX_REQUIRE_VERIFIED_APPROVER"] = raw
                self.assertIs(principal.strict_mode(), expected)


class TestUnverifiedIsRecordedAsUnverified(_EnvIsolated):
    """The default path still resolves -- but never claims verification.

    This is the anti-laundering property: an unverified assertion must be
    distinguishable, downstream, from a real human decision. RFX-74 is what
    happens when it is not.
    """

    def test_default_path_marks_the_approver_unverified(self):
        got = resolve_approver("any-token", "human", "leo.david")
        self.assertEqual(got["id"], "leo.david")
        self.assertFalse(got["verified"])
        self.assertEqual(got["source"], "asserted")

    def test_hold_record_and_audit_carry_the_provenance(self):
        import tempfile
        from app import holds

        with tempfile.TemporaryDirectory() as tmp:
            holds._reset(os.path.join(tmp, "holds.jsonl"))
            try:
                rec = holds.create_hold(
                    {"action": {"verb": "delete"}, "agent": {"id": "agent:x"}},
                    "reeflex.policy/irreversible_broad_prod",
                )
                # Present from creation, conservative.
                self.assertIs(rec["decided_by_verified"], False)

                unverified = holds.resolve_hold(
                    rec["id"], "approve", "human", "leo.david",
                    verified=False, principal_source="asserted",
                )
                self.assertEqual(unverified["decided_by"], "human:leo.david")
                self.assertIs(unverified["decided_by_verified"], False)
                self.assertEqual(unverified["principal_source"], "asserted")

                rec2 = holds.create_hold(
                    {"action": {"verb": "delete"}, "agent": {"id": "agent:x"}},
                    "reeflex.policy/irreversible_broad_prod",
                )
                verified = holds.resolve_hold(
                    rec2["id"], "approve", "human", "alice",
                    verified=True, principal_source="credential",
                )
                self.assertIs(verified["decided_by_verified"], True)
                self.assertEqual(verified["principal_source"], "credential")
            finally:
                holds._reset(None)

    def test_decided_by_wire_shape_is_unchanged(self):
        # The frozen "{type}:{id}" contract the CLI, dashboard and Attest parse
        # must not move -- the provenance is additive, not a reformatting.
        import tempfile
        from app import holds

        with tempfile.TemporaryDirectory() as tmp:
            holds._reset(os.path.join(tmp, "holds.jsonl"))
            try:
                rec = holds.create_hold({"action": {"verb": "delete"}},
                                        "reeflex.policy/x")
                out = holds.resolve_hold(rec["id"], "approve", "human", "leo")
                self.assertEqual(out["decided_by"], "human:leo")
            finally:
                holds._reset(None)


class TestResubmissionCheckSix(unittest.TestCase):
    """decide.py check 6 must refuse the same self-approvals as resolve time.

    A3 rode all the way to `allow` because check 6 was also a raw `==`.
    """

    def _validate(self, envelope, decided_by):
        import tempfile
        from app import decide, holds

        with tempfile.TemporaryDirectory() as tmp:
            holds._reset(os.path.join(tmp, "holds.jsonl"))
            try:
                rec = holds.create_hold(envelope, "reeflex.policy/x")
                holds.resolve_hold(
                    rec["id"], "approve",
                    *decided_by.split(":", 1),
                )
                resubmitted = dict(envelope)
                resubmitted["approval"] = {"present": True, "hold_id": rec["id"]}
                # canonical_hash covers {action, axes, magnitude, target} only,
                # so adding `approval` keeps the hash matching (SPEC §5.1).
                return decide._validate_approval(resubmitted)
            finally:
                holds._reset(None)

    def _envelope_full(self, agent_id=None, on_behalf_of=None):
        env = {
            "action": {"namespace": "t", "verb": "delete", "ability": "t/x"},
            "target": {"kind": "k", "environment": "production"},
            "magnitude": {"count": 1},
            "axes": {"reversibility": "irreversible",
                     "blast_radius": "broad", "externality": "internal"},
        }
        env.update(_envelope(agent_id=agent_id, on_behalf_of=on_behalf_of))
        return env

    def test_a3_case_variant_is_now_refused_on_resubmission(self):
        _, resp, _ = self._validate(
            self._envelope_full(agent_id="svc-bot"), "human:SVC-BOT")
        self.assertIsNotNone(resp)
        self.assertEqual(resp["reason"], "reeflex_hold_actor_is_approver")

    def test_a4_on_behalf_of_is_now_refused_on_resubmission(self):
        _, resp, _ = self._validate(
            self._envelope_full(agent_id="agent:cursor",
                                on_behalf_of="user:alice"),
            "human:user:alice")
        self.assertIsNotNone(resp)
        self.assertEqual(resp["reason"], "reeflex_hold_actor_is_approver")

    def test_a_real_second_human_still_passes(self):
        code, resp, hold = self._validate(
            self._envelope_full(agent_id="agent:cursor"), "human:bob")
        self.assertEqual(code, 0, "a genuine approver must not be refused: %r" % (resp,))
        self.assertIsNone(resp)


if __name__ == "__main__":
    unittest.main()
