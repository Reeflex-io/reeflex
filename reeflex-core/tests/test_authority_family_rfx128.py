"""
test_authority_family_rfx128.py — an action that changes WHO MAY ACT reaches a
human, and the hold it raises is one a human can actually clear.

RFX-128.  R1-R5 read six things and `action.ability` is not one of them, while
SPEC §3 says that field exists precisely so a policy can write fine-grained
rules.  So a whole family of harm was honestly reversible, single-entity and
internal — the adapter was not lying, the canon had nowhere to put it:

    grant a user the administrator role   -> allow / default_allow
    grant a database superuser            -> allow / default_allow
    attach an IAM policy                  -> allow / default_allow
    reset another user's password         -> allow / default_allow
    disable MFA enrolment                 -> allow / default_allow
    install a plugin (arbitrary PHP)      -> allow / default_allow

Measured 12 of 12 on a real core at main 759b83f over HTTP before this change.

WHAT THIS FILE PINS THAT THE REGO TESTS STRUCTURALLY CANNOT.
policy/authority_test.rego asserts the decision on envelopes handed straight to
OPA.  These tests run the REAL path — envelope.py's canonicalisation, then
decide.py, then the hold chain — which is where three separate classes of
defect have shipped before:

  1. R7 composes with F5 canonicalisation, so `Production` is not an evasion
     (the RFX-86 shape, one tier up).
  2. R7 IS RESOLVABLE END TO END: hold -> a human approves -> the same
     envelope resubmitted is allowed.  A rule that raises a hold nobody can
     clear is a deny wearing a hold's name, which is exactly what RFX-132
     argued core must not add.  Asserting only "it held" would not have
     caught that.
  3. R7 IS RAISE-ONLY over the whole canon: adding an authority signal to an
     ability never LOWERS a verdict.  This is the property that makes an
     admittedly incomplete, name-based list safe to ship, and it is asserted
     over a grid rather than on one example.

unittest.TestCase style on purpose: gate.py runs this suite with
`unittest discover`, which collects nothing from bare pytest functions.
"""

from __future__ import annotations

import itertools
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.decide import process  # noqa: E402

AUTHORITY_RULE = "reeflex.policy/authority_change_prod"
_POLICY_DIR = _repo_root / "policy"

_SESSION_SEQ = [0]


def _opa_available() -> bool:
    return bool(os.environ.get("REEFLEX_OPA_BIN") or shutil.which("opa"))


def _envelope(ability, verb="update", environment="production", **over):
    _SESSION_SEQ[0] += 1
    env = {
        "reeflex_version": "0.1",
        "agent": {"id": "agent:rfx128", "on_behalf_of": "user:1",
                  "session_id": "sess-rfx128-%d" % _SESSION_SEQ[0]},
        "action": {"namespace": "t", "verb": verb, "ability": ability},
        "target": {"kind": "t", "ref": "t:1", "environment": environment},
        "params": {},
        "magnitude": {"count": 1},
        "axes": {"reversibility": "reversible", "blast_radius": "single",
                 "externality": "internal"},
        "approval": {"present": False, "hold_id": None},
    }
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(env.get(k), dict):
            env[k].update(v)
        else:
            env[k] = v
    return env


class _CoreCase(unittest.TestCase):
    """Isolated holds/audit state per test, as the other core suites do."""

    def setUp(self):
        if not _opa_available():
            self.skipTest("opa binary not available")
        self._tmp = tempfile.TemporaryDirectory()
        self._prev = {k: os.environ.get(k) for k in
                      ("REEFLEX_HOLDS_PATH", "REEFLEX_AUDIT_LOG",
                       "REEFLEX_RESOLVER_TOKENS")}
        os.environ["REEFLEX_HOLDS_PATH"] = os.path.join(self._tmp.name, "holds.jsonl")
        os.environ["REEFLEX_AUDIT_LOG"] = os.path.join(self._tmp.name, "audit.jsonl")
        import app.holds as holds_mod
        holds_mod._reset(os.environ["REEFLEX_HOLDS_PATH"])

    def tearDown(self):
        for k, v in self._prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()


# ---------------------------------------------------------------------------
# 1. The family RFX-128 measured, through the real decision path.
# ---------------------------------------------------------------------------

class TestTheAuthorityFamilyReachesAHuman(_CoreCase):

    #: Each row is (label, ability, verb). Every one of these answered
    #: allow/default_allow on main 759b83f.
    FAMILY = [
        ("grant_administrator_role", "users/assign-role", "update"),
        ("grant_db_superuser", "postgres/grant_admin", "update"),
        ("attach_iam_policy", "iam/AttachUserPolicy", "update"),
        ("revoke_capability", "users/revoke-capability", "update"),
        ("add_group_member", "directory/add-group-member", "create"),
        ("reset_password", "users/reset-password", "update"),
        ("rotate_credential", "n8n/update-credential", "update"),
        ("disable_mfa", "security/disable-mfa", "update"),
        ("install_plugin", "plugins/install", "create"),
        ("activate_plugin", "plugins/activate", "update"),
        ("install_theme", "themes/install", "create"),
        ("schedule_cron", "cron/schedule-event", "create"),
    ]

    def test_every_member_of_the_family_holds(self):
        for label, ability, verb in self.FAMILY:
            with self.subTest(label):
                _, resp = process(_envelope(ability, verb=verb))
                print("\n[T_rfx128/%s] %s" % (label, json.dumps(resp)))
                self.assertEqual(resp["decision"], "require_approval", resp)
                self.assertEqual(resp["rule"], AUTHORITY_RULE, resp)

    def test_the_reason_names_the_signal_that_fired(self):
        """'a rule asked for a human' is only actionable if it says at what."""
        _, resp = process(_envelope("users/assign-role"))
        self.assertIn("role", resp["reason"])

    def test_a_non_canonical_environment_is_not_an_evasion(self):
        """R7 composes with F5. `Production` must not buy a default_allow.

        This is the RFX-86 shape one tier up: a rule that exact-matches
        `production` while the boundary hands it whatever the caller typed.
        """
        _, resp = process(_envelope("users/assign-role",
                                    environment="Production"))
        self.assertEqual(resp["rule"], AUTHORITY_RULE, resp)

    def test_an_envelope_with_no_ability_behaves_exactly_as_before(self):
        env = _envelope("placeholder")
        env["action"].pop("ability")
        _, resp = process(env)
        self.assertEqual(resp["decision"], "allow", resp)


# ---------------------------------------------------------------------------
# 2. The false-positive floor. A gate that asks on ordinary work is switched
#    off within a day, and a switched-off gate is a fail-open with extra steps.
# ---------------------------------------------------------------------------

class TestTheEverydayFloorIsUnmoved(_CoreCase):

    CONTROLS = [
        ("edit_a_post", "posts/update", "update", "production"),
        ("upload_media", "media/upload", "create", "production"),
        ("update_site_title", "core/update-option", "update", "production"),
        ("claude_code_edit", "claude-code/Edit", "update", "production"),
        ("claude_code_write", "claude-code/Write", "create", "production"),
        # production-only, exactly like R2 and R3
        ("grant_role_in_staging", "users/assign-role", "update", "staging"),
        ("install_plugin_in_dev", "plugins/install", "create", "dev"),
        # whole-token matching, not substring
        ("migrant_is_not_grant", "records/update-migrant", "update", "production"),
        ("installment_is_not_install", "billing/create-installment", "create", "production"),
        # a read cannot change who may act
        ("list_roles_is_a_read", "users/list-roles", "read", "production"),
    ]

    def test_no_control_is_held(self):
        for label, ability, verb, env in self.CONTROLS:
            with self.subTest(label):
                _, resp = process(_envelope(ability, verb=verb, environment=env))
                self.assertEqual(
                    resp["decision"], "allow",
                    "FALSE POSITIVE on %s: %s" % (label, resp))


# ---------------------------------------------------------------------------
# 3. RAISE-ONLY, over a grid rather than an example.
# ---------------------------------------------------------------------------

class TestR7IsRaiseOnly(_CoreCase):
    """Adding an authority signal to an ability must never LOWER a verdict.

    This is the property that makes an incomplete, name-based list safe to
    ship: being wrong costs an approval prompt, never a missed deny. Without
    it, `users/revoke-role` on an R3 envelope could soften a terminal refusal
    into a resolvable hold — the RFX-133 shape, a field added to buy a smaller
    answer.
    """

    #: deny is stricter than require_approval is stricter than allow.
    RANK = {"allow": 0, "require_approval": 1, "deny": 2}

    def test_adding_a_signal_never_lowers_the_verdict(self):
        grid = itertools.product(
            ["reversible", "recoverable", "irreversible"],
            ["single", "scoped", "broad", "systemic"],
            ["production", "staging", "dev"],
            ["update", "delete", "create", "execute"],
        )
        checked = 0
        for rev, blast, env, verb in grid:
            axes = {"reversibility": rev, "blast_radius": blast,
                    "externality": "internal"}
            _, plain = process(_envelope("posts/update", verb=verb,
                                         environment=env, axes=axes))
            _, signalled = process(_envelope("users/revoke-role", verb=verb,
                                             environment=env, axes=axes))
            with self.subTest(rev=rev, blast=blast, env=env, verb=verb):
                self.assertGreaterEqual(
                    self.RANK[signalled["decision"]],
                    self.RANK[plain["decision"]],
                    "signal LOWERED the verdict: %s -> %s"
                    % (plain, signalled))
            checked += 1
        # The floor: a grid that shrank to nothing would assert nothing.
        self.assertEqual(checked, 3 * 4 * 3 * 4)


# ---------------------------------------------------------------------------
# 4. The hold is one a human can actually clear.
# ---------------------------------------------------------------------------

class TestTheHoldIsResolvable(_CoreCase):

    def test_the_rule_is_not_in_non_resolvable_rules(self):
        """Asserted against server.py's real constant, not a copy of it.

        `irreversible_systemic_prod` is the ONE rule a human may not clear.
        If R7 were added there — or if the rule id in reeflex.rego drifted
        from the one the guard names — the product would have gained a second
        terminal refusal by accident.
        """
        from app.server import NON_RESOLVABLE_RULES
        self.assertNotIn(AUTHORITY_RULE.split("/", 1)[1], NON_RESOLVABLE_RULES)
        # ...and the guard still names the rule it was written for, so this
        # test cannot pass by NON_RESOLVABLE_RULES having been emptied.
        self.assertIn("irreversible_systemic_prod", NON_RESOLVABLE_RULES)

    def test_the_rule_id_reeflex_rego_emits_is_the_one_core_can_resolve(self):
        """No typo drift between the .rego string and the Python guard."""
        rego = (_POLICY_DIR / "reeflex.rego").read_text(encoding="utf-8")
        self.assertIn('"rule": "%s"' % AUTHORITY_RULE, rego)

    def test_hold_then_approve_then_resubmit_is_allowed(self):
        """WHAT THIS PROVES AND WHAT IT DOES NOT.

        It proves the DECIDE side: an R7 hold, once approved, lets the same
        envelope through. It does NOT exercise /v1/holds/{id}/resolve's own
        guard chain — `resolve_hold()` writes the state change and its
        docstring is explicit that the caller owns the validation. The
        endpoint-level walk (verified bearer token -> human principal ->
        HTTP 200 -> resubmission allowed) was run against a live core and is
        in the round's evidence, not asserted here.
        """
        from app.holds import resolve_hold

        env = _envelope("users/assign-role")
        _, held = process(env)
        self.assertEqual(held["decision"], "require_approval", held)
        hold_id = held.get("hold_id")
        self.assertTrue(hold_id, "R7 raised no hold id: %s" % held)

        # NOTE the literal: holds.resolve_hold() maps anything that is not
        # exactly "approve" to a REJECTION, while its own docstring documents
        # the argument as `"approved" | "rejected"`. Following the docstring
        # silently rejects the hold. Filed separately; pinned here so this
        # test cannot pass for that reason.
        resolved = resolve_hold(hold_id, "approve", "human",
                                "alice@example.test",
                                reason="reviewed: intentional role change",
                                verified=True)
        self.assertEqual(resolved["status"], "approved", resolved)

        approved = json.loads(json.dumps(env))
        approved["approval"] = {"present": True, "hold_id": hold_id}
        _, after = process(approved)
        print("\n[T_rfx128/resubmission] %s" % json.dumps(after))
        self.assertEqual(after["decision"], "allow", after)

    def test_a_hold_id_that_was_never_granted_buys_nothing(self):
        """The control that makes the test above mean something.

        Without it, "resubmission was allowed" is equally consistent with core
        ignoring `approval` entirely.
        """
        env = _envelope("users/assign-role")
        env["approval"] = {"present": True, "hold_id": "hold_never_granted"}
        _, resp = process(env)
        self.assertNotEqual(resp["decision"], "allow", resp)


# ---------------------------------------------------------------------------
# 5. R7 CO-FIRING WITH R6 AND R0. Added on the rebase (dev-3 round 039), not by
#    RFX-128's author: R7 was written against a tree where neither R6
#    (protected assets, #100) nor R0 (unclassified action, #106) existed.
#
#    A complete rule in Rego must produce ONE output. Two decision bodies that
#    are both true is `eval_conflict_error`, app/opa.py raises OpaEvalError, and
#    decide.py fails closed with HTTP 500 — on an envelope each rule alone gets
#    right. `opa check`, `opa test` and both unit suites all stay green over it,
#    because none of them evaluates a single envelope that satisfies two bodies.
#    So the assertion has to be the STATUS CODE on a co-firing envelope, and the
#    control has to be the same envelope against a policy tree with the guards
#    taken back out.
# ---------------------------------------------------------------------------

class TestTwoRulesCanFireAtOnceAndCoreStillAnswersOnce(_CoreCase):

    PROTECTED_RULE = "reeflex.policy/irreversible_protected_asset_prod"
    UNCLASSIFIED_RULE = "reeflex.policy/unclassified_action"

    #: Satisfies R6 and R7 simultaneously: `/srv/` is in the protected_assets
    #: shipped by #100, and `iam`, `revoke` and `role` are all authority
    #: signals. Nothing here is contrived — it is a role revocation on a
    #: production IAM store.
    def _co_firing_envelope(self, environment="production"):
        return _envelope(
            "iam/revoke-role", verb="delete",
            target={"kind": "iam_role", "ref": "/srv/prod/iam/roles.db",
                    "environment": environment},
            axes={"reversibility": "irreversible", "blast_radius": "single",
                  "externality": "internal"})

    def test_r6_and_r7_together_produce_one_decision(self):
        status, resp = process(self._co_firing_envelope())
        print("\n[T_rfx128/co-fire-r6] %d %s" % (status, json.dumps(resp)))
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["decision"], "require_approval", resp)
        # R6 wins: its reason names the operator's own declared asset.
        self.assertEqual(resp["rule"], self.PROTECTED_RULE, resp)

    def test_r0_and_r7_together_produce_one_decision(self):
        # `provenance` is core-computed and a caller-supplied block is
        # DISCARDED (envelope.py F8), and the field is REQUIRED, so the way to
        # make target.environment undeclared is an environment string core
        # cannot fold to a SPEC tier — F5 then guesses `production`
        # (_ENV_DEFAULT). That is the RFX-132 shape and a real deployment
        # spelling, not a contrivance.
        env = self._co_firing_envelope(environment="prod-eu-west-1")
        status, resp = process(env)
        print("\n[T_rfx128/co-fire-r0] %d %s" % (status, json.dumps(resp)))
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["decision"], "require_approval", resp)
        # R0 wins: a verdict resting on a field core GUESSED is reported as a
        # coverage gap, not as a control the operator configured.
        self.assertEqual(resp["rule"], self.UNCLASSIFIED_RULE, resp)

    def test_the_verdict_is_unchanged_by_which_rule_id_wins(self):
        """The guards move a rule id. They must not move a decision.

        R7 alone, R6+R7 and R0+R7 are all `require_approval`; if a guard had
        been written as a precondition rather than a tie-break, one of these
        would have become an allow.
        """
        for label, env in (
            ("r7_alone", _envelope("iam/revoke-role", verb="delete")),
            ("r6_and_r7", self._co_firing_envelope()),
        ):
            with self.subTest(label):
                _, resp = process(env)
                self.assertEqual(resp["decision"], "require_approval", resp)

    def test_without_the_two_guard_lines_core_answers_500(self):
        """The control. Without it, the three tests above are equally
        consistent with the co-firing envelope simply not co-firing.

        Copies the shipped policy dir, deletes exactly the two guard lines from
        R7's decision body, and re-runs the same envelope through the same
        process() against that tree.
        """
        scratch = os.path.join(self._tmp.name, "policy-no-guards")
        shutil.copytree(str(_POLICY_DIR), scratch)
        rego_path = os.path.join(scratch, "reeflex.rego")
        with open(rego_path, encoding="utf-8") as fh:
            src = fh.read()
        marker = ('\t"rule": "reeflex.policy/authority_change_prod",\n'
                  "} if {\n"
                  "\tr7_authority_change\n"
                  "\tnot r3_deny\n"
                  "\tnot r2_require_approval\n"
                  "\tnot budget_require_approval\n"
                  "\tnot r6_require_approval\n"
                  "\tnot r0_unclassified\n")
        self.assertIn(marker, src,
                      "R7's decision body is not where this control expects it; "
                      "the control, not the guard, needs updating")
        stripped = src.replace(
            marker,
            marker.replace("\tnot r6_require_approval\n", "")
                  .replace("\tnot r0_unclassified\n", ""))
        with open(rego_path, "w", encoding="utf-8") as fh:
            fh.write(stripped)

        prev = os.environ.get("REEFLEX_POLICY_DIR")
        os.environ["REEFLEX_POLICY_DIR"] = scratch
        try:
            status, resp = process(self._co_firing_envelope())
        finally:
            if prev is None:
                os.environ.pop("REEFLEX_POLICY_DIR", None)
            else:
                os.environ["REEFLEX_POLICY_DIR"] = prev
        print("\n[T_rfx128/control-no-guards] %d %s" % (status, json.dumps(resp)))
        self.assertEqual(status, 500, resp)
        self.assertEqual(resp["decision"], "deny", resp)


if __name__ == "__main__":
    unittest.main()
