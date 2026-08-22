"""
test_unknown_tool_envelope.py -- RFX-206.

Every `mcp__*` tool lands in classify.py's unknown-tool branch, so that branch
is what prices a customer's database, payment processor and cluster.  It used
to return one constant for all of them: `_classify_unknown(tool_input)` took
tool_input as a parameter and referenced it in zero expressions, and never
received tool_name at all.

Measured against reeflex-core at 759b83f with the shipped policy pack, that
constant (`execute / irreversible / scoped / internal`, magnitude 1) was the
ONE variant of the envelope the pack ALLOWED in production.  Declaring `broad`
holds (R2); declaring `systemic` denies (R3); omitting the axes entirely holds
under R0.  The "safe-conservative default" was strictly worse than declaring
nothing.

MEASURED, not asserted: run against a detached worktree at the parent commit
(759b83f), **15 of the 24 tests below fail**.  The 9 that pass there fall into
two groups, and the difference matters when reading this file:

  * genuine invariant guards, which SHOULD pass on both -- `TestNothingElseMoved`
    (the diff must not move the known tools) and
    `test_the_old_floor_really_was_the_permissive_one`.
  * tests that pass on the parent VACUOUSLY, because a constant classifier
    trivially satisfies "nothing the caller says changes the price" --
    `test_saying_nothing_is_never_cheaper_than_saying_something`,
    `test_an_annotation_claiming_safety_changes_nothing`,
    `test_a_nested_structure_is_never_dumped_into_target_ref`,
    `test_magnitude_is_never_below_one`,
    `test_params_extra_cannot_displace_the_existing_params_keys`,
    `test_the_floor_never_produces_a_terminal_deny`.
    These are worth keeping -- they are the properties the fix could plausibly
    break -- but they are evidence about THIS commit, not about the parent.

THE INVARIANT THESE TESTS DEFEND -- monotone escalation.  Evidence read out of
tool_name / tool_input may only ever RAISE the price of a call.  If any of
these can be made to LOWER one, the fix has reopened RFX-165 (an agent buys a
discount by saying less) or RFX-173 (the upstream server marks its own
homework).
"""

import os
import unittest

from reeflex_claude.classify import classify
from reeflex_claude.envelope import build_envelope


_FLOOR_RISK = {
    "reversibility": "irreversible",
    "blast_radius": "broad",
}


def _c(name, tool_input=None):
    return classify(name, tool_input or {})


def _env(name, tool_input=None, environment="production"):
    old = os.environ.get("REEFLEX_CLAUDE_ENVIRONMENT")
    os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = environment
    try:
        cls = _c(name, tool_input)
        return build_envelope(
            {"session_id": "t", "tool_name": name, "tool_input": tool_input or {}},
            cls,
        )
    finally:
        if old is None:
            os.environ.pop("REEFLEX_CLAUDE_ENVIRONMENT", None)
        else:
            os.environ["REEFLEX_CLAUDE_ENVIRONMENT"] = old


class TestTheFloorIsActuallyConservative(unittest.TestCase):
    """The floor must be the value that asks a human, not the one just under it."""

    def test_an_unknown_tool_is_priced_broad_not_scoped(self):
        for name in ("mcp__db__anything", "SomeCustomTool", "Task", "", "mcp__x__y"):
            with self.subTest(name=name):
                r = _c(name, {})
                self.assertEqual(r["blast_radius"], "broad")
                self.assertEqual(r["reversibility"], "irreversible")

    def test_the_floor_never_produces_a_terminal_deny(self):
        # SPEC 4.0 (RFX-132): an action we could not price asks a human, it does
        # not refuse forever.  `systemic` is R3, which no human may clear.
        for name, ti in [
            ("mcp__db__delete_everything", {"where": "1=1"}),
            ("mcp__k8s__destroy_cluster", {"cluster": "prod"}),
            ("mcp__stripe__refund_all", {"amount": 10 ** 9, "currency": "EUR"}),
        ]:
            with self.subTest(name=name):
                self.assertNotEqual(_c(name, ti)["blast_radius"], "systemic")


class TestTheEnvelopeCarriesTheCall(unittest.TestCase):
    """Three payloads that used to be indistinguishable must now differ."""

    def test_delete_list_and_refund_are_no_longer_the_same_envelope(self):
        axes = ("verb", "reversibility", "blast_radius", "externality",
                "magnitude_count", "target_ref")
        payloads = [
            ("mcp__db__delete_production_rows", {"table": "customers", "where": "1=1"}),
            ("mcp__db__list_tables", {}),
            ("mcp__stripe__refund_all_charges", {"amount": "9999999", "currency": "EUR"}),
        ]
        seen = {tuple(_c(n, ti)[k] for k in axes) for n, ti in payloads}
        self.assertEqual(len(seen), 3, "three different calls must not price identically")

    def test_the_human_answering_the_hold_can_see_which_table(self):
        r = _c("mcp__db__delete_production_rows", {"table": "customers", "where": "1=1"})
        self.assertIsNotNone(r["target_ref"])
        self.assertIn("customers", r["target_ref"])
        self.assertIn("1=1", r["target_ref"])

    def test_a_destructive_name_is_priced_delete_so_the_budget_can_count_it(self):
        # SPEC 4.1.1: the deletions budget aggregates cumulative.count_by_verb
        # .delete.  A delete priced `execute` never lands there.
        for name in ("mcp__db__delete_row", "mcp__s3__purgeBucket",
                     "mcp__api__revoke_key", "mcp__db__truncate_table"):
            with self.subTest(name=name):
                self.assertEqual(_c(name, {})["verb"], "delete")

    def test_every_token_of_the_name_is_read_not_just_the_first(self):
        # RFX-175: reading only the leading token is how `search_and_replace`
        # gets priced as a search.
        self.assertEqual(_c("mcp__fs__search_and_destroy", {})["verb"], "delete")
        self.assertEqual(_c("mcp__x__listAndDeleteRows", {})["verb"], "delete")


class TestMoneyReachesTheMoneyBudget(unittest.TestCase):
    """SPEC 4.1.1's money dimension reads params.amount. Nothing else."""

    def test_amount_and_currency_reach_params(self):
        e = _env("mcp__stripe__refund_all_charges", {"amount": "9999999", "currency": "EUR"})
        self.assertEqual(e["params"]["amount"], 9999999.0)
        self.assertEqual(e["params"]["currency"], "EUR")

    def test_a_money_move_is_transact_and_outbound(self):
        r = _c("mcp__stripe__refund_charge", {"amount": 10, "currency": "EUR"})
        self.assertEqual(r["verb"], "transact")
        self.assertEqual(r["externality"], "outbound")

    def test_an_undeclared_amount_is_recorded_as_undeclared_not_as_zero(self):
        # RFX-133 / RFX-180: the money budget is evaded by omitting the amount.
        # We cannot invent the number, but silence must not read as zero.
        e = _env("mcp__stripe__refund_all_charges", {"currency": "EUR"})
        self.assertIs(e["params"]["amount_declared"], False)
        self.assertNotIn("amount", e["params"])

    def test_params_extra_cannot_displace_the_existing_params_keys(self):
        e = _env("mcp__stripe__refund", {"amount": 5, "currency": "EUR",
                                         "tool_name": "spoofed", "verb_source": "spoofed"})
        self.assertEqual(e["params"]["tool_name"], "mcp__stripe__refund")
        self.assertTrue(e["params"]["verb_source"].startswith("tool_name_map:"))


class TestMagnitudeReachesTheObjectsTouchedBudget(unittest.TestCase):

    def test_a_list_of_ids_sets_the_magnitude(self):
        self.assertEqual(_c("mcp__db__delete_rows", {"ids": list(range(37))})["magnitude_count"], 37)

    def test_a_declared_limit_sets_the_magnitude(self):
        self.assertEqual(_c("mcp__db__delete_rows", {"limit": 500})["magnitude_count"], 500)

    def test_magnitude_is_never_below_one(self):
        for ti in ({}, {"ids": []}, {"limit": 0}, {"limit": -5}, {"count": "not a number"}):
            with self.subTest(ti=ti):
                self.assertEqual(_c("mcp__db__delete_rows", ti)["magnitude_count"], 1)


class TestMonotoneEscalation(unittest.TestCase):
    """
    The load-bearing property.  Saying less must never be cheaper, and a name
    that claims to be harmless must not buy anything.
    """

    def test_saying_nothing_is_never_cheaper_than_saying_something(self):
        # RFX-165.  For every payload, the empty call must be at least as
        # guarded on every risk axis.
        floor = _c("mcp__db__delete_rows", {})
        for ti in [{"id": 1}, {"table": "t", "where": "id=1"}, {"ids": [1]},
                   {"limit": 1}, {"confirm": False}, {"readOnly": True},
                   {"safe": True}, {"dry_run": True}]:
            with self.subTest(ti=ti):
                r = _c("mcp__db__delete_rows", ti)
                self.assertEqual(r["reversibility"], floor["reversibility"])
                self.assertEqual(r["blast_radius"], floor["blast_radius"])
                self.assertGreaterEqual(r["magnitude_count"], floor["magnitude_count"])

    def test_a_harmless_sounding_name_is_priced_exactly_like_a_dangerous_one(self):
        # RFX-173: the upstream server does not get to mark its own homework.
        # A name can add risk; it can never subtract any.
        benign = _c("mcp__db__list_tables", {})
        for k in _FLOOR_RISK:
            self.assertEqual(benign[k], _FLOOR_RISK[k])

    def test_an_annotation_claiming_safety_changes_nothing(self):
        plain = _c("mcp__db__delete_rows", {"table": "t"})
        for claim in ({"readOnlyHint": True}, {"destructiveHint": False},
                      {"openWorldHint": False}, {"idempotent": True}):
            with self.subTest(claim=claim):
                ti = {"table": "t"}
                ti.update(claim)
                r = _c("mcp__db__delete_rows", ti)
                self.assertEqual(r["verb"], plain["verb"])
                self.assertEqual(r["reversibility"], plain["reversibility"])
                self.assertEqual(r["blast_radius"], plain["blast_radius"])


class TestRedaction(unittest.TestCase):
    """
    target_ref is transmitted to core and written to the audit log.  tool_input
    is arbitrary third-party JSON that routinely carries credentials.
    """

    def test_credential_shaped_arguments_never_reach_the_envelope(self):
        secrets = {
            "api_key": "sk-live-SHOULD-NOT-APPEAR",
            "password": "hunter2-SHOULD-NOT-APPEAR",
            "auth_token": "bearer-SHOULD-NOT-APPEAR",
            "session_cookie": "cookie-SHOULD-NOT-APPEAR",
            "private_key": "-----BEGIN-SHOULD-NOT-APPEAR",
        }
        ti = {"table": "customers"}
        ti.update(secrets)
        import json
        blob = json.dumps(_env("mcp__db__delete_rows", ti))
        self.assertNotIn("SHOULD-NOT-APPEAR", blob)
        self.assertIn("customers", blob)  # the identifying part still survives

    def test_a_nested_structure_is_never_dumped_into_target_ref(self):
        r = _c("mcp__db__insert", {"id": {"nested": "SHOULD-NOT-APPEAR"}})
        self.assertNotIn("SHOULD-NOT-APPEAR", str(r["target_ref"]))

    def test_a_list_argument_is_summarised_as_a_count_not_as_content(self):
        r = _c("mcp__db__delete_rows", {"ids": ["SHOULD-NOT-APPEAR"] * 4})
        self.assertNotIn("SHOULD-NOT-APPEAR", str(r["target_ref"]))
        self.assertIn("4", str(r["target_ref"]))

    def test_target_ref_is_bounded(self):
        r = _c("mcp__db__delete_rows", {"table": "x" * 5000, "where": "y" * 5000})
        self.assertLessEqual(len(r["target_ref"]), 200)


class TestNothingElseMoved(unittest.TestCase):
    """The known tools must be untouched -- the diff is the unknown branch only."""

    def test_known_tools_keep_their_classification(self):
        self.assertEqual(_c("Read", {"file_path": "/tmp/a"})["verb"], "read")
        self.assertEqual(_c("Bash", {"command": "ls"})["verb"], "read")
        self.assertEqual(_c("Write", {"file_path": "/tmp/new"})["verb"], "create")
        self.assertEqual(_c("Edit", {"file_path": "/tmp/a"})["verb"], "update")

    def test_known_tools_carry_no_params_extra(self):
        e = _env("Bash", {"command": "ls"})
        self.assertEqual(set(e["params"]), {"tool_name", "verb_source"})


class TestTheLocalAuditRecordSaysWhich(unittest.TestCase):
    """
    The customer-side record. "A delete was held in production" is not an
    auditable statement; "a delete against table=customers where=1=1 was held"
    is.
    """

    def test_the_audit_record_names_the_resource_and_the_count(self):
        from reeflex_claude.audit import _build_record
        e = _env("mcp__db__delete_production_rows",
                 {"table": "customers", "where": "1=1", "ids": list(range(9))})
        rec = _build_record(e, "ask", "reeflex.policy/irreversible_broad_prod",
                            "held", True, [])
        self.assertIn("customers", rec["target_ref"])
        self.assertEqual(rec["magnitude_count"], 9)

    def test_the_audit_record_carries_no_credential_material(self):
        from reeflex_claude.audit import _build_record
        import json
        e = _env("mcp__db__delete_rows",
                 {"table": "customers", "api_key": "sk-live-SHOULD-NOT-APPEAR"})
        rec = _build_record(e, "ask", "r", "held", True, [])
        self.assertNotIn("SHOULD-NOT-APPEAR", json.dumps(rec))


class TestSessionLocalBuiltinsAreNotUnknown(unittest.TestCase):
    """
    The cost of a `broad` floor is noise, and the first end-to-end run of this
    fix paid it: the agent was blocked on `ToolSearch`, not on the delete.  The
    answer is to name the first-party tools whose effect stays inside the
    session -- not to soften the floor for the third-party ones.
    """

    def test_session_local_builtins_do_not_ask_for_approval(self):
        for name in ("ToolSearch", "BashOutput", "TodoWrite", "ExitPlanMode"):
            with self.subTest(name=name):
                r = _c(name, {})
                self.assertEqual(r["verb"], "read")
                self.assertEqual(r["reversibility"], "reversible")
                self.assertEqual(r["blast_radius"], "single")

    def test_tools_that_do_whatever_they_are_asked_keep_the_floor(self):
        for name in ("Task", "SlashCommand", "Skill", "KillShell"):
            with self.subTest(name=name):
                r = _c(name, {})
                self.assertEqual(r["blast_radius"], "broad")
                self.assertEqual(r["reversibility"], "irreversible")

    def test_an_mcp_server_cannot_name_itself_into_the_builtin_list(self):
        for name in ("mcp__evil__ToolSearch", "mcp__evil__todowrite"):
            with self.subTest(name=name):
                self.assertEqual(_c(name, {})["blast_radius"], "broad")


class TestAntiVacuity(unittest.TestCase):
    """
    Guards against the suite above degenerating into "assert whatever the code
    does".  Only the first of these passes on the parent commit; the second
    fails there, because the parent emitted `danger_signature: "none"` for
    every unknown tool -- which is itself part of the finding.
    """

    def test_the_old_floor_really_was_the_permissive_one(self):
        # scoped < broad on the blast_radius ladder, and R2 reads broad.
        ladder = ["single", "scoped", "broad", "systemic"]
        self.assertLess(ladder.index("scoped"), ladder.index("broad"))

    def test_the_unknown_branch_is_where_mcp_tools_land(self):
        # If Claude Code ever grows a first-class mcp classifier, this test
        # fails and the whole file needs revisiting.
        self.assertEqual(_c("mcp__anything__at_all", {})["danger_signature"],
                         "unknown_tool")


if __name__ == "__main__":
    unittest.main()
