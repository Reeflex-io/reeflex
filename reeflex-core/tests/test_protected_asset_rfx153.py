"""
test_protected_asset_rfx153.py — R6: an irreversible destruction of a NAMED
production asset reaches a human, at any cardinality (RFX-153).

THE DEFECT
==========
`blast_radius` is a CARDINALITY axis. R2 requires `broad`, R3 requires
`systemic`, so

    irreversible + production + single   -> no rule but R4 default_allow
    irreversible + production + scoped   -> the same

and `rm /srv/prod/db.sqlite` — one production database, unrecoverable — was
ALLOWED with no human.  Reproduced against a real core built from main
44c6f85; see scripts/attack-probe-rfx153-protected-asset.py, which is the
end-to-end witness over HTTP.  This file is the in-suite guard, and it drives
the REAL decide.process() path (envelope -> validate -> ledger -> OPA eval),
same discipline as test_decide.py and test_budgets_rfx11.py.  No mocking of
OPA: a Rego bug has to be able to fail these.

FOUR THINGS ARE PINNED, AND THE LAST TWO ARE WHY THIS FILE IS LONG
==================================================================
1. THE HOLD.  Five ground-truth shapes reach `require_approval` under
   `reeflex.policy/irreversible_protected_asset_prod`, including two the
   adapter classifies as `execute` rather than `delete` — R6 reads neither the
   verb nor the cardinality on purpose.

2. THE EVASIONS.  R6 compares a caller-supplied path by PREFIX, which is the
   exact shape of RFX-86 (`environment` compared exactly, "Prod" fell to
   default_allow).  Eight spellings of ONE protected file must all land on the
   same verdict, or the fix shipped a sixth instance of the class
   field_treatments.py exists to close.

3. THE COST.  A fix that also holds `rm /tmp/scratch.txt` is not a fix — the
   adapter defaults `target.environment` to production, so a naive rule turns
   every `rm` a coding agent issues into an approval prompt, and a gate that
   asks on that is switched off within a day (RFX-145 from the other side).
   Seven cases pin what the operator's attention is NOT spent on.

4. THE NON-REGRESSION, WHICH IS THE STRONGEST CLAIM HERE.  R6 sits LAST among
   the holds, so it can only ever convert an ALLOW into a hold: no existing
   deny, no existing hold and no existing rule id moves when protected.rego is
   added.  An auditor diffing a pre- and post-RFX-153 build sees additions and
   nothing else.  test_r6_never_renames_an_existing_verdict is that claim.

Run:
  cd reeflex-core
  python -m unittest tests.test_protected_asset_rfx153 -v
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import uuid

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

import app.ledger as ledger_mod
from app.envelope import ValidationError, canonicalize_target_ref, validate_and_fill_defaults
from app.decide import process
from app.field_treatments import TREATMENTS

R6_RULE = "reeflex.policy/irreversible_protected_asset_prod"
R2_RULE = "reeflex.policy/irreversible_broad_prod"
R3_RULE = "reeflex.policy/irreversible_systemic_prod"
R1_RULE = "reeflex.policy/read_only_internal"
R4_RULE = "reeflex.policy/default_allow"
R5_RULE = "reeflex.policy/cumulative_budget"
R5_DELETE_RULE = "reeflex.policy/session_delete_budget"

#: The reference asset.  Every evasion case is this same file respelled.
ASSET = "/srv/prod/db.sqlite"


def _fresh_session() -> str:
    return f"rfx153_sess_{uuid.uuid4().hex[:12]}"


def _envelope(
    *,
    ref,
    session_id: str | None = None,
    verb: str = "delete",
    reversibility: str = "irreversible",
    blast_radius: str = "single",
    environment: str = "production",
    externality: str = "internal",
    ability: str = "bash/rm",
    count: int = 1,
) -> dict:
    """An Action Envelope in the shape the Claude Code adapter emits."""
    return {
        "reeflex_version": "0.1",
        "agent": {
            "id": "agent:claude-code",
            "on_behalf_of": "user:synthetic",
            "session_id": session_id or _fresh_session(),
        },
        "action": {"namespace": "shell", "verb": verb, "ability": ability},
        "target": {"kind": "command", "ref": ref, "environment": environment},
        "params": {},
        "magnitude": {"count": count},
        "axes": {
            "reversibility": reversibility,
            "blast_radius": blast_radius,
            "externality": externality,
        },
        "approval": {"present": False},
        "context": {},
        "meta": {
            "timestamp": "2026-08-22T00:00:00Z",
            "nonce": uuid.uuid4().hex,
            "signature": "ed25519:skeleton_placeholder",
        },
    }


def _decide(**kw) -> dict:
    status, resp = process(_envelope(**kw))
    assert status == 200, (status, resp)
    return resp


# ---------------------------------------------------------------------------
# 1. THE HOLD — the shapes that used to reach R4
# ---------------------------------------------------------------------------

class TestNamedProductionAssetIsHeld(unittest.TestCase):

    def test_single_named_production_database_is_held(self) -> None:
        """`rm /srv/prod/db.sqlite` — the RFX-153 headline. Was default_allow."""
        resp = _decide(ref=ASSET)
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_scoped_is_covered_too_not_just_single(self) -> None:
        """The gap is the whole low half of the cardinality axis.

        R2 starts at `broad`, so `scoped` was in the hole with `single`. A fix
        that only special-cased `single` would leave `rm -r <4 files>` open.
        """
        resp = _decide(
            ref="/var/lib/postgresql/16/main/base", blast_radius="scoped", count=4,
        )
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_the_verb_is_not_read_so_a_misclassified_verb_cannot_evade(self) -> None:
        """A truncate-by-redirect and a `dd` are `execute`, and destroy just
        as completely.

        RFX-144 measured the adapter mispricing verbs wholesale. R6 must not
        inherit that: it reads reversibility, environment and the declared
        asset, and nothing else.
        """
        for verb, ability in (("execute", "bash/redirect"), ("execute", "bash/dd"),
                              ("update", "bash/tee")):
            with self.subTest(verb=verb, ability=ability):
                resp = _decide(ref=ASSET, verb=verb, ability=ability)
                self.assertEqual(resp["decision"], "require_approval", resp)
                self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_a_hold_and_not_a_deny(self) -> None:
        """R6 is require_approval, deliberately.

        The whole cost argument for a non-empty default protect-list rests on
        the worst case being ONE approval prompt. A deny on a false positive
        would make the floor indefensible.
        """
        resp = _decide(ref=ASSET)
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertIn("declared production asset", resp["reason"])


# ---------------------------------------------------------------------------
# 2. THE EVASIONS — one file, eight spellings (F9 + the lowered compare)
# ---------------------------------------------------------------------------

class TestPrefixComparisonCannotBeEvaded(unittest.TestCase):
    """R6 compares a caller-supplied path by prefix.

    RFX-86 is what this class exists to not repeat: `target.environment` was
    compared exactly and "Prod" fell through to default_allow. Every case here
    is the SAME FILE as ASSET.
    """

    EVASIONS = {
        "dot_dot_resolving_back_in": "/srv/prod/../prod/db.sqlite",
        "doubled_leading_separator": "//srv/prod/db.sqlite",
        "dot_segments_and_inner_double": "/srv/./prod//db.sqlite",
        "trailing_space": "/srv/prod/db.sqlite ",
        "leading_space": "  /srv/prod/db.sqlite",
        "uppercase_prefix": "/SRV/prod/db.sqlite",
        "zero_width_space_in_prefix": "/srv\u200b/prod/db.sqlite",
        "trailing_newline": "/srv/prod/db.sqlite\n",
    }

    def test_every_spelling_of_the_protected_asset_is_held(self) -> None:
        for name, ref in self.EVASIONS.items():
            with self.subTest(name=name, ref=ref):
                resp = _decide(ref=ref)
                self.assertEqual(
                    resp["decision"], "require_approval",
                    f"{name}: {ref!r} spelled its way out of R6 -> {resp}",
                )
                self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_a_dot_dot_that_walks_OUT_is_honestly_not_protected(self) -> None:
        """Normalisation is identity-preserving, so it works both ways.

        `/srv/prod/../../etc/hosts` IS `/etc/hosts`, which is not a declared
        asset. Holding it would mean the canonicalisation had invented a
        protection the operator never declared — the same dishonesty in the
        other direction.
        """
        resp = _decide(ref="/srv/prod/../../etc/hosts")
        self.assertEqual(resp["decision"], "allow", resp)
        self.assertEqual(resp["rule"], R4_RULE, resp)

    def test_relabelling_the_verb_read_does_not_buy_back_the_allow(self) -> None:
        """R1 (read + internal) must not outrank R6.

        R1's two conditions are both caller-asserted, so if R1 won, one field
        would undo R6 — the same `verb: "read"` on a delete that SPEC §3
        already cross-checks for. An irreversible action is never read-only.
        """
        resp = _decide(ref=ASSET, verb="read", ability="bash/cat")
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_a_container_ref_is_refused_not_silently_unmatched(self) -> None:
        """`{"ref": ["/srv/prod/db.sqlite"]}` must not become an R6 evasion.

        A list matches no prefix. Coercing it to None would too. So it is a
        structural refusal (HTTP 400), the same treatment F2/F3 give a
        wrong-typed magnitude or session_id.
        """
        for bad in ([ASSET], {"path": ASSET}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    validate_and_fill_defaults(_envelope(ref=bad))


class TestCanonicalizeTargetRefUnit(unittest.TestCase):
    """F9 in isolation — the parts the E2E cases cannot show."""

    def test_identity_preserving_normalisations(self) -> None:
        cases = {
            "/srv/prod/../prod/db.sqlite": "/srv/prod/db.sqlite",
            "//srv/prod/db.sqlite": "/srv/prod/db.sqlite",
            "/srv/./prod//db.sqlite": "/srv/prod/db.sqlite",
            "/srv/prod/db.sqlite ": "/srv/prod/db.sqlite",
            "/srv/prod/db.sqlite\n": "/srv/prod/db.sqlite",
            "/srv\u200b/prod/db.sqlite": "/srv/prod/db.sqlite",
            "src/old_module.py": "src/old_module.py",
            "post:1481": "post:1481",
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(canonicalize_target_ref(raw), want)

    def test_case_is_NOT_folded(self) -> None:
        """This value lands in the audit record and the envelope_hash preimage.

        /srv/Prod/db and /srv/prod/db are two different files on Linux;
        folding case here would make the evidence name a file that was never
        touched. The case-insensitive compare R6 needs happens on a lowercased
        COPY, in protected.rego.
        """
        self.assertEqual(canonicalize_target_ref("/SRV/Prod/DB.sqlite"),
                         "/SRV/Prod/DB.sqlite")

    def test_uri_shaped_refs_are_not_path_normalised(self) -> None:
        """posixpath.normpath would rewrite s3://b/k to s3:/b/k.

        That mangles the identifier in the audit record to save a comparison
        nobody asked for. Stated limit: a URI ref is compared as written apart
        from Unicode/whitespace folding.
        """
        self.assertEqual(canonicalize_target_ref("s3://acme-prod/db.tar "),
                         "s3://acme-prod/db.tar")
        self.assertEqual(canonicalize_target_ref("k8s://prod//pod-1"),
                         "k8s://prod//pod-1")

    def test_null_and_scalars(self) -> None:
        self.assertIsNone(canonicalize_target_ref(None))
        self.assertEqual(canonicalize_target_ref(1481), "1481")
        self.assertEqual(canonicalize_target_ref(""), "")

    def test_absent_ref_stays_absent(self) -> None:
        """Adding a null `ref` key would change canonical_hash()'s preimage for
        every envelope that never had one, silently breaking the join between
        an existing hold and its resubmission."""
        env = _envelope(ref=None)
        del env["target"]["ref"]
        self.assertNotIn("ref", validate_and_fill_defaults(env)["target"])

    def test_target_ref_is_a_declared_field(self) -> None:
        """The enumeration is the point (field_treatments.py). A rule that
        reads an undeclared caller-supplied field is the defect class itself."""
        self.assertIn("target.ref", TREATMENTS)
        self.assertEqual(TREATMENTS["target.ref"].kind, "canonicalise")
        self.assertTrue(TREATMENTS["target.ref"].unverifiable_assertion)


# ---------------------------------------------------------------------------
# 3. THE COST — what the operator's attention is NOT spent on
# ---------------------------------------------------------------------------

class TestTheFixIsNotBoughtWithEveryRm(unittest.TestCase):
    """A rule that also holds `rm /tmp/scratch.txt` is not a fix.

    The adapter defaults target.environment to production, so "irreversible +
    production, any cardinality" would prompt on every delete a coding agent
    issues. These are the cases that must stay `allow`.
    """

    def test_scratch_and_working_tree_deletes_stay_allowed(self) -> None:
        cases = {
            "tmp_scratch_file": dict(ref="/tmp/scratch.txt"),
            "relative_source_file": dict(ref="src/old_module.py"),
            "var_tmp_under_var": dict(ref="/var/tmp/build-8891.log"),
            "build_cache_scoped": dict(ref="node_modules/.cache",
                                       blast_radius="scoped", count=9),
            "home_dotfile": dict(ref="/home/dev/.bash_history"),
            "absent_ref": dict(ref=None),
        }
        for name, kw in cases.items():
            with self.subTest(name=name):
                resp = _decide(**kw)
                self.assertEqual(
                    resp["decision"], "allow",
                    f"{name} was held — the fix is being bought with the "
                    f"operator's attention: {resp}",
                )

    def test_var_tmp_is_not_caught_by_a_var_prefix(self) -> None:
        """The protect-list is not a top-level-directory list.

        /var/lib is production state and /var/tmp is designated temporary, and
        both sit under /var. A `/var/` entry would have been the lazy version
        of this list and it would have held every build log.
        """
        held = _decide(ref="/var/lib/postgresql/16/main/base/1")
        allowed = _decide(ref="/var/tmp/build-8891.log")
        self.assertEqual(held["rule"], R6_RULE, held)
        self.assertEqual(allowed["decision"], "allow", allowed)

    def test_the_same_asset_outside_production_is_allowed(self) -> None:
        for environment in ("dev", "staging"):
            with self.subTest(environment=environment):
                resp = _decide(ref=ASSET, environment=environment)
                self.assertEqual(resp["decision"], "allow", resp)

    def test_a_recoverable_action_on_a_protected_asset_is_allowed(self) -> None:
        """R6 is about irreversibility, not about touching a protected path.

        `mv /srv/prod/db.sqlite /srv/prod/db.sqlite.bak` is a backup, and a
        rule that held it would be a rule about paths rather than about risk.
        """
        resp = _decide(ref=ASSET, verb="update", reversibility="recoverable",
                       ability="bash/mv")
        self.assertEqual(resp["decision"], "allow", resp)

    def test_a_genuine_read_of_a_protected_asset_still_hits_r1(self) -> None:
        resp = _decide(ref="/srv/prod", verb="read", reversibility="reversible",
                       ability="bash/ls")
        self.assertEqual(resp["decision"], "allow", resp)
        self.assertEqual(resp["rule"], R1_RULE, resp)


# ---------------------------------------------------------------------------
# 4. THE NON-REGRESSION — R6 can only ever convert an ALLOW
# ---------------------------------------------------------------------------

class TestR6OnlyConvertsAnAllow(unittest.TestCase):
    """The strongest claim in this file.

    R6 sits LAST among the holds in reeflex.rego. It could have gone above R5
    — both produce require_approval, so only the reported `rule` differs — and
    last was chosen so that no pre-existing verdict is RENAMED. The rule id is
    what an Attest report and an auditor read, so a new rule that steals an
    existing verdict changes the evidence even when the decision letter does
    not move.
    """

    def test_r6_never_renames_an_existing_verdict(self) -> None:
        # R3: deny outranks everything, on a protected asset.
        deny = _decide(ref="/srv/prod", blast_radius="systemic",
                       ability="postgres/drop-database")
        self.assertEqual(deny["decision"], "deny", deny)
        self.assertEqual(deny["rule"], R3_RULE, deny)

        # R2: broad, on a protected asset, still reported as R2.
        broad = _decide(ref="/srv/prod/data", blast_radius="broad", count=40)
        self.assertEqual(broad["decision"], "require_approval", broad)
        self.assertEqual(broad["rule"], R2_RULE, broad)

    def test_r5_keeps_its_rule_id_on_a_protected_asset(self) -> None:
        """A budget hold on a protected asset is still reported as the budget.

        This is the case that decided R6's precedence: one irreversible
        count=21 delete on a protected asset trips R5's `deletions` dimension
        (default limit 20) AND satisfies R6, so both fire and only precedence
        decides which rule id the audit line carries. R5 must keep it.
        """
        session = _fresh_session()
        ledger_mod.clear_session(session)
        resp = _decide(ref=ASSET, session_id=session, count=21)
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R5_DELETE_RULE, resp)
        self.assertIn("delete budget", resp["reason"])

    def test_a_non_delete_budget_also_keeps_its_rule_id(self) -> None:
        """The other R5 rule id, on the same protected asset."""
        session = _fresh_session()
        ledger_mod.clear_session(session)
        resp = _decide(ref=ASSET, session_id=session, count=201,
                       verb="update", ability="bash/tee")
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R5_RULE, resp)
        self.assertIn("objects_touched", resp["reason"])

    def test_exactly_one_decision_is_still_produced(self) -> None:
        """Totality (SPEC §5). Adding a rule to a precedence chain is the way
        that invariant gets broken, so it is asserted rather than assumed."""
        shapes = [
            dict(ref=ASSET),
            dict(ref=ASSET, blast_radius="broad"),
            dict(ref=ASSET, blast_radius="systemic"),
            dict(ref=ASSET, verb="read", reversibility="reversible"),
            dict(ref="/tmp/x"),
            dict(ref=None),
            dict(ref=ASSET, environment="dev"),
        ]
        for kw in shapes:
            with self.subTest(**kw):
                resp = _decide(**kw)
                self.assertIn(resp["decision"],
                              ("allow", "deny", "require_approval"), resp)
                self.assertTrue(resp["rule"].startswith("reeflex.policy/"), resp)


# ---------------------------------------------------------------------------
# 4b. R0 (RFX-132) vs R6 — WHICH RULE ID IS THE HONEST ONE
#
# R6 was written against a tree where R0 did not exist; #106 landed it while
# this branch was open, at the TOP of the precedence chain. R0 says "the
# verdict rests on a value core GUESSED"; R6's id says "the operator declared
# this path production state and the adapter declared the action
# irreversible". Only one of those can be the label on a given decision, and
# R0's is the weaker, truer one — so R6 yields.
#
# The reachable case is narrow and it is the whole reason this section exists:
# a protected ref with a DECLARED low cardinality and an UNRECOGNISED
# target.environment. F5 coerces an environment outside the SPEC enum to the
# most-guarded tier, `production` — so `environment: "qa-eu"` reaches R6 as
# production, R2 and R3 never fire because the cardinality is `single`, and R6
# would otherwise raise a hold whose reason asserts a declaration that never
# happened.
#
# NOTE ON WHAT "GUESSED" MEANS HERE, because the obvious reading is wrong and
# cost this test class a rewrite: `target.environment` cannot be OMITTED —
# core answers `400 envelope.target.environment is required`, so an absent
# environment never reaches a rule at all. `_environment_is_declared` judges
# the VALUE: undeclared means "not a string, or a token outside _ENV_CANON".
# The axes are the other way round: `axes: {}` is a valid envelope and each
# missing axis is filled by _AXIS_DEFAULTS.
# ---------------------------------------------------------------------------

R0_RULE = "reeflex.policy/unclassified_action"


def _envelope_omitting(*paths: str, **kw) -> dict:
    """A well-formed envelope with specific dotted paths REMOVED.

    Provenance is what R0 reads, and it is computed from what the caller did
    not send — so these cases cannot be expressed by passing a value. Only
    top-level and one-level-nested paths are needed here.
    """
    env = _envelope(**kw)
    for path in paths:
        head, _, tail = path.partition(".")
        if tail:
            env.get(head, {}).pop(tail, None)
        else:
            env.pop(head, None)
    return env


def _decide_omitting(*paths: str, **kw) -> dict:
    status, resp = process(_envelope_omitting(*paths, **kw))
    assert status == 200, (status, resp)
    return resp


class TestR0OutranksR6(unittest.TestCase):
    """Two rules that can both match one call, and the reason code that is true."""

    def test_r0_outranks_r6_when_environment_was_guessed(self) -> None:
        # "qa-eu" is #106's own example of an environment core cannot place.
        # F5 coerces it to `production`, which is what R6 then reads.
        resp = _decide(ref=ASSET, environment="qa-eu")
        # The DECISION is the same either way — a human is asked. What moves is
        # the rule id, which is what an Attest report and an auditor read.
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R0_RULE, resp)
        # And the reason must name the field, or "the classifier is not keeping
        # up" is not actionable (#106's own requirement, applied to this path).
        self.assertIn("target.environment", resp["reason"], resp)

    def test_an_absent_environment_or_verb_is_refused_not_guessed(self) -> None:
        """The premise this class was first written on, kept as the record of
        why it is wrong.

        `target.environment` and `action.verb` are REQUIRED fields: omitting
        either is a 400, so an absent one can never be the input a rule fires
        on. For those two, "core guessed" means the caller sent a value core
        does not recognise and F5/F6 coerced it. Only the axes can genuinely be
        absent. Pinned because the distinction is the difference between
        testing R0 and testing the request validator.
        """
        for path in ("target.environment", "action.verb"):
            with self.subTest(path=path):
                status, resp = process(_envelope_omitting(path, ref=ASSET))
                self.assertEqual(status, 400, resp)
                self.assertIn(path, resp["detail"], resp)

    def test_r6_keeps_its_own_rule_id_when_the_adapter_declared_everything(self) -> None:
        """The other direction. Without this, R0 could swallow R6 entirely and
        the ticket's own fix would report as somebody else's coverage gap."""
        resp = _decide(ref=ASSET, environment="production")
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_a_guessed_blast_radius_alone_does_not_downgrade_r6(self) -> None:
        """R0's input set is PER RULE, not global.

        R6 deliberately does not read `axes.blast_radius` — cardinality is the
        axis that was wrong about a named production asset in the first place —
        so a guess at it cannot be what produced an R6 verdict. This is the
        same discipline #106 applied when it excluded `axes.externality` and
        `action.verb` from R2/R3's set.

        Omitting blast_radius defaults it to `systemic`, which makes R3 fire,
        which routes to R0 by #106's OWN first clause. So the observable claim
        here is the one that is actually reachable: the verdict is R0 because
        R3 was reached on a guess, and it is NOT a terminal deny.
        """
        resp = _decide_omitting("axes.blast_radius", ref=ASSET)
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R0_RULE, resp)
        self.assertIn("axes.blast_radius", resp["reason"], resp)

    def test_an_unclassifiable_action_on_a_protected_ref_is_not_a_deny(self) -> None:
        """RFX-132's headline shape, aimed at a protected path. R6 must not
        reintroduce the terminal refusal #106 removed."""
        resp = _decide_omitting("axes", ref=ASSET, environment="production")
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R0_RULE, resp)

    def test_r6_hold_is_resolvable_by_a_human(self) -> None:
        """R6 MANUFACTURES holds, so #105's flip is what decides whether they
        can ever be cleared. `irreversible_systemic_prod` is terminal by
        design; a protected-asset hold is the opposite — it exists to be
        answered. If R6's id ever lands in NON_RESOLVABLE_RULES, every
        `rm /srv/prod/db.sqlite` becomes an unclearable refusal, which is the
        RFX-132 defect wearing this ticket's rule id.
        """
        from app.server import NON_RESOLVABLE_RULES
        short = R6_RULE.split("/", 1)[1]
        self.assertNotIn(short, NON_RESOLVABLE_RULES)
        self.assertIn("irreversible_systemic_prod", NON_RESOLVABLE_RULES)


class TestPrecedenceIsTotalAcrossTheGrid(unittest.TestCase):
    """The failure mode a rule-ordering change actually has.

    Rego `decision` is a COMPLETE rule: if two bodies are simultaneously true
    with different values, OPA does not pick one — it raises
    `eval_conflict_error`, and core answers 500 on a call it used to decide
    correctly. That is strictly worse than a wrong rule id, and it is invisible
    to any test that only checks the cases it thought of.

    R0's new R6 clause is exactly the kind of edit that opens one: before it,
    R0 could only fire on top of R2/R3, both of which R5 already excluded, so
    R5 needed no R0 guard. After it, R0 can fire with neither — and a
    fragmentation budget can be tripped by the very same call.
    """

    #: The concrete conflict the R5 guard closes: protected ref, environment
    #: GUESSED (so R0 fires via its R6 clause) and count over the deletions
    #: budget (so R5's body is true too). Both bodies true, two different
    #: rule ids, one complete rule.
    def test_the_r5_and_r0_overlap_does_not_error(self) -> None:
        session = _fresh_session()
        ledger_mod.clear_session(session)
        status, resp = process(_envelope(
            ref=ASSET, environment="qa-eu", session_id=session, count=21))
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["decision"], "require_approval", resp)
        # R0 wins: the verdict rests on a guessed environment either way.
        self.assertEqual(resp["rule"], R0_RULE, resp)

    def test_precedence_is_total_across_the_grid(self) -> None:
        # Only the AXES can be absent from a valid envelope. `target.environment`
        # and `action.verb` are required fields, so for those two "undeclared"
        # is an unrecognised VALUE and belongs in the value dimensions below.
        omissions = ((), ("axes.blast_radius",), ("axes.reversibility",),
                     ("axes",), ("axes.externality",))
        refs = (ASSET, "/srv/prod", "/tmp/scratch.txt", "src/x.py", None,
                "/var/tmp/b.log", "/SRV/prod/db.sqlite")
        radii = ("single", "scoped", "broad", "systemic")
        counts = (1, 21, 201)
        # "production" declared, and "qa-eu" coerced to production on a guess —
        # the two sides of the R0-vs-R6 question, across the whole grid.
        environments = ("production", "qa-eu")
        # "frobnicate" is #106's own example of a verb nobody aliased.
        verbs = ("delete", "frobnicate")

        seen_rules: set[str] = set()
        checked = 0
        for omit in omissions:
            for ref in refs:
                for radius in radii:
                    for count in counts:
                        for env in environments:
                            for verb in verbs:
                                session = _fresh_session()
                                ledger_mod.clear_session(session)
                                kw = dict(ref=ref, blast_radius=radius,
                                          count=count, environment=env,
                                          verb=verb, session_id=session)
                                with self.subTest(omit=omit, ref=ref,
                                                  radius=radius, count=count,
                                                  env=env, verb=verb):
                                    status, resp = process(
                                        _envelope_omitting(*omit, **kw))
                                    # A 500 here IS eval_conflict_error.
                                    self.assertEqual(status, 200, resp)
                                    self.assertIn(
                                        resp["decision"],
                                        ("allow", "deny", "require_approval"),
                                        resp)
                                    self.assertTrue(
                                        resp["rule"].startswith(
                                            "reeflex.policy/"), resp)
                                    seen_rules.add(resp["rule"])
                                    checked += 1

        # A grid that never reaches the new rules would pass while proving
        # nothing, so assert the grid is not vacuous.
        self.assertGreaterEqual(checked, 500, checked)
        for required in (R0_RULE, R6_RULE, R2_RULE, R3_RULE, R4_RULE):
            self.assertIn(required, seen_rules, sorted(seen_rules))


# ---------------------------------------------------------------------------
# 5. THE POSTURE SWITCH — proved to move a decision (unlike RFX-145's STRICT)
# ---------------------------------------------------------------------------

class TestDefaultProtectedIsPolicyNotPython(unittest.TestCase):
    """`default_protected := true` flips the floor's coverage limit away.

    RFX-145 is the cautionary case: REEFLEX_CLAUDE_STRICT is the adapter's only
    documented tightening knob and it is decision-inert for all 16 allows. A
    knob that changes no decision is worse than no knob, because the docs
    promise a control that does not exist. So this test does what that one
    could not: ONE unchanged envelope, two postures, two different decisions,
    with ZERO Python changes — the flip comes from editing a Rego data file.
    """

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="rfx153-policy-")
        self._tmp_policy_dir = pathlib.Path(self._tmpdir) / "policy"
        shutil.copytree(_repo_root / "policy", self._tmp_policy_dir)

        path = self._tmp_policy_dir / "protected.rego"
        text = path.read_text(encoding="utf-8")
        edited = text.replace("default_protected := false",
                              "default_protected := true")
        self.assertNotEqual(text, edited,
                            "expected the posture literal to be present")
        path.write_text(edited, encoding="utf-8")

        self._orig = os.environ.get("REEFLEX_POLICY_DIR")
        os.environ["REEFLEX_POLICY_DIR"] = str(self._tmp_policy_dir)

    def tearDown(self) -> None:
        if self._orig is None:
            os.environ.pop("REEFLEX_POLICY_DIR", None)
        else:
            os.environ["REEFLEX_POLICY_DIR"] = self._orig
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_an_undeclared_path_is_held_under_the_strict_posture(self) -> None:
        """`rm /home/app/data/customers.db` — the floor's blind spot.

        Under the default posture this allows, and that is the honest coverage
        limit of an FHS-derived floor. Under the strict posture it holds.
        """
        resp = _decide(ref="/home/app/data/customers.db")
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_an_absent_ref_is_held_under_the_strict_posture(self) -> None:
        """An adapter that cannot name what it is destroying is the case a
        human should see, not the case that slips through."""
        resp = _decide(ref=None)
        self.assertEqual(resp["decision"], "require_approval", resp)
        self.assertEqual(resp["rule"], R6_RULE, resp)

    def test_declared_ephemeral_paths_are_still_allowed(self) -> None:
        """The strict posture is survivable only because it has an escape.

        Without `ephemeral_assets` it would hold every `rm /tmp/*` and be
        switched off in a day — the same failure mode as the naive fix.
        """
        for ref in ("/tmp/scratch.txt", "/var/tmp/build.log",
                    "/var/cache/apt/x.deb", "/run/app.pid"):
            with self.subTest(ref=ref):
                resp = _decide(ref=ref)
                self.assertEqual(resp["decision"], "allow", resp)

    def test_the_strict_posture_still_respects_the_other_two_axes(self) -> None:
        """Even strict, R6 is not "hold everything": it is scoped to
        irreversible actions in production."""
        self.assertEqual(_decide(ref="/anything", environment="dev")["decision"],
                         "allow")
        self.assertEqual(
            _decide(ref="/anything", reversibility="recoverable")["decision"],
            "allow")


if __name__ == "__main__":
    unittest.main()
