"""
test_field_treatments.py — the enumeration IS the test (RFX-127 / RFX-133).

Five ways to beat the decision path have been found and each was fixed one
field at a time.  This file is the thing that stops the sixth being found the
same way: it DERIVES the set of caller-supplied fields the decision path
actually reads, from the two places that read them, and fails if any of them
lacks a declared treatment in app/field_treatments.py.

    T_every_policy_read_is_declared
        Extract every `input.<path>` and `object.get(input, [...])` from
        policy/*.rego.  Each must be in TREATMENTS.  ADD A FIELD TO A RULE
        WITHOUT DECLARING ITS TREATMENT AND THIS GOES RED.

    T_every_ledger_read_is_declared
        The ledger is the SECOND reader, and the one a policy-only scan
        misses: `params.currency` appears in no .rego file, yet omitting it
        disabled the money budget (RFX-133).  Each path ledger.py declares
        must also be in TREATMENTS.

    T_ledger_declares_every_envelope_path_it_reads
        AST-scan app/ledger.py for envelope key reads and check them against
        LEDGER_ENVELOPE_PATHS, so that tuple cannot silently fall behind the
        code it documents.

    T_no_stale_declarations
        Every declared path must be read by SOMETHING.  Keeps the table from
        becoming a wish list nobody maintains.

    T_canonicalise_fields_land_in_their_closed_set
        For each CANONICALISE field, run a hostile variant corpus (case,
        whitespace, unicode compatibility forms, zero-width characters,
        wrong types, unknown values) through the real
        validate_and_fill_defaults() and assert the output is in the declared
        closed set.  A declaration is not worth anything if the code does not
        honour it.

    T_core_computed_fields_are_overwritten
        A caller that puts its own `cumulative` in the envelope must not
        influence the decision.

    T_verify_fields_are_not_read_from_the_caller
        approval.present must reach OPA as false however the caller sets it.

Run:
  cd reeflex-core
  python -m unittest tests.test_field_treatments -v
"""

from __future__ import annotations

import ast
import pathlib
import sys
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.envelope import validate_and_fill_defaults
from app.field_treatments import (
    CANONICALISE,
    CORE_COMPUTED,
    TREATMENTS,
    VALIDATE,
    VERIFY,
    policy_input_paths,
    undeclared,
)
from app.decide import DECIDE_ENVELOPE_PATHS
from app.ledger import LEDGER_ENVELOPE_PATHS

_POLICY_DIR = _repo_root / "policy"
_LEDGER_PY = _repo_root / "app" / "ledger.py"


def _rego_sources() -> dict[str, str]:
    """Every non-test .rego in the policy dir, by filename."""
    return {
        p.name: p.read_text(encoding="utf-8")
        for p in sorted(_POLICY_DIR.glob("*.rego"))
        if not p.name.endswith("_test.rego")
    }


def _envelope(**over) -> dict:
    base = {
        "reeflex_version": "0.1",
        "agent": {"session_id": "sess_treatments", "id": "agent:t"},
        "action": {"namespace": "t", "verb": "update", "ability": "t/op"},
        "target": {"kind": "t", "ref": "t:1", "environment": "dev"},
        "params": {},
        "magnitude": {"count": 1},
        "axes": {
            "reversibility": "reversible",
            "blast_radius": "single",
            "externality": "internal",
        },
        "approval": {"present": False, "hold_id": None},
    }
    for dotted, value in over.items():
        head, _, tail = dotted.partition("__")
        if tail:
            base.setdefault(head, {})[tail] = value
        else:
            base[head] = value
    return base


# ---------------------------------------------------------------------------
# 1. The enumeration is total
# ---------------------------------------------------------------------------

class TestEnumerationIsTotal(unittest.TestCase):

    def test_every_policy_read_is_declared(self):
        """No rule may read a caller-supplied field with no declared treatment.

        THIS IS THE TEST THAT REPLACES THE FIVE PATCHES.  Adding
        `input.target.kind` to a rule, or a new budget dimension keyed on a
        new params field, turns the gate red until app/field_treatments.py
        says how that field is made safe to compare against.
        """
        paths = policy_input_paths(_rego_sources())
        self.assertTrue(paths, "extracted no input paths — the derivation broke")
        missing = undeclared(paths)
        self.assertEqual(
            set(), missing,
            "policy/*.rego reads caller-supplied field(s) with NO declared "
            "treatment: %s.\nDeclare each in app/field_treatments.py "
            "TREATMENTS (canonicalise / validate / verify / core_computed) "
            "and implement the treatment before the rule can ship. This is "
            "the RFX-86/85/84/127/133 class." % sorted(missing),
        )

    def test_the_five_known_fields_are_all_declared(self):
        """Regression anchor: the five that were found the hard way."""
        for path in ("target.environment", "action.verb", "approval.present",
                     "approval.hold_id", "params.currency"):
            self.assertIn(path, TREATMENTS, path)

    def test_every_ledger_read_is_declared(self):
        """The ledger is the second reader; RFX-133 lived exactly here."""
        missing = undeclared(set(LEDGER_ENVELOPE_PATHS))
        self.assertEqual(
            set(), missing,
            "ledger.py reads envelope field(s) with no declared treatment: %s"
            % sorted(missing),
        )

    def test_every_decide_read_is_declared(self):
        """decide.py is the third reader; RFX-127 lived exactly here."""
        missing = undeclared(set(DECIDE_ENVELOPE_PATHS))
        self.assertEqual(
            set(), missing,
            "decide.py reads envelope field(s) with no declared treatment: %s"
            % sorted(missing),
        )

    def test_the_policy_is_not_the_only_reader(self):
        """Scanning policy/*.rego alone is not an enumeration.

        RFX-133 and RFX-127 both lived in fields no .rego file mentions
        (params.currency at the time, approval.hold_id still). This asserts
        the general form of that lesson so it cannot rot: each of the other
        two readers must contribute at least one path the policy does not,
        and every such path must be declared.
        """
        policy = policy_input_paths(_rego_sources())
        for name, paths in (("ledger.py", LEDGER_ENVELOPE_PATHS),
                            ("decide.py", DECIDE_ENVELOPE_PATHS)):
            only = set(paths) - policy
            self.assertTrue(
                only,
                "%s contributes no path the policy scan misses — if that is "
                "genuinely true now, this test is the place to say so "
                "deliberately rather than by accident" % name,
            )
            self.assertEqual(set(), undeclared(only),
                             "%s-only path(s) undeclared: %s" % (name, sorted(only)))

    def test_no_stale_declarations(self):
        """Every declared path must be read by one of the three readers."""
        read = (policy_input_paths(_rego_sources())
                | set(LEDGER_ENVELOPE_PATHS)
                | set(DECIDE_ENVELOPE_PATHS))
        # cumulative.* projections are read via object.get on sub-keys; the
        # parent `cumulative` is declared for the overwrite invariant.
        read.add("cumulative")
        stale = {p for p in TREATMENTS if p not in read}
        self.assertEqual(
            set(), stale,
            "declared treatment(s) for field(s) nothing reads: %s — remove "
            "them so the table stays a description of the code, not a wish "
            "list." % sorted(stale),
        )

    def test_every_treatment_has_a_valid_kind_and_an_implementer(self):
        for path, t in TREATMENTS.items():
            self.assertIn(t.kind, (CANONICALISE, VALIDATE, VERIFY, CORE_COMPUTED), path)
            self.assertTrue(t.applied_by.strip(), "%s declares no implementer" % path)


# ---------------------------------------------------------------------------
# 2. The ledger's declared read-set matches its code
# ---------------------------------------------------------------------------

class TestLedgerDeclarationMatchesCode(unittest.TestCase):
    """LEDGER_ENVELOPE_PATHS must not drift away from what ledger.py reads.

    AST-scan append_entry() for the string literals it uses as envelope keys
    and check that every second-level read is declared.  Without this the
    tuple is just a comment, and a future `params.get("fee_currency")` would
    slip past the enumeration exactly the way params.currency did.
    """

    def _append_entry_ast(self) -> ast.FunctionDef:
        tree = ast.parse(_LEDGER_PY.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "append_entry":
                return node
        self.fail("ledger.append_entry not found")

    def test_ledger_declares_every_envelope_path_it_reads(self):
        fn = self._append_entry_ast()
        # Every `.get("literal")` call in the function body.
        keys: list[str] = []
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                keys.append(node.args[0].value)

        # Top-level envelope blocks the function reaches into.
        blocks = {p.split(".")[0] for p in LEDGER_ENVELOPE_PATHS}
        leaves = {p.split(".")[1] for p in LEDGER_ENVELOPE_PATHS}
        # Keys that are neither a declared block, a declared leaf, nor an
        # internal ledger entry field, are undeclared envelope reads.
        internal = {"count", "amount_by_currency", "ts", "verb", "ability",
                    "externality"}
        unexpected = [
            k for k in keys if k not in blocks and k not in leaves and k not in internal
        ]
        self.assertEqual(
            [], unexpected,
            "ledger.append_entry reads envelope key(s) not declared in "
            "LEDGER_ENVELOPE_PATHS: %s" % sorted(set(unexpected)),
        )
        # And the declared blocks are genuinely reached.
        for block in blocks:
            self.assertIn(block, keys, "declared block %r is never read" % block)


# ---------------------------------------------------------------------------
# 3. The declarations are honoured by the code
# ---------------------------------------------------------------------------

#: One hostile corpus, applied to every CANONICALISE field.  These are the
#: shapes that actually beat exact-match comparisons: case, padding, Unicode
#: compatibility forms, invisible characters, wrong types, and plain unknowns.
_HOSTILE = [
    "",
    "   ",
    "UNKNOWN-VALUE",
    "unknown value",
    "​",            # zero-width space alone
    None,
    42,
    True,
    [],
    {},
]


def _hostile_variants(canonical: str) -> list:
    """Near-misses of a known-good value, plus the generic hostile corpus."""
    return _HOSTILE + [
        canonical.upper(),
        canonical.capitalize(),
        "  %s  " % canonical,
        "%s\n" % canonical,
        "%s​" % canonical,          # trailing zero-width space
        "﻿%s" % canonical,          # leading BOM
        "".join(chr(ord(c) + 0xFEE0) if "a" <= c <= "z" else c
                for c in canonical),      # fullwidth form
    ]


class TestCanonicaliseIsHonoured(unittest.TestCase):

    def test_axes_land_in_their_closed_set(self):
        for axis in ("reversibility", "blast_radius", "externality"):
            t = TREATMENTS["axes.%s" % axis]
            for member in sorted(t.closed_set):
                for variant in _hostile_variants(member):
                    env = _envelope()
                    env["axes"][axis] = variant
                    got = validate_and_fill_defaults(env)["axes"][axis]
                    self.assertIn(
                        got, t.closed_set,
                        "axes.%s=%r -> %r, outside the declared closed set"
                        % (axis, variant, got),
                    )

    def test_environment_lands_in_its_closed_set(self):
        t = TREATMENTS["target.environment"]
        for member in sorted(t.closed_set):
            for variant in _hostile_variants(member):
                env = _envelope()
                env["target"]["environment"] = variant
                try:
                    got = validate_and_fill_defaults(env)["target"]["environment"]
                except Exception:
                    # empty / wrong-type environment is a structural 400 —
                    # a refusal, not a fall-through, which is the safe end.
                    continue
                self.assertIn(got, t.closed_set,
                              "environment=%r -> %r" % (variant, got))

    def test_unknown_environment_coerces_to_the_declared_default(self):
        t = TREATMENTS["target.environment"]
        env = _envelope()
        env["target"]["environment"] = "qa-eu-west"
        got = validate_and_fill_defaults(env)["target"]["environment"]
        self.assertEqual(t.conservative_default, got)

    def test_verb_lands_in_its_closed_set(self):
        t = TREATMENTS["action.verb"]
        for member in sorted(t.closed_set):
            for variant in _hostile_variants(member):
                env = _envelope()
                env["action"]["verb"] = variant
                try:
                    got = validate_and_fill_defaults(env)["action"]["verb"]
                except Exception:
                    continue
                self.assertIn(got, t.closed_set, "verb=%r -> %r" % (variant, got))

    def test_currency_lands_in_alpha3_or_the_declared_default(self):
        t = TREATMENTS["params.currency"]
        variants = _hostile_variants("eur") + [
            "€", "euros", "Euro", "e u r", "EURO", "eur ", "ＥＵＲ", "eu",
            "eurr", "1234", -1,
        ]
        for variant in variants:
            env = _envelope()
            env["params"] = {"amount": 10, "currency": variant}
            got = validate_and_fill_defaults(env)["params"]["currency"]
            self.assertTrue(
                got == t.conservative_default
                or (len(got) == 3 and got.isascii() and got.isalpha()
                    and got.isupper()),
                "currency=%r -> %r, neither alpha-3 nor %s"
                % (variant, got, t.conservative_default),
            )

    def test_currency_near_misses_all_fold_to_one_bucket(self):
        """The point of canonicalising: one currency, one ledger bucket."""
        got = set()
        for variant in ("EUR", "eur", " Eur ", "eur\n", "eur​", "ＥＵＲ"):
            env = _envelope()
            env["params"] = {"amount": 10, "currency": variant}
            got.add(validate_and_fill_defaults(env)["params"]["currency"])
        self.assertEqual({"EUR"}, got)

    def test_currency_is_left_alone_when_it_denominates_nothing(self):
        """params is free-form: core only touches the money pair."""
        env = _envelope()
        env["params"] = {"currency": "Bitcoin", "note": "not money"}
        out = validate_and_fill_defaults(env)["params"]
        self.assertEqual("Bitcoin", out["currency"])
        self.assertEqual("not money", out["note"])


class TestValidateIsHonoured(unittest.TestCase):

    def test_magnitude_count_is_an_int_ge_1_or_a_refusal(self):
        for bad in ("5", 5.5, 0, -3, True, [], {}):
            env = _envelope()
            env["magnitude"] = {"count": bad}
            with self.assertRaises(Exception, msg="count=%r was accepted" % bad):
                validate_and_fill_defaults(env)
        env = _envelope()
        env["magnitude"] = {}
        self.assertEqual(1, validate_and_fill_defaults(env)["magnitude"]["count"])

    def test_session_id_is_required_non_empty(self):
        for bad in (None, "", "   ", 42, [], {}):
            env = _envelope()
            env["agent"] = {"session_id": bad}
            with self.assertRaises(Exception, msg="session_id=%r accepted" % bad):
                validate_and_fill_defaults(env)


# ---------------------------------------------------------------------------
# 5. The fourth reader — derived by RUNNING the chain, not by reading it
# ---------------------------------------------------------------------------

class _RecordingEnvelope(dict):
    """A dict that logs which second-level keys anybody actually reads.

    Wraps every nested dict in another one of itself, so `envelope["agent"]`
    followed by `.get("on_behalf_of")` is recorded as `agent.on_behalf_of`
    NO MATTER WHICH MODULE, WHICH FRAME, OR WHICH LOOP does the reading.
    """

    def __init__(self, data, seen, prefix=""):
        super().__init__(data)
        self._seen = seen
        self._prefix = prefix

    def _wrap(self, key, value):
        path = "%s.%s" % (self._prefix, key) if self._prefix else str(key)
        if self._prefix:
            # A leaf read under a top-level block: this is the depth the
            # Action Envelope declares fields at (SPEC §2).
            self._seen.add(path)
        if isinstance(value, dict):
            return _RecordingEnvelope(value, self._seen, path)
        return value

    def __getitem__(self, key):
        return self._wrap(key, super().__getitem__(key))

    def get(self, key, default=None):
        if key not in self:
            # Record the ABSENT read too: an omission is exactly how RFX-127
            # and RFX-133 worked, so "the code looked for it" is the fact
            # worth capturing, not "the caller supplied it".
            if self._prefix:
                self._seen.add("%s.%s" % (self._prefix, key))
            return default
        return self._wrap(key, super().__getitem__(key))


class TestTheApprovalChainDeclaresWhatItReads(unittest.TestCase):
    """RFX-139 — the guard passed by under-reporting, and this is the fix.

    DECIDE_ENVELOPE_PATHS declared four paths and decide.py read six.  The two
    it omitted, agent.id and agent.on_behalf_of, are read ONE FRAME DEEPER —
    inside principal.actor_identities(), behind

        for field in ("id", "on_behalf_of", "session_id"):

    so app/principal.py is the FOURTH READER that field_treatments.py's own
    RESIDUAL note 3 predicted would be invisible.  The cost was not tidiness:
    approval_bound_paths() is derived from TREATMENTS, so an undeclared field
    could never be bound to an approval, and that is precisely how RFX-138
    survived a sweep built to be exhaustive.

    WHY THIS IS A RUNTIME PROBE AND NOT AN AST SCAN.  The ticket's own fix
    shape proposed "a static (ast) sweep of envelope subscripting in those
    modules".  An AST sweep of decide.py would NOT have caught this — the
    reads are in another module, behind a tuple loop, so there is no
    `.get("on_behalf_of")` literal to find anywhere in the scanned file.  A
    scan pointed at the right module set today is a scan that misses the FIFTH
    reader tomorrow.  Driving a recording envelope through the real chain
    records what the code did, wherever it did it.
    """

    def _record(self, envelope: dict, hold_envelope: dict, hold: dict) -> set:
        """Run the real approval chain over a recording envelope."""
        import app.decide as decide_mod
        import app.holds as holds_mod

        seen: set = set()
        probe = _RecordingEnvelope(envelope, seen)
        real_get_hold = holds_mod.get_hold
        holds_mod.get_hold = lambda _hid: hold
        try:
            decide_mod._validate_approval(probe)
        finally:
            holds_mod.get_hold = real_get_hold
        return seen

    def _approved_hold(self, envelope: dict) -> dict:
        from app.holds import canonical_hash
        return {
            "id": "probe-hold", "status": "approved",
            "envelope": envelope, "envelope_hash": canonical_hash(envelope),
            "decided_by": "human:probe-approver", "expires_ts": None,
            "rule_id": "reeflex.policy/irreversible_broad_prod",
        }

    def test_the_approval_chain_reads_nothing_undeclared(self):
        env = validate_and_fill_defaults(_envelope(
            agent__on_behalf_of="user:probe",
            approval={"present": True, "hold_id": "probe-hold"}))
        seen = self._record(env, env, self._approved_hold(env))
        self.assertTrue(seen, "the recording probe observed no reads at all — "
                              "the derivation broke, not the code")
        missing = undeclared(seen)
        self.assertEqual(
            set(), missing,
            "the hold-approval chain dereferences envelope field(s) with NO "
            "declared treatment: %s.\nDeclare each in "
            "app/field_treatments.py TREATMENTS and add it to "
            "DECIDE_ENVELOPE_PATHS. This is the RFX-139 class: the guard goes "
            "green by under-reporting." % sorted(missing),
        )

    def test_the_approval_chain_reads_nothing_decide_does_not_declare(self):
        """The under-reporting itself, asserted directly.

        Being declared in TREATMENTS is not enough — DECIDE_ENVELOPE_PATHS is
        what the other tests in this file run against, so it is the list that
        has to be complete.  On origin/main 44c6f85 this is RED: the probe
        records agent.id and agent.on_behalf_of and the tuple names neither.
        """
        env = validate_and_fill_defaults(_envelope(
            agent__on_behalf_of="user:probe",
            approval={"present": True, "hold_id": "probe-hold"}))
        seen = self._record(env, env, self._approved_hold(env))
        # The hash projection is bound by check 5 as a whole, via
        # canonical_hash(); those blocks have their own declarations and are
        # not decide.py's own reads.
        from app.field_treatments import HASH_COVERED_BLOCKS
        own = {p for p in seen if p.split(".")[0] not in HASH_COVERED_BLOCKS}
        undeclared_by_decide = own - set(DECIDE_ENVELOPE_PATHS)
        self.assertEqual(
            set(), undeclared_by_decide,
            "decide.py's approval chain reads %s, which DECIDE_ENVELOPE_PATHS "
            "does not declare. The declaration is hand-maintained; this test "
            "is what stops it going stale." % sorted(undeclared_by_decide),
        )

    def test_the_probe_is_not_vacuous(self):
        """A probe that records nothing interesting proves nothing.

        Pinned explicitly, because a refactor that stops the chain reading
        identity would silently turn the two tests above into tautologies —
        and "the guard passes because it checks nothing" is the exact defect
        RFX-139 names.
        """
        env = validate_and_fill_defaults(_envelope(
            agent__on_behalf_of="user:probe",
            approval={"present": True, "hold_id": "probe-hold"}))
        seen = self._record(env, env, self._approved_hold(env))
        for expected in ("agent.id", "agent.on_behalf_of",
                         "agent.session_id", "approval.hold_id"):
            self.assertIn(
                expected, seen,
                "the approval chain no longer reads %s — if that is genuinely "
                "intended, the four-eyes and actor-binding guards need "
                "re-reading, not this test relaxing" % expected)


if __name__ == "__main__":
    unittest.main()
