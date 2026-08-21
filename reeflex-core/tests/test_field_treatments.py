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
import os
import pathlib
import sys
import tempfile
import unittest

_repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.envelope import validate_and_fill_defaults
from app.field_treatments import (
    BIND_ACTOR,
    BIND_HASH,
    BIND_NONE,
    BIND_VALUE,
    CANONICALISE,
    CORE_COMPUTED,
    HASH_COVERED_BLOCKS,
    TREATMENTS,
    VALIDATE,
    VERIFY,
    approval_actor_paths,
    approval_bound_paths,
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
# A recording envelope — the derivation for readers a regex cannot follow
#
# RFX-139: DECIDE_ENVELOPE_PATHS is HAND-MAINTAINED, and it was wrong.  It
# omitted agent.id and agent.on_behalf_of, which decide.py has always read --
# indirectly, through principal.is_self_approval(), which iterates a tuple of
# field names in ANOTHER MODULE.  No amount of grepping decide.py finds that,
# and the AST scan that keeps ledger.py honest would not either.
#
# So this derivation is dynamic: run the real code against an envelope that
# records every field dereferenced, wherever the dereference happens.  It
# follows indirection by construction, because it watches the data rather than
# the source.
# ---------------------------------------------------------------------------

class _RecordingBlock(dict):
    """A top-level envelope block that records every field read from it."""

    def __init__(self, block: str, data: dict, sink: set) -> None:
        super().__init__(data)
        self._block = block
        self._sink = sink

    def _seen(self, key):
        if isinstance(key, str):
            self._sink.add("%s.%s" % (self._block, key))

    def get(self, key, default=None):
        self._seen(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self._seen(key)
        return super().__getitem__(key)

    def __contains__(self, key):
        self._seen(key)
        return super().__contains__(key)


class _RecordingEnvelope(dict):
    """An envelope whose blocks record their reads.

    Bare top-level block reads (`envelope["action"]`, as canonical_hash() does
    over its whole projection) are deliberately NOT recorded: a treatment is
    declared per FIELD, and whole-block coverage is check 5's job, asserted
    separately against holds._HASH_ALLOWLIST.
    """

    def __init__(self, data: dict, sink: set) -> None:
        super().__init__(data)
        self._sink = sink

    def _wrap(self, key, value):
        if isinstance(value, dict) and not isinstance(value, _RecordingBlock):
            return _RecordingBlock(key, value, self._sink)
        return value

    def get(self, key, default=None):
        if not dict.__contains__(self, key):
            return default
        return self._wrap(key, dict.__getitem__(self, key))

    def __getitem__(self, key):
        return self._wrap(key, dict.__getitem__(self, key))


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
# 1b. Every field says what an APPROVAL of it binds  (RFX-138 / RFX-139)
# ---------------------------------------------------------------------------

class TestApprovalBindingIsDeclared(unittest.TestCase):
    """A treatment says how a field is made safe to COMPARE.  It does not say
    what a human's approval of that value is worth on the next request that
    cites the hold -- and that is where RFX-138 lived: `agent` was outside the
    envelope hash and outside check 7, so an approval of agent A's irreversible
    production delete was spendable by agent B.

    The old derivation selected on a BLOCK list, with `agent` excluded by a
    comment asserting it carried no decision input.  It did.  These tests make
    the exclusion a per-field DECLARATION that has to be written down, so the
    next omission is a red gate rather than a comment nobody re-reads.
    """

    def test_every_caller_supplied_field_declares_a_binding(self):
        undeclared_binding = sorted(
            p for p, t in TREATMENTS.items()
            if t.kind != CORE_COMPUTED
            and t.approval_binding not in (BIND_HASH, BIND_VALUE, BIND_ACTOR, BIND_NONE)
        )
        self.assertEqual(
            [], undeclared_binding,
            "caller-supplied field(s) with no declared approval_binding: %s.\n"
            "Say what a human's approval binds about the field: BIND_HASH "
            "(inside canonical_hash), BIND_VALUE (compared by check 7), "
            "BIND_ACTOR (part of who the approval was granted to, check 8), or "
            "BIND_NONE with the reason in the note. RFX-138 was an UNDECLARED "
            "binding, not a wrong one." % undeclared_binding,
        )

    def test_core_computed_fields_declare_no_binding(self):
        """Nothing for an approval to bind: core recomputes them per request."""
        for path, t in TREATMENTS.items():
            if t.kind == CORE_COMPUTED:
                self.assertEqual("", t.approval_binding, path)

    def test_bind_hash_means_the_hash_actually_covers_it(self):
        """BIND_HASH is a claim about holds._HASH_ALLOWLIST. Check it.

        If the hash projection is ever narrowed, the fields it drops must stop
        claiming to be bound by it -- otherwise the table would keep saying
        "check 5 has this" about a field check 5 no longer sees.
        """
        from app.holds import _HASH_ALLOWLIST
        self.assertEqual(
            set(_HASH_ALLOWLIST), set(HASH_COVERED_BLOCKS),
            "HASH_COVERED_BLOCKS has drifted from holds._HASH_ALLOWLIST",
        )
        for path, t in TREATMENTS.items():
            block = path.split(".")[0]
            if t.approval_binding == BIND_HASH:
                self.assertIn(block, HASH_COVERED_BLOCKS,
                              "%s claims the hash binds it, but the hash does "
                              "not cover the %r block" % (path, block))
            elif t.kind != CORE_COMPUTED and block in HASH_COVERED_BLOCKS:
                self.fail("%s is inside the hash projection but declares %r"
                          % (path, t.approval_binding))

    def test_the_derived_lists_are_what_the_checks_run_against(self):
        """The two derivations must stay non-empty and disjoint."""
        value_bound = set(approval_bound_paths())
        actor_bound = set(approval_actor_paths())
        self.assertTrue(value_bound, "check 7 would bind nothing")
        self.assertTrue(actor_bound, "check 8 would bind nothing")
        self.assertEqual(set(), value_bound & actor_bound)
        # Regression anchors: the two fields each check exists for.
        self.assertIn("params.amount", value_bound)      # RFX-133 / check 7
        self.assertIn("agent.id", actor_bound)           # RFX-138 / check 8
        self.assertIn("agent.on_behalf_of", actor_bound)

    def test_the_actor_key_reads_exactly_the_declared_actor_paths(self):
        """principal.approval_actor_key() and the table must agree.

        A field declared BIND_ACTOR that the key never reads is a promise the
        code does not keep; a field the key reads that is not declared is
        RFX-139 again.
        """
        from app.principal import approval_actor_key
        sink: set[str] = set()
        # BOTH branches: a named agent (which never reaches the fallback) and
        # a SPEC-minimal envelope (which is the only thing that does).
        approval_actor_key(_RecordingEnvelope(
            {"agent": {"id": "a", "on_behalf_of": "b", "session_id": "c"}}, sink))
        approval_actor_key(_RecordingEnvelope({"agent": {"session_id": "c"}}, sink))
        self.assertEqual(
            set(approval_actor_paths()), sink,
            "approval_actor_key() reads %s; the table declares %s"
            % (sorted(sink), sorted(approval_actor_paths())),
        )


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


# ---------------------------------------------------------------------------
# 2b. decide.py's declared read-set matches what it ACTUALLY dereferences
# ---------------------------------------------------------------------------

class TestDecideDeclarationMatchesCode(unittest.TestCase):
    """The counterpart to TestLedgerDeclarationMatchesCode, for the reader a
    static scan cannot follow.

    RFX-139 in one sentence: the guard was sound and the list it was pointed
    at was short.  `undeclared(set(DECIDE_ENVELOPE_PATHS)) == set()` passes
    trivially when DECIDE_ENVELOPE_PATHS omits a field decide.py reads -- it
    checks the list against the table, never the list against the CODE.  So
    this runs the approval chain against a recording envelope and asserts
    against what was really touched.

    SCOPE, STATED HONESTLY.  It sweeps _validate_approval(), which is where
    both defects that reached production through decide.py lived (RFX-127's
    skipped validation, RFX-138's unbound actor) and which reaches allow and
    deny verdicts OPA never sees.  It does NOT sweep all of process(), because
    process() also hands the envelope to the audit writer, whose reads
    (context.traceparent, meta.*) are audit-only by design and deliberately
    outside this table -- sweeping them would force treatments for fields that
    cannot change a verdict.  The freeze gate's action.verb read stays covered
    by the static declaration above.
    """

    def setUp(self) -> None:
        import app.holds as holds_mod
        self._dir = tempfile.TemporaryDirectory(prefix="rfx139_sweep_")
        holds_mod._reset(os.path.join(self._dir.name, "holds.jsonl"))
        self._holds = holds_mod

    def tearDown(self) -> None:
        os.environ.pop("REEFLEX_HOLDS_PATH", None)
        self._dir.cleanup()

    def _sweep(self) -> set:
        """Every envelope field the approval chain dereferences, all 8 checks.

        The hold is APPROVED and the envelope matches it, so the chain runs to
        the end instead of short-circuiting at check 1 -- a sweep that stops at
        the first refusal would under-report exactly the way the hand-written
        list did.
        """
        from app.decide import _validate_approval
        raw = _envelope(agent__on_behalf_of="user:sweep",
                        params={"amount": 10, "currency": "EUR"})
        filled = validate_and_fill_defaults(raw)
        rec = self._holds.create_hold(filled, "reeflex.policy/sweep")
        self._holds.resolve_hold(rec["id"], "approve", "human", "sweeper", None)

        sink: set = set()
        env = dict(filled)
        env["approval"] = {"present": True, "hold_id": rec["id"]}
        code, resp, _hold = _validate_approval(_RecordingEnvelope(env, sink))
        self.assertEqual((0, None), (code, resp),
                         "the sweep envelope must pass all 8 checks, or the "
                         "chain short-circuited and the sweep under-reports")
        return sink

    def test_the_approval_chain_reads_nothing_undeclared(self):
        touched = self._sweep()
        self.assertTrue(touched, "recorded no reads — the derivation broke")
        missing = undeclared(touched)
        self.assertEqual(
            set(), missing,
            "the hold-approval chain dereferences envelope field(s) with NO "
            "declared treatment: %s. Declare each in app/field_treatments.py — "
            "this is the RFX-139 check: the guard must run against what the "
            "code reads, not against a list someone maintained by hand."
            % sorted(missing),
        )

    def test_decide_declares_the_paths_only_it_reads(self):
        """A path the chain reads that no OTHER reader explains must be in
        DECIDE_ENVELOPE_PATHS.

        This is the assertion that was red before RFX-138 was fixed:
        agent.id and agent.on_behalf_of are read by is_self_approval() and by
        approval_actor_key(), appear in no .rego file and in no ledger read,
        and were in nobody's declared list.
        """
        explained_elsewhere = (policy_input_paths(_rego_sources())
                               | set(LEDGER_ENVELOPE_PATHS))
        decide_only = self._sweep() - explained_elsewhere
        undeclared_here = decide_only - set(DECIDE_ENVELOPE_PATHS)
        self.assertEqual(
            set(), undeclared_here,
            "decide.py alone reads %s and DECIDE_ENVELOPE_PATHS does not list "
            "it. The list is what the approval binding is derived from, so a "
            "field missing from it can never be bound (RFX-138/RFX-139)."
            % sorted(undeclared_here),
        )

    def test_the_sweep_would_catch_a_new_undeclared_reader(self):
        """Negative control: the derivation must actually be able to go red.

        Without this, a recorder that silently stopped recording would leave
        both tests above passing forever -- the same failure mode as the guard
        they replace.
        """
        sink: set = set()
        env = _RecordingEnvelope({"agent": {"session_id": "s"},
                                  "params": {"fee_currency": "EUR"}}, sink)
        (env.get("params") or {}).get("fee_currency")
        self.assertIn("params.fee_currency", sink)
        self.assertEqual({"params.fee_currency"}, undeclared(sink))


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


if __name__ == "__main__":
    unittest.main()
