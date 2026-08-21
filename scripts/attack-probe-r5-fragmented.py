#!/usr/bin/env python3
"""
attack-probe-r5-fragmented.py -- RFX-CORE-3 live repro, the FRAGMENTED form.

Why fragmented and not single-call
----------------------------------
R5 has existed in two shapes, and they fail differently on a single call:

  SPEC section 4.1 (the original, still deployed on api-dev v0.1.13):
      input.cumulative.count_by_verb.delete + input.magnitude.count > 20
    The `magnitude.count` term is added UNCONDITIONALLY -- it never checks the
    verb -- so a single count=25 call trips it whatever the verb is (it even
    fires on a `read`). Only the CUMULATIVE term is keyed on the exact string
    "delete".

  budgets.rego (RFX-11 / PR #82, in main):
      current_for("deletions")  requires input.action.verb == "delete"
      cumulative_for("deletions") reads cumulative.count_by_verb.delete
    Both terms are keyed on "delete", so a non-canonical verb evades on the
    very first call.

The FRAGMENTED probe below is decisive on BOTH shapes, because in both the
cumulative term is keyed on the exact literal "delete": N small calls under a
non-canonical spelling accumulate under their own ledger key and never reach
the budget. And fragmentation resistance is the entire stated purpose of R5
(SPEC section 4.1: "fragmentation buys nothing"), so this is the rule failing
at the one thing it exists to do.

  python3 scripts/attack-probe-r5-fragmented.py            # api-dev
  REEFLEX_PROBE_BASE=http://127.0.0.1:8080 REEFLEX_PROBE_TOKEN= \
      python3 scripts/attack-probe-r5-fragmented.py        # local fixed build
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_probe = __import__("attack-probe-rfx-core-2".replace("-", "_")) if False else None

# Import the shared helpers from the sibling probe by path (hyphenated filename).
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "probe_core",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "attack-probe-rfx-core-2.py"),
)
probe = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(probe)

CHUNK = int(os.environ.get("REEFLEX_PROBE_CHUNK", "5"))
CALLS = int(os.environ.get("REEFLEX_PROBE_CALLS", "6"))

# The deletions budget is 20. Fragmented into CHUNK-sized calls, the canonical
# spelling must trip on the call where prior + current first exceeds 20.
SPELLINGS = [
    "delete",       # control -- MUST trip
    "Delete",       # case near-miss
    "DELETE",
    "remove",       # synonym
    "destroy",
    "purge",
    "drop",
    "truncate",
    "rm",
    "hard_delete",
    "delete​",  # zero-width space
]


def which_build():
    """Empirically fingerprint the deployed R5 shape (core exposes no version)."""
    probe.banner("FINGERPRINT  which R5 is deployed here? (core exposes no version)")
    # A read with count=25. Under budgets.rego (main) the deletions dimension
    # requires verb=='delete', so this must be ALLOW (R1 read-only internal).
    # Under the original SPEC section 4.1 rule, magnitude.count is added
    # unconditionally, so it trips the "delete" budget on a READ.
    _, r = probe.call("POST", "/v1/decide",
                      probe.envelope(probe.sid("fp-read"), "read", count=25,
                                     env="dev", reversibility="reversible",
                                     blast="single", externality="internal"),
                      "fingerprint: verb='read' count=25, read-only internal")
    v, ru = probe.verdict(r), probe.rule(r)
    print("\n  verb='read' count=25 -> %s (%s)" % (v, ru))
    if "session_delete_budget" in ru:
        print("  => DEPLOYED R5 is the original SPEC section 4.1 rule: it adds")
        print("     magnitude.count unconditionally, so it fires on a READ.")
        print("     This build PREDATES budgets.rego (RFX-11 / PR #82).")
    elif v == "allow":
        print("  => DEPLOYED R5 is budgets.rego (RFX-11 / PR #82): the deletions")
        print("     dimension correctly gates on verb=='delete'.")
    else:
        print("  => inconclusive; inspect the raw verdict above.")

    # objects_touched (limit 200) only exists in budgets.rego.
    _, r2 = probe.call("POST", "/v1/decide",
                       probe.envelope(probe.sid("fp-ot"), "create", count=201,
                                      env="dev", reversibility="reversible",
                                      blast="single", externality="internal"),
                       "fingerprint: verb='create' count=201 (objects_touched=200?)")
    print("\n  verb='create' count=201 -> %s (%s)" % (probe.verdict(r2), probe.rule(r2)))
    if "cumulative_budget" in probe.rule(r2):
        print("  => objects_touched dimension present -> budgets.rego is live.")
    else:
        print("  => no objects_touched dimension -> budgets.rego is NOT live.")


def run_spelling(verb, tag):
    """Fragment CALLS x CHUNK deletes into one session under this spelling."""
    session = probe.sid("frag-%s" % tag)
    trail = []
    tripped_at = None
    for i in range(1, CALLS + 1):
        _, r = probe.call("POST", "/v1/decide",
                          probe.envelope(session, verb, count=CHUNK, env="dev"),
                          "B-frag verb=%r call %d/%d (count=%d, running total=%d)"
                          % (verb, i, CALLS, CHUNK, i * CHUNK))
        v = probe.verdict(r)
        trail.append(v)
        if v != "allow" and tripped_at is None:
            tripped_at = i * CHUNK
    return trail, tripped_at


def main():
    print("reeflex-core R5 fragmented-delete probe -- RFX-CORE-3")
    print("target : %s" % probe.BASE)
    print("run    : %s" % probe.RUN)
    print("shape  : %d calls x count=%d = %d deletes vs a budget of 20"
          % (CALLS, CHUNK, CALLS * CHUNK))

    if os.environ.get("REEFLEX_PROBE_SKIP_FP", "") != "1":
        which_build()

    rows = []
    only = os.environ.get("REEFLEX_PROBE_ONLY", "")
    spellings = [only] if only else SPELLINGS
    for i, verb in enumerate(spellings):
        probe.banner("B-frag  %d x count=%d as verb=%r" % (CALLS, CHUNK, verb))
        trail, tripped = run_spelling(verb, "%02d" % i)
        rows.append((verb, trail, tripped))

    print("\n" + "=" * 78)
    print("RFX-CORE-3 SUMMARY -- %d deletes fragmented %d x %d, budget = 20"
          % (CALLS * CHUNK, CALLS, CHUNK))
    print("=" * 78)
    print("%-18s %-14s %s" % ("verb (repr)", "held at", "per-call verdicts"))
    for verb, trail, tripped in rows:
        held = ("%d deletes" % tripped) if tripped else "NEVER"
        flag = "" if tripped else "   <-- EVADED, fail OPEN"
        print("%-18s %-14s %s%s"
              % (repr(verb), held, " ".join(t[:4] for t in trail), flag))
    evaded = [v for v, _, t in rows if t is None]
    print("\n  %d/%d spellings never tripped the delete budget across %d deletes"
          % (len(evaded), len(rows), CALLS * CHUNK))
    if evaded:
        print("  evaded: %s" % ", ".join(repr(v) for v in evaded))


if __name__ == "__main__":
    main()
