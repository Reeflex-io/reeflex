#!/usr/bin/env python3
"""
attack-probe-envelope-boundary.py -- live repro for RFX-127 and RFX-133.

Both are the SAME defect as RFX-84/85/86: a CALLER-SUPPLIED value that the
policy reads without canonicalising or verifying it.

  RFX-127  approval.present is a self-asserted boolean.  R5's predicate is
           `count(exceeded_dimensions) > 0` AND `not input.approval.present`,
           so a bare {"present": true} with NO hold_id switches the whole
           cumulative-budget rule off.  decide.py only enters the six-check
           hold-validation chain when `approval_present AND approval.hold_id`
           -- with hold_id omitted the envelope falls straight through to OPA
           carrying present=true.  Nothing verifies that a hold exists, was
           approved, or was approved by anyone.

  RFX-133  the money dimension is keyed on params.amount, and the ledger only
           records an amount when params.currency is ALSO present
           (ledger.append_entry: `if currency and isinstance(amount, ...)`).
           Omit params.currency and the amount is never accumulated: every
           call re-compares a single amount against the budget, so N calls of
           (limit - 1) never trip.  And when it DOES fire, cumulative_for
           ("money") sums amount_by_currency across every currency key, so
           the number compared against a EUR-denominated limit is a sum of
           unlike units.

BUILD FINGERPRINT (why this matters -- see RFX-97)
--------------------------------------------------
api-dev does NOT track main.  This probe fingerprints the target build FIRST
and labels each attack "reproduced" / "not applicable to this build" on the
evidence, instead of assuming.  Concretely, on api-dev v0.1.13:
  * R5 is the ORIGINAL SPEC 4.1 shape
    (`cumulative.count_by_verb.delete + magnitude.count > 20`), which fires
    even on a `read` -- budgets.rego (RFX-11 / PR #82) is not deployed;
  * therefore the `money` dimension DOES NOT EXIST on that build, and RFX-133
    is not reproducible there.  It is reproducible against a pinned local
    build of main -- run this same script with REEFLEX_PROBE_BASE pointing at
    a localhost core.

  python3 scripts/attack-probe-envelope-boundary.py                 # api-dev
  REEFLEX_PROBE_BASE=http://127.0.0.1:8080 REEFLEX_PROBE_TOKEN= \
  REEFLEX_PROBE_PACE=0 python3 scripts/attack-probe-envelope-boundary.py

PROD (api.reeflex.io) IS OUT OF SCOPE and is refused by the shared harness.
"""
from __future__ import annotations

import importlib.util as _ilu
import json
import os
import sys

_spec = _ilu.spec_from_file_location(
    "probe_core",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "attack-probe-rfx-core-2.py"),
)
probe = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(probe)

call, envelope, sid, verdict = probe.call, probe.envelope, probe.sid, probe.verdict

RESULTS: list[dict] = []


def record(ident: str, name: str, outcome: str, detail: str) -> None:
    RESULTS.append({"id": ident, "name": name, "outcome": outcome, "detail": detail})
    print("\n>>> %-9s %-46s %s\n    %s" % (ident, name, outcome, detail))


def money_envelope(session_id, amount, currency=None, count=1):
    """A transact envelope carrying params.amount (+ optionally currency)."""
    env = envelope(session_id, "transact", count=count, env="dev",
                   reversibility="reversible", blast="single",
                   externality="internal")
    env["action"]["ability"] = "eval/pay"
    env["params"] = {"amount": amount}
    if currency is not None:
        env["params"]["currency"] = currency
    return env


# ---------------------------------------------------------------------------
# Build fingerprint
# ---------------------------------------------------------------------------

def fingerprint() -> dict:
    print("=" * 78)
    print("BUILD FINGERPRINT -- %s" % probe.BASE)
    print("=" * 78)

    # Which R5 shape? A read/internal/dev action with count=25.
    #   old SPEC 4.1 shape : cumulative.count_by_verb.delete + magnitude.count
    #                        > 20 -- the magnitude term is unconditional, so
    #                        this READ trips it.
    #   budgets.rego shape : deletions current_for requires verb == "delete"
    #                        -> 0; objects_touched 25 < 200 -> R1 allow.
    _, r = call("POST", "/v1/decide",
                envelope(sid("fp-r5"), "read", count=25, env="dev",
                         reversibility="reversible", externality="internal"),
                "FP-1 R5 shape probe: read/internal/dev count=25")
    old_r5 = verdict(r) == "require_approval"

    # Is the money dimension present at all?  amount 6000 > the 5000 default.
    _, r = call("POST", "/v1/decide", money_envelope(sid("fp-money"), 6000, "EUR"),
                "FP-2 money dimension probe: transact amount=6000 EUR")
    money_live = verdict(r) == "require_approval"

    # Is the environment canon (RFX-86 / PR #89) deployed?
    _, r = call("POST", "/v1/decide",
                envelope(sid("fp-env"), "update", env="Prod",
                         reversibility="irreversible", blast="systemic"),
                'FP-3 environment canon probe: environment="Prod" irrev+systemic')
    env_canon = verdict(r) == "deny"

    fp = {"old_r5_shape": old_r5, "money_dimension": money_live,
          "environment_canon": env_canon}
    print("\nFINGERPRINT: " + json.dumps(fp))
    print("  R5 shape        : %s" % ("original SPEC 4.1 (pre-RFX-11)" if old_r5
                                      else "budgets.rego (RFX-11 / PR #82)"))
    print("  money dimension : %s" % ("PRESENT" if money_live else "ABSENT"))
    print("  environment canon (PR #89): %s" % ("PRESENT" if env_canon else "ABSENT"))
    return fp


# ---------------------------------------------------------------------------
# RFX-127 -- unverified approval.present switches R5 off entirely
# ---------------------------------------------------------------------------

def attack_rfx_127(fp: dict) -> None:
    print("\n" + "=" * 78)
    print("RFX-127 -- approval:{present:true} with NO hold_id disables R5")
    print("=" * 78)

    # CONTROL: an envelope that demonstrably trips a cumulative budget on THIS
    # build.  count=25 trips the old shape; verb=delete count=25 trips both.
    ctl = envelope(sid("127-ctl"), "delete", count=25, env="dev",
                   reversibility="irreversible", externality="internal")
    _, r_ctl = call("POST", "/v1/decide", ctl,
                    "A4-control delete count=25, approval absent")
    v_ctl = verdict(r_ctl)

    # ATTACK: byte-identical except approval.present = true.  No hold_id, no
    # hold was ever created, nothing was approved by anyone.
    atk = envelope(sid("127-atk"), "delete", count=25, env="dev",
                   reversibility="irreversible", externality="internal",
                   approval={"present": True})
    _, r_atk = call("POST", "/v1/decide", atk,
                    "A4-ATTACK  same envelope + approval={present:true}, NO hold_id")
    v_atk = verdict(r_atk)

    # SECURE means the forged approval did not buy an ALLOW.  Both surviving
    # outcomes count: `deny` (the assertion is refused by the hold-validation
    # chain, which is what a build carrying the RFX-127 fix does) and
    # `require_approval` (the budget simply still fires).
    if v_ctl == "require_approval" and v_atk == "allow":
        record("RFX-127", "unverified approval.present disables R5",
               "REPRODUCED -- INSECURE",
               "control=%s -> attack=%s. The whole cumulative-budget rule is "
               "switched off by a caller-asserted boolean." % (v_ctl, v_atk))
    elif v_ctl == "require_approval" and v_atk in ("deny", "require_approval"):
        detail = "refused by the hold-validation chain" if v_atk == "deny" \
            else "the budget still fires"
        record("RFX-127", "unverified approval.present disables R5", "SECURE",
               "control=%s, attack=%s (%s) -- present=true without a "
               "validated hold no longer suppresses the budget."
               % (v_ctl, v_atk, detail))
    else:
        record("RFX-127", "unverified approval.present disables R5", "INCONCLUSIVE",
               "control=%s attack=%s -- the control did not trip a budget on "
               "this build; nothing to suppress." % (v_ctl, v_atk))


# ---------------------------------------------------------------------------
# RFX-133 -- money budget evaded by omitting params.currency; mixed-currency sum
# ---------------------------------------------------------------------------

def attack_rfx_133(fp: dict) -> None:
    print("\n" + "=" * 78)
    print("RFX-133 -- money budget: currency omission + mixed-unit sum")
    print("=" * 78)

    if not fp.get("money_dimension"):
        record("RFX-133", "money budget evaded by omitting params.currency",
               "NOT APPLICABLE TO THIS BUILD",
               "FP-2 shows the money dimension does not exist on %s (R5 is the "
               "pre-RFX-11 shape). Re-run against a localhost core built from "
               "main to reproduce." % probe.BASE)
        record("RFX-133b", "cumulative_for('money') sums mixed currencies",
               "NOT APPLICABLE TO THIS BUILD",
               "Same reason: no money dimension on this build.")
        return

    # CONTROL: three 2000-unit transactions WITH a currency.  The default money
    # limit is 5000, so prior(2000+2000) + current(2000) = 6000 must trip on
    # the third call.
    s = sid("133-ctl")
    verdicts = []
    for i in range(3):
        _, r = call("POST", "/v1/decide", money_envelope(s, 2000, "EUR"),
                    "A5-control #%d amount=2000 currency=EUR" % (i + 1))
        verdicts.append(verdict(r))
    ctl_tripped = verdicts[-1] == "require_approval"

    # ATTACK 1: the same three transactions with params.currency OMITTED.
    # ledger.append_entry records amount_by_currency only when currency is
    # truthy, so nothing accumulates and each call re-compares 2000 vs 5000.
    s = sid("133-atk")
    verdicts_a = []
    for i in range(4):
        _, r = call("POST", "/v1/decide", money_envelope(s, 2000),
                    "A5-ATTACK #%d amount=2000, params.currency OMITTED" % (i + 1))
        verdicts_a.append(verdict(r))
    atk_evaded = all(v == "allow" for v in verdicts_a)

    if ctl_tripped and atk_evaded:
        record("RFX-133", "money budget evaded by omitting params.currency",
               "REPRODUCED -- INSECURE",
               "with currency: %s (trips). without currency: %s -- 8000 spent, "
               "budget 5000, never held." % (verdicts, verdicts_a))
    elif ctl_tripped and not atk_evaded:
        record("RFX-133", "money budget evaded by omitting params.currency",
               "SECURE", "with currency: %s. without currency: %s -- the "
               "amount now accumulates regardless." % (verdicts, verdicts_a))
    else:
        record("RFX-133", "money budget evaded by omitting params.currency",
               "INCONCLUSIVE",
               "control did not trip: %s (attack: %s)" % (verdicts, verdicts_a))

    # ATTACK 2 (the UNIT error): EUR 4000 then JPY 2000.  Under the naive sum
    # that is "6000 > 5000" and is HELD -- a wrong-DENY, because the session
    # has moved about EUR 4012.  Under per-currency utilisation it is
    # 4000/5000 + 2000/800000 = 0.8025 and is allowed.  This is the decisive
    # discriminator between a sum of unlike units and a unit-correct budget.
    s = sid("133-mix")
    verdicts_m = []
    for amount, cur in ((4000, "EUR"), (2000, "JPY")):
        _, r = call("POST", "/v1/decide", money_envelope(s, amount, cur),
                    "A5b-UNITS amount=%d currency=%s" % (amount, cur))
        verdicts_m.append("%s%d:%s" % (cur, amount, verdict(r)))
    if verdicts_m[-1].endswith("require_approval"):
        record("RFX-133b", "money budget sums unlike currencies",
               "REPRODUCED -- UNIT ERROR",
               "%s -- EUR 4000 + JPY 2000 (about EUR 4012) was held as "
               "'6000 > 5000'. The number compared against the limit is a sum "
               "of unlike units, not a quantity of money." % verdicts_m)
    else:
        record("RFX-133b", "money budget sums unlike currencies",
               "UNIT-CORRECT",
               "%s -- EUR 4000 (0.800 of its limit) + JPY 2000 (0.0025 of "
               "its limit) = 0.8025 utilisation, correctly not a budget "
               "overage." % verdicts_m)

    # ATTACK 3 (the regression guard on the fix): per-currency budgets ALONE
    # would reopen fragmentation one currency over.  4900 EUR + 4900 USD is
    # ~EUR 9000 and breaches neither individual limit.  This MUST trip on both
    # the old build (naive sum: 9800 > 5000) and the new one (utilisation:
    # 0.980 + 0.891 = 1.871 > 1).  If it ever stops tripping, the unit fix
    # traded one hole for another.
    s = sid("133-split")
    verdicts_s = []
    for cur in ("EUR", "USD"):
        _, r = call("POST", "/v1/decide", money_envelope(s, 4900, cur),
                    "A5c-SPLIT amount=4900 currency=%s" % cur)
        verdicts_s.append("%s:%s" % (cur, verdict(r)))
    if verdicts_s[-1].endswith("require_approval"):
        record("RFX-133c", "spend split across currencies still trips",
               "SECURE", "%s" % verdicts_s)
    else:
        record("RFX-133c", "spend split across currencies still trips",
               "INSECURE -- REGRESSION",
               "%s -- ~EUR 9000 split over two currencies evaded the money "
               "budget entirely." % verdicts_s)


def main() -> int:
    print("target : %s" % probe.BASE)
    print("run    : %s" % probe.RUN)
    fp = fingerprint()
    attack_rfx_127(fp)
    attack_rfx_133(fp)

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    for row in RESULTS:
        print("  %-9s %-46s %s" % (row["id"], row["name"], row["outcome"]))
    print("\nfingerprint: " + json.dumps(fp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
