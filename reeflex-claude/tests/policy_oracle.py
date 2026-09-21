"""
policy_oracle.py -- the ONE offline transcription of the shipped policy pack
(RFX-303).

WHY THIS FILE EXISTS
====================
The Bash conformance corpus is scored on two planes:

  offline  tests/test_conformance_bash.py -- classifier + this oracle, no
           network, no OPA, so a classifier change that stops routing a
           production destruction to a human fails in a unit suite
  live     scripts/attack-probe-rfx144-agent-prices-own-action.py -- the same
           corpus through the real hook against a real reeflex-core

Until RFX-303 the oracle was a copy of R1-R4 living inside the offline test
file, the live arm was run by nothing at all, and the two planes had therefore
never been compared. Two divergences had accumulated in that gap, both
measured against reeflex-core v0.2.1 (the build api-dev.reeflex.io runs):

  1. THE ORACLE WAS MISSING R6. `rm /srv/app/truncate.log` -- one corpus case,
     in the `everyday` regression floor -- is held live by
     `reeflex.policy/irreversible_protected_asset_prod` and was scored `allow`
     offline. /srv/ is in the shipped pack's `protected_assets`.
  2. THE ORACLE RANKED R1 FIRST; THE PACK RANKS IT LAST. reeflex.rego's
     `read_only_internal` decision carries `not r2/r3/budget/r6/r7` guards and
     says why, verbatim: "Letting R1 win would therefore hand back a one-field
     evasion of R6 (relabel the delete `read`)". The oracle contained exactly
     that evasion -- an envelope declaring verb=read on an irreversible broad
     production action scored `allow` here and `require_approval` on a real
     core.

So this module is deliberately NOT in the offline test file and NOT in the
shipped package: both planes import it, which is what makes the sentence "the
two are kept honest against each other" true rather than aspirational.

NOT PART OF THE ADAPTER. `reeflex_claude` does not import this module and must
not. The adapter classifies; core decides. This is an instrument that lets a
unit suite predict what core will say -- and the live arm is what proves the
prediction.

WHAT THIS ORACLE DOES NOT MODEL -- read before trusting an offline green
=======================================================================
  R0  `unclassified_action` -- fires on `provenance.undeclared`, which CORE
      computes from what the envelope omitted (it is not caller-supplied). The
      adapter declares every axis R0 reads, so no corpus case reaches it. That
      was measured 0 of 84 on v0.2.1 and has NOT been re-measured since; the
      count is left here as the date-stamped observation it is rather than
      refreshed into a number that will rot again.
  R5  cumulative budgets -- needs session history. The probe gives every case
      its own session id, so every corpus call is a first call and no budget
      can accumulate. R5 can only ever make a verdict stricter, never looser.
  R7  `authority_change_prod` -- authority.rego holds three operator-editable
      signal lists and a tokenizer. Transcribing those would add more drift
      surface than it removes, and no corpus case reaches it.

      THAT LAST CLAUSE IS NOW ASSERTED, NOT COUNTED (RFX-327). It used to read
      "measured 0 of 84" -- a count taken once, against a corpus that has since
      passed 150 cases with nothing re-taking it. R7 fires on
      `action.ability`, which envelope.py composes as `claude-code/<tool>`, so
      reachability is a property of the TOOL NAME and changes the moment a row
      is added for a tool whose name carries a signal token
      (`mcp__admin__grant_role` -> {grant, role} is a match; every built-in
      tool in the corpus today is not).
      `TestTheUnmodelledRulesAreStillUnreachable` in test_conformance_bash.py
      re-derives it from the shipped rego on every run, so the day a case does
      reach R7 the suite says so instead of the docstring being quietly wrong.
      A case that reaches it also shows up as a live-vs-oracle divergence,
      which is the whole point of the live arm -- but only if the live arm ran,
      and it needs a real core.
  THE REF IS COMPARED RAW. Core canonicalises `target.ref` first (envelope.py
      F9: `..` segments, doubled separators, zero-width characters), and this
      module does not. A ref that only becomes protected after canonicalisation
      is scored unprotected here and held live -- again, a divergence the live
      arm reports rather than a silent disagreement.
"""

from __future__ import annotations

import pathlib
import re

# --------------------------------------------------------------------------
# Transcribed from reeflex-core/policy/protected.rego.
#
# These are policy DATA an operator edits, not engine constants, so a
# transcription here is exactly the kind of hand-copied model RFX-303 is
# about. It is kept honest two ways: `protected_assets_from_rego()` below
# parses the shipped file, and test_conformance_bash.py asserts the two agree
# on every run where the monorepo is present.
# --------------------------------------------------------------------------

PROTECTED_PREFIXES = (
    "/srv/",
    "/var/lib/",
    "/var/opt/",
    "/var/spool/",
    "/var/backups/",
    "/data/",
    "/mnt/data/",
    "/opt/data/",
)

EPHEMERAL_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/var/cache/",
    "/dev/shm/",
    "/run/",
)

# protected.rego's posture switch. false = only declared assets are protected.
DEFAULT_PROTECTED = False

_REGO = pathlib.Path(__file__).resolve().parents[2] / "reeflex-core" / "policy" / "protected.rego"

_ARRAY_RE = r"^%s\s*:=\s*\[(.*?)\]"
_BOOL_RE = r"^%s\s*:=\s*(true|false)\s*$"


def rego_path() -> pathlib.Path:
    """protected.rego in the monorepo; may not exist (installed wheel)."""
    return _REGO


def protected_assets_from_rego(path=None):
    """Parse (protected_assets, ephemeral_assets, default_protected) out of the
    shipped rego. Returns None when the file is absent."""
    path = pathlib.Path(path) if path else _REGO
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")

    def _array(name):
        m = re.search(_ARRAY_RE % name, text, re.M | re.S)
        if not m:
            return None
        return tuple(re.findall(r'"([^"]*)"', m.group(1)))

    m = re.search(_BOOL_RE % "default_protected", text, re.M)
    return {
        "protected_assets": _array("protected_assets"),
        "ephemeral_assets": _array("ephemeral_assets"),
        "default_protected": (m.group(1) == "true") if m else None,
    }


# --------------------------------------------------------------------------
# R7 REACHABILITY (RFX-327).  NOT a transcription of R7 -- read the difference.
#
# The docstring above declines to model R7 and justifies it with "no corpus case
# reaches it".  That justification was a COUNT, taken once at 84 cases; the
# corpus is past 150 and nothing re-took it.  A residual whose evidence is a
# number someone typed is the shape RFX-303 and RFX-327 are both about, so the
# claim is now asserted on every run instead (test_conformance_bash.py,
# TestTheUnmodelledRulesAreStillUnreachable).
#
# What is parsed here decides NO verdict.  It answers one question -- could any
# corpus row's `action.ability` match an R7 signal -- so the oracle's silence
# about R7 stays a measured fact rather than an inherited sentence.  The signal
# lists are PARSED from the shipped file, exactly as protected_assets_from_rego
# parses protected.rego; only the tokenizer is mirrored.
#
# THE RESIDUAL IN THIS GUARD, SAID OUT LOUD: `ability_tokens` mirrors
# authority.rego's two regex lines.  If the rego tokenizer widens and this one
# does not, this guard goes quietly green on a row it should have caught -- i.e.
# it fails back to exactly where main is today, an unmeasured claim, and never
# to a false red.  That is why it is worth having and why it is not a proof.
# --------------------------------------------------------------------------

_AUTHORITY_REGO = pathlib.Path(__file__).resolve().parents[2] / "reeflex-core" / "policy" / "authority.rego"

_SET_RE = r"^%s\s*:=\s*\{(.*?)\}"


def authority_rego_path() -> pathlib.Path:
    """authority.rego in the monorepo; may not exist (installed wheel)."""
    return _AUTHORITY_REGO


def authority_signals_from_rego(path=None):
    """The union of authority.rego's three operator-editable signal lists.

    Returns None when the file is absent, so an installed wheel skips rather
    than passing over an empty set.
    """
    path = pathlib.Path(path) if path else _AUTHORITY_REGO
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    signals = set()
    found = []
    for name in ("authority_signals", "credential_signals", "executable_signals"):
        m = re.search(_SET_RE % name, text, re.M | re.S)
        if m:
            found.append(name)
            signals |= set(re.findall(r'"([^"]*)"', m.group(1)))
    # A rename in the rego must not read as "no signals, nothing reachable".
    if len(found) != 3:
        return {"signals": signals, "lists_found": found, "complete": False}
    return {"signals": signals, "lists_found": found, "complete": True}


def ability_tokens(raw):
    """authority.rego's `ability_tokens`: camelCase humps first, then split on
    every run of non-alphanumerics, lowercased, empties dropped."""
    if not isinstance(raw, str):
        return set()
    humped = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", raw)
    return {t for t in re.split(r"[^a-zA-Z0-9]+", humped.lower()) if t}


def _under(key: str, prefix: str) -> bool:
    """protected.rego's `_under`: prefix match, plus exact match on the prefix
    with its trailing separator removed, so "/srv/" protects "/srv" itself."""
    prefix = prefix.lower()
    return key.startswith(prefix) or key == prefix.rstrip("/")


def protected_target(target_ref) -> bool:
    """protected.rego's `protected_target`, both postures.

    A ref that is absent, null or not a string becomes "" -- which matches no
    prefix under the default posture, and is NOT ephemeral under the strict
    one, exactly as the rego has it.
    """
    key = target_ref.lower() if isinstance(target_ref, str) else ""
    if not DEFAULT_PROTECTED:
        return any(_under(key, p) for p in PROTECTED_PREFIXES)
    return not any(_under(key, p) for p in EPHEMERAL_PREFIXES)


def policy_oracle_rule(cls: dict, environment: str = "production"):
    """
    Return (verdict, rule_id) for a FIRST call in a session, in the pack's own
    precedence order: R3, R2, R6, R1, R4.

    THE ORDER IS THE POINT. reeflex.rego produces a single decision via
    explicit guards, and R1 is the second-to-last clause, not the first --
    see the module docstring, defect (2).
    """
    irreversible = cls.get("reversibility") == "irreversible"
    production = environment == "production"
    blast = cls.get("blast_radius")

    # R3 -- irreversible + systemic + production. Terminal.
    if irreversible and blast == "systemic" and production:
        return "deny", "reeflex.policy/irreversible_systemic_prod"

    # R2 -- the SPEC headline rule: irreversible + broad + production.
    if irreversible and blast == "broad" and production:
        return "ask", "reeflex.policy/irreversible_broad_prod"

    # R5 would sit here. Not modelled -- see the module docstring.

    # R6 -- irreversible production change to a DECLARED production asset, at
    # any cardinality (RFX-153). Reads neither blast_radius nor the verb.
    if irreversible and production and protected_target(cls.get("target_ref")):
        return "ask", "reeflex.policy/irreversible_protected_asset_prod"

    # R7 would sit here. Not modelled -- see the module docstring.

    # R1 -- read-only internal, and ONLY when nothing above applied.
    if cls.get("verb") == "read" and cls.get("externality") == "internal":
        return "allow", "reeflex.policy/read_only_internal"

    # R4 -- default.
    return "allow", "reeflex.policy/default_allow"


def policy_oracle(cls: dict, environment: str = "production") -> str:
    """The verdict alone, for call sites that do not need the rule id."""
    return policy_oracle_rule(cls, environment)[0]
