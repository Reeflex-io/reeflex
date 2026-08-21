"""
ledger.py — In-memory per-session action ledger for cumulative state (SPEC §4.1).

Computes the `cumulative` object injected into policy input BEFORE each eval.
Appends each decided action to the ledger AFTER eval.

RFX-11: in addition to the original per-verb/per-ability/per-currency
breakdowns, this module now also tracks two dimension-agnostic aggregates
that budgets.rego reads to build cumulative CONFIGURABLE budgets over
heterogeneous action types (SPEC §4.1):
  - `count_by_externality`: summed magnitude.count per axes.externality value.
    Lets a "external_sends" budget aggregate across every verb/ability that
    happens to be outbound (email, webhook, DM, ...), not just one verb.
  - `total_count`: summed magnitude.count across EVERY entry, regardless of
    verb/ability/externality. This is the "objects_touched" dimension: every
    action contributes, including the small ones — the long-tail-smurfing
    gap this ticket closes (a competitor's session amplifier assigns 0 to
    small-tier actions, so it never accumulates).

SKELETON SHORTCUTS (upgrade path documented):
  - Storage: in-memory dict. TODO: replace with Postgres-backed ledger for
    persistence across process restarts and multi-replica deployments.
  - Expiry: entries outside the rolling window are excluded from cumulative
    computation but are NOT pruned from memory. TODO: add a background sweep
    (or lazy prune on access) to cap memory usage in production.
  - currency/amount: skeleton records count only; amount_by_currency requires
    the adapter to supply params.amount + params.currency. TODO: extract those
    from the envelope params when the financial verb set (transact) is used.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from .envelope import canonicalize_currency, is_money_amount

# THE ENVELOPE FIELDS THIS MODULE READS.
#
# The ledger is the SECOND reader of the envelope, after policy/*.rego, and it
# is the one that made RFX-133 invisible: `params.currency` appears nowhere in
# any .rego file, yet omitting it disabled the money budget entirely, because
# this module decides what lands in `cumulative.amount_by_currency`.  Any
# enumeration of "fields the policy reads" that scans only the Rego therefore
# MISSES a whole class of caller-supplied inputs.
#
# So the paths are declared here, next to the code that reads them, and
# app/field_treatments.py requires each to carry a declared treatment.
# tests/test_field_treatments.py AST-scans append_entry() and fails if it
# reads an envelope path that is not in this tuple.
LEDGER_ENVELOPE_PATHS: tuple[str, ...] = (
    "action.verb",
    "action.ability",
    "axes.externality",
    "magnitude.count",
    "params.amount",
    "params.currency",
)

_lock = threading.Lock()

# { session_id -> [ {ts, verb, ability, count}, ... ] }
_ledger: dict[str, list[dict]] = {}


def compute_cumulative(session_id: str, window_seconds: int) -> dict:
    """
    Return the cumulative object for all PRIOR entries in the session within
    the rolling window.  Called BEFORE appending the current action, so the
    result reflects history only (SPEC §4.1: cumulative reflects prior actions;
    magnitude.count is the current one).
    """
    now = time.time()
    cutoff = now - window_seconds

    count_by_verb: dict[str, int] = {}
    count_by_ability: dict[str, int] = {}
    count_by_externality: dict[str, int] = {}
    amount_by_currency: dict[str, float] = {}
    total_count = 0

    with _lock:
        entries = _ledger.get(session_id, [])
        for entry in entries:
            if entry["ts"] < cutoff:
                continue
            verb = entry["verb"]
            ability = entry.get("ability") or ""
            externality = entry.get("externality") or ""
            count_by_verb[verb] = count_by_verb.get(verb, 0) + entry["count"]
            if ability:
                count_by_ability[ability] = count_by_ability.get(ability, 0) + entry["count"]
            if externality:
                count_by_externality[externality] = (
                    count_by_externality.get(externality, 0) + entry["count"]
                )
            # objects_touched: every entry contributes, whatever its verb/
            # ability/externality — the cross-cutting aggregate that makes
            # heterogeneous small actions accumulate (RFX-11).
            total_count += entry["count"]
            # Amount tracking — only populated if adapter supplied it
            for currency, amount in entry.get("amount_by_currency", {}).items():
                amount_by_currency[currency] = (
                    amount_by_currency.get(currency, 0.0) + amount
                )

    return {
        "window_seconds": window_seconds,
        "count_by_verb": count_by_verb,
        "count_by_ability": count_by_ability,
        "count_by_externality": count_by_externality,
        "amount_by_currency": amount_by_currency,
        "total_count": total_count,
    }


def append_entry(session_id: str, envelope: dict) -> None:
    """
    Append the decided action to the session ledger.
    Called AFTER OPA eval so cumulative only reflects settled decisions.
    """
    entry: dict[str, Any] = {
        "ts": time.time(),
        "verb": envelope.get("action", {}).get("verb", "unknown"),
        "ability": envelope.get("action", {}).get("ability", ""),
        "externality": (envelope.get("axes") or {}).get("externality", ""),
        "count": int((envelope.get("magnitude") or {}).get("count") or 1),
        "amount_by_currency": {},
    }

    # Extract financial amounts from params if present (transact verb support).
    # Defensive: envelope.py normalizes params to dict, but guard here too so
    # ledger never crashes even if called with a raw (un-normalized) envelope.
    #
    # RFX-133 — THE CONDITION USED TO BE `if currency and isinstance(...)`, so
    # an amount with NO currency was silently DROPPED and never accumulated.
    # That single `and` was the whole evasion: N calls of (limit - 1) with
    # `params.currency` omitted each re-compared one amount against the money
    # budget and the session's spend was never summed at all.  An amount is now
    # ALWAYS recorded; a missing/unusable currency lands in the "XXX" bucket
    # (ISO 4217 "no currency involved"), which is a real accumulating bucket
    # with its own limit, not a discard.
    #
    # abs(): the amount is an EXPOSURE, not a signed balance.  A negative
    # amount (a refund, a reversal, or just a caller writing "-5000") would
    # otherwise SUBTRACT from cumulative spend, letting a session alternate
    # +N/-N forever and never accumulate.  Money moved is money moved.
    #
    # canonicalize_currency() is imported from the envelope boundary rather
    # than re-implemented, so the ledger's bucket keys and the keys the policy
    # matches on cannot drift apart.
    _raw_params = envelope.get("params")
    params = _raw_params if isinstance(_raw_params, dict) else {}
    amount = params.get("amount")
    if is_money_amount(amount):
        currency = canonicalize_currency(params.get("currency"))
        entry["amount_by_currency"] = {currency: abs(float(amount))}

    with _lock:
        if session_id not in _ledger:
            _ledger[session_id] = []
        _ledger[session_id].append(entry)


def clear_session(session_id: str) -> None:
    """Remove a session ledger entry entirely (used in tests)."""
    with _lock:
        _ledger.pop(session_id, None)
