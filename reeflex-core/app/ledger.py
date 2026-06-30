"""
ledger.py — In-memory per-session action ledger for cumulative state (SPEC §4.1).

Computes the `cumulative` object injected into policy input BEFORE each eval.
Appends each decided action to the ledger AFTER eval.

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
    amount_by_currency: dict[str, float] = {}

    with _lock:
        entries = _ledger.get(session_id, [])
        for entry in entries:
            if entry["ts"] < cutoff:
                continue
            verb = entry["verb"]
            ability = entry.get("ability") or ""
            count_by_verb[verb] = count_by_verb.get(verb, 0) + entry["count"]
            if ability:
                count_by_ability[ability] = count_by_ability.get(ability, 0) + entry["count"]
            # Amount tracking — only populated if adapter supplied it
            for currency, amount in entry.get("amount_by_currency", {}).items():
                amount_by_currency[currency] = (
                    amount_by_currency.get(currency, 0.0) + amount
                )

    return {
        "window_seconds": window_seconds,
        "count_by_verb": count_by_verb,
        "count_by_ability": count_by_ability,
        "amount_by_currency": amount_by_currency,
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
        "count": int((envelope.get("magnitude") or {}).get("count") or 1),
        "amount_by_currency": {},
    }

    # Extract financial amounts from params if present (transact verb support).
    # Defensive: envelope.py normalizes params to dict, but guard here too so
    # ledger never crashes even if called with a raw (un-normalized) envelope.
    _raw_params = envelope.get("params")
    params = _raw_params if isinstance(_raw_params, dict) else {}
    currency = params.get("currency")
    amount = params.get("amount")
    if currency and isinstance(amount, (int, float)):
        entry["amount_by_currency"] = {currency: float(amount)}

    with _lock:
        if session_id not in _ledger:
            _ledger[session_id] = []
        _ledger[session_id].append(entry)


def clear_session(session_id: str) -> None:
    """Remove a session ledger entry entirely (used in tests)."""
    with _lock:
        _ledger.pop(session_id, None)
