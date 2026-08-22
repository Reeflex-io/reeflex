"""
ledger.py — Durable, shared, per-session action ledger for cumulative state
(SPEC §4.1).

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

=============================================================================
RFX-197 — WHY THIS MODULE IS A FILE AND NOT A DICT
=============================================================================

R5's cumulative budget is the entire substance of the product's headline
anti-fragmentation claim (README: "a per-session cumulative ledger defeats
split-batch evasion"; docs/why-reeflex.md's competitive table: "fragmentation
buys nothing"; the n8n package ships a demo whose FILENAME is
demo2-fragmentation-doesnt-work).

Until RFX-197 this module stored that ledger in a process-local dict, and its
own docstring said so under "SKELETON SHORTCUTS". Measured on the customer
artefact (the root Dockerfile) at main 7f9ebf8, with the shipped
`deletions: {limit: 20}` budget and ONE session_id:

    CONTROL   same live process, 4 x count=5 ->  5th call held
    VECTOR A  `docker restart`, replay the SAME session -> 20 more deletes
              allowed, no human, and the 5th call held again from zero
    VECTOR B  a SECOND replica of the same image, SAME session, no restart
              -> another 20 allowed

So the guarantee held for exactly one process that had never been restarted,
and the ordinary HA shape (two replicas behind a load balancer) silently
multiplied every session budget by the replica count, continuously. No
attacker, no privilege, no race: just a restart, or a second container.

THREE THINGS THIS MODULE NOW DOES ABOUT THAT.

1. DURABLE.  Entries are appended to an event-sourced JSONL file
   (REEFLEX_LEDGER_PATH, default alongside the audit log), following holds.py
   exactly — append-only, fsync, read-back proof, in-memory state folded from
   the file. A restart resumes the window instead of zeroing it.

2. SHARED.  The in-memory index is NOT authoritative. Every read
   re-synchronises from the file first (an incremental tail read from a
   remembered offset, so the cost is the bytes another replica appended, not
   the file), which means two replicas that share the volume share ONE
   budget. The file — not any process's memory — is the ledger.

3. ATOMIC ACROSS THE READ-DECIDE-WRITE.  `session_guard(session_id)` is a
   context manager a caller holds across

       compute_cumulative()  ->  OPA eval  ->  append_entry()

   taking BOTH a per-stripe thread lock and a per-stripe POSIX record lock
   (fcntl.lockf byte range) on a sidecar lock file, so the cycle is atomic
   across threads AND across processes. decide.py holds it for exactly that
   span.

   This is the guard qa--012 asked for and qa--030 measured the absence of.
   Their finding was that the race does not currently occur — because
   app/server.py builds a single-threaded http.server.HTTPServer, so requests
   never overlap. That is an accident of the dev-server choice, not a
   designed property: the moment RFX-198 makes the request path concurrent
   (ThreadingHTTPServer, or workers), two calls on one session would both
   read the same prior cumulative, both compare (prior + current) against the
   limit, and both be allowed. The budget's correctness must not depend on
   the server class, so the guard exists whether or not anything overlaps
   today.

   Locks are STRIPED by hash(session_id), so different sessions do not
   serialise against each other; two sessions colliding on a stripe wait on
   each other, which is a latency cost, never a correctness one.

WHAT THIS DOES NOT FIX — STATED HERE AND NOT ONLY IN THE ROADMAP.
Replicas that do NOT share a filesystem (separate hosts, ReadWriteOnce
volumes, `docker compose down` with no named volume) still each keep their own
ledger, and each therefore grants a full budget. A file cannot fix that; the
shared-store upgrade (docs/roadmap.md: the Postgres-backed ledger) can. So
this module REPORTS its own scope rather than leaving the operator to assume:
`ledger_epoch()` states the mode and path, /healthz exposes it, and every
boot writes a `ledger_epoch` marker to the audit stream — see below.

FAIL-CLOSED, deliberately asymmetric with audit.py.  audit.py is EVIDENCE and
is best-effort: decide.py wraps it so a failed audit write never changes a
decision. This module is ENFORCEMENT: if the ledger cannot record an action,
the next call's budget would under-count, so `append_entry()` RAISES
(LedgerWriteError) and decide.py turns that into a denial. An enforcement
point that cannot remember must refuse, not wave through.

THE STARTUP MARKER (RFX-197's second half).  The old failure was not only
that the counter reset — it was that the reset was invisible. Two consecutive
audit rows for one session, eleven seconds apart, both declaring
`window_seconds: 3600`, carried `count_by_verb.delete` 20 then 0: a monotonic
counter moving backwards inside its own declared window, machine-detectable,
and nothing detected it. `grep -icE 'start|boot|restart|ledger|reset|epoch'`
over the whole audit log returned 0. So: every boot mints an epoch id, writes
one `{"event": "ledger_epoch", ...}` record to the audit stream saying what it
restored and whether it is durable at all, and every decision record carries
the `ledger_epoch` it was decided under. A counter that falls now has a named
cause on the same append-only stream that carries the contradiction.

SKELETON SHORTCUTS THAT REMAIN (upgrade path documented):
  - Storage: append-only JSONL on a shared filesystem. TODO: Postgres-backed
    ledger for replicas that do not share one (docs/roadmap.md).
  - Boot scan: bounded to the last REEFLEX_LEDGER_SCAN_BYTES (default 64 MiB)
    of the file, because everything inside a one-hour window is at the tail.
    If that cap is hit while still inside the window the epoch record says
    `scan_truncated: true` — under-counting is visible, not silent.
  - currency/amount: skeleton records count only; amount_by_currency requires
    the adapter to supply params.amount + params.currency.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import sys
import threading
import time
import uuid
from typing import Any, Iterator

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

# Number of lock stripes. Sessions are hashed onto stripes so unrelated
# sessions do not serialise; the byte range [0, _STRIPES) of the lock file is
# the per-session space and byte _STRIPES is the append serialisation point.
_STRIPES = 64
_APPEND_BYTE = _STRIPES

_DEFAULT_SCAN_BYTES = 64 * 1024 * 1024  # 64 MiB of tail is ~ hours of traffic
_PRUNE_INTERVAL_SECONDS = 60.0

# `_lock` protects the in-memory index and the file-read cursor. It is
# RE-ENTRANT because session_guard() -> compute_cumulative()/append_entry()
# is a legitimate nesting.
_lock = threading.RLock()

# Per-stripe thread locks. POSIX record locks are held per PROCESS, so two
# threads of one process locking the same byte range do NOT exclude each
# other; the thread lock is what makes the guard work in-process, and the
# record lock is what makes it work across processes.
_stripe_locks: list[threading.RLock] = [threading.RLock() for _ in range(_STRIPES)]

# Re-entrancy bookkeeping for the record lock: only the OUTERMOST guard for a
# stripe may take (and release) the byte range, because releasing it from an
# inner exit would drop the lock while the outer holder still needs it.
_held = threading.local()

# { session_id -> [ {ts, verb, ability, count}, ... ] } — folded from the
# file; never the authority, always a cache of it.
_ledger: dict[str, list[dict]] = {}

# Read cursor into the ledger file: which file (st_dev, st_ino) and how many
# bytes of it have been folded into `_ledger`.
_read_key: tuple[int, int] | None = None
_read_offset: int = 0
_loaded = False
_scan_truncated = False
_last_prune: float = 0.0

# Epoch identity for this process's view of the ledger. Minted when the file
# is first folded (or when persistence is off), so it names a CONTINUITY
# boundary: a new epoch id in the audit stream is exactly the event that
# explains a cumulative counter that fell.
_epoch: dict[str, Any] = {}

# The lock-file descriptor. Opened once and NEVER closed: closing ANY
# descriptor for a file drops every POSIX record lock this process holds on
# it, so a stray close() would silently disarm the guard.
_lock_fd: int | None = None
_lock_fd_lock = threading.Lock()


class LedgerWriteError(RuntimeError):
    """The action could not be recorded, so the next budget would under-count.

    Raised by append_entry(). decide.py converts this into a fail-closed
    denial: an enforcement point that cannot remember must refuse.
    """


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _persist_enabled() -> bool:
    """Is the ledger durable? DEFAULT YES; only an explicit off-word disables.

    Tri-state parse, the RFX-84 idiom: an unrecognised value reads as the
    DEFAULT (durable), never as the opt-out. A typo in a deployment's env
    must not silently return the product to the RFX-197 behaviour.
    """
    raw = os.environ.get("REEFLEX_LEDGER_PERSIST", "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    return True


def ledger_path() -> pathlib.Path:
    env_path = os.environ.get("REEFLEX_LEDGER_PATH", "")
    if env_path:
        return pathlib.Path(env_path)
    here = pathlib.Path(__file__).resolve()
    return here.parent.parent / "audit" / "ledger.jsonl"


def _lock_path() -> pathlib.Path:
    return ledger_path().with_suffix(ledger_path().suffix + ".lock")


def _default_window_seconds() -> int:
    """The rolling window, for the epoch record when no caller supplied one.

    Deliberately a module-level helper and NOT an inline
    `os.environ.get("REEFLEX_WINDOW_SECONDS")` inside append_entry():
    tests/test_field_treatments.py AST-scans append_entry() for every
    `.get("literal")` and treats an undeclared one as an envelope path this
    module reads without declaring. That guard exists because `params.currency`
    (RFX-133) slipped past exactly such an enumeration, so the right response to
    it firing is to stop reading config in the hot append path -- not to widen
    the allow-list until the scan means nothing.
    """
    try:
        return int(os.environ.get("REEFLEX_WINDOW_SECONDS", "3600"))
    except (ValueError, TypeError):
        return 3600


def _scan_bytes() -> int:
    try:
        n = int(os.environ.get("REEFLEX_LEDGER_SCAN_BYTES", str(_DEFAULT_SCAN_BYTES)))
    except (ValueError, TypeError):
        return _DEFAULT_SCAN_BYTES
    return n if n > 0 else _DEFAULT_SCAN_BYTES


# ---------------------------------------------------------------------------
# The cross-process guard
# ---------------------------------------------------------------------------

def _stripe_for(session_id: str) -> int:
    # sha256 rather than hash(): PYTHONHASHSEED randomises str hashes per
    # process, so two replicas would map one session to DIFFERENT stripes and
    # the record lock would not exclude them at all.
    digest = hashlib.sha256((session_id or "").encode("utf-8")).digest()
    return digest[0] % _STRIPES


def _get_lock_fd() -> int | None:
    """Open (once) the sidecar lock file. None if it cannot be opened."""
    global _lock_fd
    if _lock_fd is not None:
        return _lock_fd
    with _lock_fd_lock:
        if _lock_fd is not None:
            return _lock_fd
        try:
            path = _lock_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            print(
                f"[reeflex-core] WARN: ledger lock file unavailable ({exc}); "
                "cross-process budget serialisation is DISABLED",
                file=sys.stderr,
            )
            return None
        _lock_fd = fd
        return _lock_fd


def _byte_lock(stripe: int) -> None:
    fd = _get_lock_fd()
    if fd is None:
        return
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX, 1, stripe, 0)
    except OSError:
        pass  # degrade to thread-only exclusion rather than refusing to serve


def _byte_unlock(stripe: int) -> None:
    fd = _get_lock_fd()
    if fd is None:
        return
    try:
        fcntl.lockf(fd, fcntl.LOCK_UN, 1, stripe, 0)
    except OSError:
        pass


@contextlib.contextmanager
def session_guard(session_id: str) -> Iterator[None]:
    """Hold one session's budget across read -> decide -> write.

    Callers (decide.py) wrap compute_cumulative() ... append_entry() in this,
    so no other thread OR process can slip a decision for the same session
    between the read of the cumulative and the write of the entry.

    Re-entrant per thread. Never raises: if the lock file is unavailable the
    guard degrades to in-process exclusion and says so on stderr once, rather
    than failing a decision that would otherwise be correct.
    """
    stripe = _stripe_for(session_id)
    depths: dict[int, int] = getattr(_held, "depths", None)  # type: ignore[assignment]
    if depths is None:
        depths = {}
        _held.depths = depths

    _stripe_locks[stripe].acquire()
    outermost = depths.get(stripe, 0) == 0
    depths[stripe] = depths.get(stripe, 0) + 1
    try:
        if outermost:
            _byte_lock(stripe)
        yield
    finally:
        depths[stripe] -= 1
        if depths[stripe] == 0 and outermost:
            _byte_unlock(stripe)
        _stripe_locks[stripe].release()


# ---------------------------------------------------------------------------
# The file: fold, sync, append
# ---------------------------------------------------------------------------

def _fold_record(rec: dict) -> None:
    """Apply one ledger event to the in-memory index. Must hold `_lock`."""
    session_id = rec.get("session_id")
    if not session_id:
        return
    event_type = rec.get("event_type", "entry")
    if event_type == "entry":
        _ledger.setdefault(session_id, []).append({
            "ts": float(rec.get("ts") or 0.0),
            "verb": rec.get("verb", "unknown"),
            "ability": rec.get("ability", ""),
            "externality": rec.get("externality", ""),
            "count": int(rec.get("count") or 0),
            "amount_by_currency": dict(rec.get("amount_by_currency") or {}),
        })
    elif event_type == "clear":
        # A recorded reset, not a rewrite: the file stays append-only, and the
        # fold drops everything appended for that session BEFORE this record.
        _ledger.pop(session_id, None)


def _initial_offset(fh, size: int) -> int:
    """Where to start the first fold. Bounded tail; sets _scan_truncated."""
    global _scan_truncated
    cap = _scan_bytes()
    if size <= cap:
        _scan_truncated = False
        return 0
    _scan_truncated = True
    fh.seek(size - cap)
    fh.readline()  # discard the partial line the cap landed inside
    return fh.tell()


def _sync_from_file() -> None:
    """Fold everything appended since our cursor. Must hold `_lock`.

    This is what makes two replicas share one budget: the authority is the
    file, and every read catches up on the other replica's appends first. The
    cost is the new bytes, not the file.
    """
    global _read_key, _read_offset, _loaded

    if not _persist_enabled():
        _loaded = True
        return

    path = ledger_path()
    try:
        st = os.stat(path)
    except OSError:
        # No file yet (or unreadable): nothing to fold. A later append creates
        # it; the cursor stays at 0 so the next sync picks the file up.
        _loaded = True
        return

    key = (st.st_dev, st.st_ino)
    fresh = _read_key != key or st.st_size < _read_offset
    if fresh:
        # A different file, or one that shrank under us (rotated/truncated):
        # the cursor means nothing, so rebuild from a bounded tail.
        _ledger.clear()
        _read_key = key
        _read_offset = 0

    if not fresh and st.st_size == _read_offset:
        _loaded = True
        return

    try:
        with open(path, "rb") as fh:
            start = _initial_offset(fh, st.st_size) if fresh else _read_offset
            fh.seek(start)
            chunk = fh.read()
    except OSError as exc:
        print(f"[reeflex-core] WARN: ledger read failed: {exc}", file=sys.stderr)
        _loaded = True
        return

    # Consume COMPLETE lines only. A concurrent replica may be mid-append; the
    # trailing partial line stays unconsumed so the next sync sees it whole.
    consumed = chunk.rfind(b"\n")
    if consumed == -1:
        _loaded = True
        return
    body = chunk[: consumed + 1]
    for raw in body.split(b"\n"):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue  # skip a corrupt line; never raise on a read
        if isinstance(rec, dict):
            _fold_record(rec)
    _read_offset = start + consumed + 1
    _loaded = True


def _maybe_prune(window_seconds: int) -> None:
    """Drop out-of-window entries from memory. Must hold `_lock`.

    Closes the second documented skeleton shortcut ("entries outside the
    rolling window are excluded from cumulative computation but are NOT
    pruned from memory"), which is now load-bearing: a durable ledger is read
    back at boot, so an unpruned index would grow with the file.
    """
    global _last_prune
    now = time.time()
    if now - _last_prune < _PRUNE_INTERVAL_SECONDS:
        return
    _last_prune = now
    cutoff = now - window_seconds
    for session_id in list(_ledger.keys()):
        kept = [e for e in _ledger[session_id] if e["ts"] >= cutoff]
        if kept:
            _ledger[session_id] = kept
        else:
            del _ledger[session_id]


def _append_record(rec: dict) -> None:
    """Append one record + fsync + read-back proof. Raises LedgerWriteError.

    Serialised across processes on the dedicated append byte of the lock file
    so two replicas cannot interleave halves of a line, and so the read-back
    offset arithmetic is exact.
    """
    path = ledger_path()
    line = (json.dumps(rec, separators=(",", ":")) + "\n").encode("utf-8")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise LedgerWriteError(f"ledger directory not writable: {exc}") from exc

    fd = _get_lock_fd()
    if fd is not None:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX, 1, _APPEND_BYTE, 0)
        except OSError:
            fd = None
    try:
        with open(path, "ab") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
            end = fh.tell()
        # Read-back proof (audit.py / holds.py discipline): re-read the exact
        # byte range we believe we wrote. Under concurrent appends the LAST
        # line may be another replica's, so we verify OUR offset, not the tail.
        with open(path, "rb") as fh:
            fh.seek(max(end - len(line), 0))
            got = fh.read(len(line))
        if got != line:
            raise LedgerWriteError(
                "ledger read-back mismatch: the entry is not on disk where it "
                "was written"
            )
    except LedgerWriteError:
        raise
    except OSError as exc:
        raise LedgerWriteError(f"ledger append failed: {exc}") from exc
    finally:
        if fd is not None:
            try:
                fcntl.lockf(fd, fcntl.LOCK_UN, 1, _APPEND_BYTE, 0)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Epoch — the startup marker RFX-197 found missing
# ---------------------------------------------------------------------------

def _ensure_loaded(window_seconds: int | None = None) -> None:
    """First-use fold + epoch mint. Must hold `_lock`."""
    if _loaded:
        return
    _sync_from_file()
    _mint_epoch(_default_window_seconds() if window_seconds is None else window_seconds)


def _mint_epoch(window_seconds: int) -> None:
    """Record what this process restored, and whether it can remember at all."""
    global _epoch
    durable = _persist_enabled()
    _epoch = {
        "epoch_id": uuid.uuid4().hex,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "durable": durable,
        "path": str(ledger_path()) if durable else "",
        "window_seconds": window_seconds,
        "restored_sessions": len(_ledger),
        "restored_entries": sum(len(v) for v in _ledger.values()),
        "scan_truncated": _scan_truncated,
    }
    if not durable:
        print(
            "[reeflex-core] WARN: session ledger is EPHEMERAL "
            "(REEFLEX_LEDGER_PERSIST is off): every cumulative budget resets "
            "on restart and is not shared with any other replica",
            file=sys.stderr,
        )
    else:
        print(
            f"[reeflex-core] ledger epoch {_epoch['epoch_id'][:12]} — restored "
            f"{_epoch['restored_entries']} entries across "
            f"{_epoch['restored_sessions']} sessions from {_epoch['path']}",
            file=sys.stderr,
        )
    # The audit stream is where an auditor sees the cumulative counters, so it
    # is where the explanation for a counter that fell has to be. Best-effort:
    # a missing marker must not stop the engine deciding.
    try:
        from .audit import record_ledger_epoch  # local import: avoid a cycle

        record_ledger_epoch(dict(_epoch))
    except Exception as exc:  # noqa: BLE001
        print(
            f"[reeflex-core] WARN: ledger epoch marker not audited: {exc}",
            file=sys.stderr,
        )


def ledger_epoch() -> dict:
    """This process's ledger continuity record (also served by /healthz).

    `epoch_id` names a continuity boundary: a decision record carrying a new
    epoch_id is exactly the event that explains a cumulative counter which
    fell inside its own declared window.
    """
    with _lock:
        if not _epoch:
            _ensure_loaded()
        return dict(_epoch)


def is_durable() -> bool:
    return _persist_enabled()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_cumulative(session_id: str, window_seconds: int) -> dict:
    """
    Return the cumulative object for all PRIOR entries in the session within
    the rolling window.  Called BEFORE appending the current action, so the
    result reflects history only (SPEC §4.1: cumulative reflects prior actions;
    magnitude.count is the current one).

    RFX-197: reads the FILE, not just this process's memory — so a restarted
    process resumes the window and a second replica sharing the volume sees
    the first replica's spend. Caller holds session_guard() across this and
    the matching append_entry().
    """
    now = time.time()
    cutoff = now - window_seconds

    count_by_verb: dict[str, int] = {}
    count_by_ability: dict[str, int] = {}
    count_by_externality: dict[str, int] = {}
    amount_by_currency: dict[str, float] = {}
    total_count = 0

    with _lock:
        _ensure_loaded(window_seconds)
        _sync_from_file()
        _maybe_prune(window_seconds)
        entries = list(_ledger.get(session_id, []))

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
        # heterogeneous small actions accumulate toward a hold (RFX-11).
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

    RFX-197: RAISES LedgerWriteError if the action cannot be recorded. That is
    deliberately unlike audit.py's best-effort write: an unrecorded action
    means the NEXT call's budget under-counts, which is the fail-open this
    module exists to close, so decide.py denies instead.
    """
    entry: dict[str, Any] = {
        "event_type": "entry",
        "session_id": session_id,
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

    if not _persist_enabled():
        with _lock:
            _ensure_loaded()
            _fold_record(entry)
        return

    # Write first, then fold by re-reading. The file is the authority, so the
    # in-memory index is never updated from the write path directly: it is
    # populated only by _sync_from_file(), which makes divergence between what
    # this process believes and what is on disk structurally impossible.
    _append_record(entry)
    with _lock:
        _sync_from_file()


def clear_session(session_id: str) -> None:
    """Remove a session's ledger state entirely (used in tests).

    On a durable ledger this appends a `clear` event rather than rewriting the
    file: the stream stays append-only and the reset is itself a record, so a
    session whose budget was reset by hand is not indistinguishable from one
    that never spent anything.
    """
    if _persist_enabled():
        try:
            _append_record({
                "event_type": "clear",
                "session_id": session_id,
                "ts": time.time(),
            })
        except LedgerWriteError as exc:
            print(f"[reeflex-core] WARN: ledger clear not recorded: {exc}", file=sys.stderr)
    with _lock:
        _ledger.pop(session_id, None)


def _reset_for_tests() -> None:
    """Forget everything this process has folded (tests only).

    Tests point REEFLEX_LEDGER_PATH at a tmpdir per case; this drops the
    cursor and the epoch so the next call re-folds the new file instead of
    reusing a cursor into the previous one.
    """
    global _read_key, _read_offset, _loaded, _epoch, _scan_truncated, _last_prune
    global _lock_fd
    with _lock:
        _ledger.clear()
        _read_key = None
        _read_offset = 0
        _loaded = False
        _scan_truncated = False
        _last_prune = 0.0
        _epoch = {}
        if _lock_fd is not None:
            try:
                os.close(_lock_fd)
            except OSError:
                pass
            _lock_fd = None
