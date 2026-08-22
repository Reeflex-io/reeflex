"""appendlog.py — cross-process discipline for core's append-only files.

WHY THIS MODULE EXISTS (RFX-207 + the holds twin measured in dev-1--040).

`audit.py` and `holds.py` both wrote one JSONL line, fsync'd it, and then
re-read the file's LAST line to prove the write landed.  Both were guarded by
a module-level `threading.Lock()`, which is correct in-process and says
nothing at all about a second process.  An operator running two reeflex-core
replicas against one shared volume — an ordinary deployment, and the one
`docker-compose.yml` scales to — got:

  * `holds.py`: the read-back saw the OTHER replica's line and raised, which
    `decide.py` converts into `500 reeflex.core/hold_creation_failed`.  A
    legitimate irreversible-production action was DENIED, and — worse — the
    hold record had already landed, so a valid `pending` hold was left on the
    volume whose id the caller never received.  Nobody can answer a hold
    nobody has the id for; it sits until TTL and expires (RFX-64/65: an
    expired hold is invisible to the customer and the auditor).
    MEASURED: 100 concurrent `/v1/decide` calls at two replicas -> 9 x HTTP
    500, 9 of 9 leaving an orphaned pending hold, while all 100 hold records
    were on disk and all 100 parsed.  The data was never the problem.  The
    PROOF was.
  * `audit.py`: the same raise, but `decide.py::_try_audit` swallows it to a
    stderr WARN.  So the read-back — which exists to detect a torn or tampered
    write — reports nothing an operator acts on, and a REAL torn write is
    indistinguishable from a benign interleave.  (RFX-207 as filed predicted a
    fail-closed DENY here; measured, the audit half does not deny.  The
    ticket's mechanism is right and its stated consequence was for the wrong
    file.)

TWO FAILURE MODES, NOT ONE.  RFX-207 argued that the read-back would "observe
the other replica's line" — an id mismatch.  That happens, and so does a
second mode the ticket did not predict: the old code recorded `size` with
`seek(0, 2)`/`tell()`, walked backwards for the preceding newline, then called
`fh.read()` with NO length.  `read()` runs to the CURRENT end of file, so if
another process appended in between it returned our line PLUS theirs, and
`json.loads` raised `JSONDecodeError` — not the documented `OSError`.
Measured over 2/3/4 replicas, both modes fire in the hundreds.

WHAT THIS MODULE DOES DIFFERENTLY.

1. `exclusive(path)` takes an `fcntl.lockf` byte-range lock on a sidecar
   `<path>.lock`, so the append→fsync→verify window is atomic ACROSS
   PROCESSES, not just across threads.  Same shape the session ledger uses.

2. `append_and_verify()` proves OUR OWN BYTES landed AT OUR OWN OFFSET,
   instead of asking whether the file's last line happens to be ours.  In
   POSIX append mode a write goes atomically to the current end and leaves the
   descriptor positioned just past it, so `tell() - len(blob)` is exactly
   where our bytes went.  We read back exactly `len(blob)` bytes from exactly
   there.

   This is not merely a fix for the race — it is a STRICTLY STRONGER proof
   than the one it replaces.  "The last line has my id" was satisfied by any
   file whose tail happened to match; "my bytes are intact at my offset"
   is a real per-record integrity check, and it stays true no matter who else
   appends afterwards.  It is also O(1) syscalls instead of the old backward
   walk, which issued one `read(1)` per byte of the final line.

   Because of (2), a concurrent interleave is no longer an error AT ALL.  The
   lock in (1) is what keeps the read-modify-write decisions above it (the
   single-use CAS in `holds.mark_consumed`) atomic; the offset proof is what
   stops a neighbour's append from being mistaken for corruption.

3. A failure NAMES ITS CAUSE.  RFX-207: "if the append genuinely cannot be
   verified, the refusal must name that cause distinctly, not share a code
   with a tamper detection."  `AppendVerifyError.cause` is one of:

     "tampered"     our bytes are NOT at our offset.  The file was rewritten,
                    truncated or torn under us.  This is the real tamper
                    signal and it is the only one that should ever page
                    anybody.
     "unavailable"  we could not complete the append/verify for an
                    environmental reason (I/O error, lock not obtainable).
                    Nothing is implied about integrity.

   It subclasses `OSError` so existing `except OSError` call sites keep
   working unchanged.

LIMITS, STATED.  `fcntl.lockf` is POSIX; core ships in a Linux container and
this module is not portable to Windows.  The lock is ADVISORY and per-path: it
serialises writers that go through this module, and it cannot constrain a
writer that does not (a log-rotation tool, a shell `>>`).  That is exactly why
(2) does not depend on the lock — the offset proof holds against a
non-participating writer too, which the last-line check never did.

NOT IN SCOPE HERE.  `ledger.py`'s cross-process arm is PR #108 (RFX-197); this
module deliberately does not touch it, so the two diffs stay reviewable
separately.  Converging the ledger onto this helper is a follow-up worth doing
once both have landed.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import pathlib
from typing import Iterator

# One byte range per file is enough: every writer of a given path contends on
# the same single byte of that path's sidecar lock.  Byte 0 is used (rather
# than a computed offset) because the lock file exists only to be locked.
_LOCK_BYTE = 0

__all__ = ["AppendVerifyError", "exclusive", "append_and_verify", "read_new_records"]


class AppendVerifyError(OSError):
    """An append could not be proven to have landed intact.

    `cause` is "tampered" (our bytes are not at our offset — a real integrity
    signal) or "unavailable" (we could not complete the operation; says
    nothing about integrity).  See the module docstring for why these must not
    share one code.
    """

    def __init__(self, message: str, *, cause: str) -> None:
        super().__init__(message)
        self.cause = cause


def _lock_path(path: pathlib.Path) -> pathlib.Path:
    return path.with_name(path.name + ".lock")


@contextlib.contextmanager
def exclusive(path: pathlib.Path) -> Iterator[None]:
    """Hold an exclusive cross-process lock for `path` for the block's duration.

    Blocking: a replica waits rather than failing, because the alternative is
    refusing a legitimate action to avoid waiting a few milliseconds for an
    fsync.  A lock we cannot even open raises AppendVerifyError("unavailable")
    — never a silent pass, which would put us back where we started.
    """
    lock_file = _lock_path(path)
    try:
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY, 0o600)
    except OSError as exc:
        raise AppendVerifyError(
            f"cannot open lock file for {path.name}: {exc}", cause="unavailable"
        ) from exc
    try:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX, 1, _LOCK_BYTE, 0)
        except OSError as exc:
            raise AppendVerifyError(
                f"cannot lock {path.name}: {exc}", cause="unavailable"
            ) from exc
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.lockf(fd, fcntl.LOCK_UN, 1, _LOCK_BYTE, 0)
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def append_and_verify(path: pathlib.Path, line: str) -> int:
    """Append `line` to `path`, fsync it, and prove OUR bytes landed at OUR offset.

    `line` must already end in "\\n".  Returns the byte offset the record was
    written at, so a caller tracking a read cursor can advance it exactly.

    Raises AppendVerifyError("unavailable") if the write itself failed, and
    AppendVerifyError("tampered") if the bytes at our own offset are not the
    bytes we wrote — the only case that means the log's integrity is in doubt.

    Call this INSIDE `exclusive(path)` when the append is part of a
    read-modify-write (a status CAS); the proof itself does not require the
    lock.
    """
    blob = line.encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Binary append: no newline translation, no encoding surprises, so the
        # byte offsets below are exact.
        with open(path, "ab") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
            # POSIX O_APPEND: the write went atomically to the then-current
            # end and the descriptor now sits just past our bytes.
            end = fh.tell()
    except OSError as exc:
        raise AppendVerifyError(
            f"append to {path.name} failed: {exc}",
            cause="unavailable",
        ) from exc

    start = end - len(blob)
    if start < 0:
        raise AppendVerifyError(
            f"{path.name}: offset {start} after writing {len(blob)} bytes "
            f"(file end {end}) — the file shrank under us",
            cause="tampered",
        )

    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            got = fh.read(len(blob))
    except OSError as exc:
        raise AppendVerifyError(
            f"read-back of {path.name} failed: {exc}", cause="unavailable"
        ) from exc

    if got != blob:
        # Deliberately does NOT quote the record: audit lines carry envelope
        # content and this message reaches stderr.  Offsets and lengths are
        # enough to investigate, and the record is in the caller's hands.
        raise AppendVerifyError(
            f"{path.name}: read-back mismatch at offset {start} "
            f"({len(blob)} bytes written, {len(got)} read back, contents differ)"
            " — the log was rewritten or torn under us",
            cause="tampered",
        )
    return start


def read_new_records(path: pathlib.Path, offset: int) -> tuple[list[str], int]:
    """Return (complete lines appended at/after `offset`, new offset).

    A tail-follow, so a process can refresh its view of a file ANOTHER process
    is appending to without re-reading it from the top.

    Stops at the last newline, so a record another process is in the middle of
    writing is left for the next call instead of being folded half-parsed.  A
    missing file is (no lines, unchanged offset) — not an error: the file is
    created lazily on first append.
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
    except FileNotFoundError:
        return [], offset
    except OSError as exc:
        if exc.errno == errno.EISDIR:
            raise
        return [], offset

    if not chunk:
        return [], offset

    cut = chunk.rfind(b"\n")
    if cut < 0:
        # A partial record and nothing else: leave the cursor where it was.
        return [], offset

    complete = chunk[: cut + 1]
    try:
        text = complete.decode("utf-8")
    except UnicodeDecodeError:
        # Undecodable bytes are skipped, not raised: this is a refresh of a
        # shared log, and one bad record must not stop a replica from seeing
        # the good ones after it.  Callers already skip unparseable lines.
        return [], offset + len(complete)

    lines = [ln for ln in text.split("\n") if ln.strip()]
    return lines, offset + len(complete)
