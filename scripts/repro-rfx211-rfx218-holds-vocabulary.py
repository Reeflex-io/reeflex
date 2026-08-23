#!/usr/bin/env python3.11
"""
repro-rfx211-rfx218-holds-vocabulary.py — RFX-211 + RFX-218.

WHAT THIS MEASURES
==================
`GET /v1/holds` is the endpoint an operator (or an agent holding the published
`reeflex-holds` MCP tools) uses to ask the gate *"what is held?"*, and
`resolve_hold()` is how the answer comes back. Every parsed parameter on that
surface answers a word it does not know with a CONFIDENT WRONG ANSWER instead of
an error:

  A. status=<unrecognised>  -> 200 {"items":[],"count":0}     (RFX-211, filed)
  B. cursor=<unrecognised>  -> silently ignored: page 1 again  (UNFILED)
  C. limit=<unparseable>    -> silently 100; 0/negative -> 1   (UNFILED)
  D. resolve_hold("approved") -> REJECTS the hold              (RFX-218, filed)

A and D are the read and write halves of one defect: an enumerated parameter
whose "everything else" arm is a wrong answer rather than a refusal.

THE CONTRAST THAT MAKES THIS A DEFECT AND NOT A STYLE CHOICE
============================================================
The SAME core canonicalizes and fails CLOSED on non-canonical *envelope* input
-- `app/envelope.py::validate_and_fill_defaults` F1/F5/F6 coerce an unknown
axis, environment or verb to the most-guarded member precisely so a typo cannot
buy a weaker answer. The *query* surface of the same service does the opposite:
an unknown word buys the most reassuring answer there is, "nothing is held".

WHY "NOTHING IS HELD" IS THE DANGEROUS DIRECTION
================================================
No action gets through -- this is an instrument, not a gate. But it is the
instrument that answers the only question human oversight depends on. RFX-65's
month-long invisible pending holds are the precedent: something has to look,
and a lookup that answers "nothing" to a typo is worse than one that errors.

HOW TO RUN
==========
    python3.11 scripts/repro-rfx211-rfx218-holds-vocabulary.py

Starts its OWN reeflex-core from the tree this script lives in, on its own port,
with its own holds/audit paths under a temp dir. It never touches the shared
default holds file (a stray core reddens other sessions' suites) and it sends no
traffic anywhere but 127.0.0.1.

EXIT CODES
    0  every arm behaves correctly (i.e. the defects are FIXED in this tree)
    1  at least one arm still answers a word it does not know with a wrong answer
    2  the harness could not measure anything (setup failure) -- never a verdict
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
CORE = REPO / "reeflex-core"

GATE_TOKEN = "repro-rfx211-gate-token"
APPROVER_TOKEN = "repro-rfx211-approver-token"
APPROVER = {"type": "human", "id": "approver-rfx211"}

# The five status values reeflex-core's own docstrings and README name as the
# vocabulary of this parameter. Read from the code's stated contract, not
# invented here: app/holds.py list_holds() docstring and reeflex-holds/README.md
# both list exactly these.
CORE_STATUSES = ("pending", "approved", "rejected", "expired", "consumed")

# Words that are NOT in core's vocabulary but that a real caller plausibly
# sends. Each is annotated with WHY it is plausible -- an arbitrary garbage
# string alone would understate the defect.
NON_MEMBERS = [
    ("all", "VALID on reeflex-app's own /app/api/v1/holds (measured: it 422s an "
            "unknown status and accepts 'all'), and the single most likely word "
            "for an LLM driving the published reeflex-holds MCP tool, which "
            "forwards `status` with NO validation"),
    ("resolved", "VALID on reeflex-app's holds API -- the two surfaces do not "
                 "share a vocabulary, so an operator's correct word for one is a "
                 "false all-clear on the other"),
    ("Pending", "case variant -- exactly the class app/envelope.py F5 exists to "
                "canonicalize on the envelope side"),
    ("pending ", "trailing space -- RFX-86's evasion shape, one surface over"),
    ("banana", "control: unambiguous nonsense must not read as an all-clear"),
]


def log(msg: str = "") -> None:
    print(msg, flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def request(method: str, path: str, port: int, *, body: dict | None = None,
            token: str = GATE_TOKEN) -> tuple[int, dict | str]:
    """Return (http_status, parsed_body). Never raises on a non-2xx."""
    url = f"http://127.0.0.1:{port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode()
            code = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        code = exc.code
    except Exception as exc:  # noqa: BLE001
        return 0, f"TRANSPORT-ERROR: {exc}"
    try:
        return code, json.loads(raw)
    except json.JSONDecodeError:
        return code, raw


class Core:
    """A reeflex-core started from THIS tree, isolated from every other session."""

    def __init__(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rfx211-"))
        self.port = free_port()
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        token_map = self.tmp / "resolver-tokens.json"
        token_map.write_text(json.dumps({APPROVER_TOKEN: APPROVER}))
        env = dict(os.environ)
        env.update(
            REEFLEX_HOST="127.0.0.1",
            REEFLEX_PORT=str(self.port),
            REEFLEX_POLICY_DIR=str(CORE / "policy"),
            # Own paths: never the shared default holds file.
            REEFLEX_HOLDS_PATH=str(self.tmp / "holds.jsonl"),
            REEFLEX_AUDIT_LOG=str(self.tmp / "decisions.jsonl"),
            REEFLEX_AUTH_TOKEN=GATE_TOKEN,
            REEFLEX_RESOLVER_TOKENS=str(token_map),
            # Long TTL: this round is about vocabulary, not expiry. A hold must
            # not fold to `expired` underneath the measurement.
            REEFLEX_HOLD_TTL_SECONDS="3600",
        )
        self.proc = subprocess.Popen(
            [sys.executable, "main.py"],
            cwd=str(CORE), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ in range(100):
            code, _body = request("GET", "/healthz", self.port)
            if code == 200:
                return
            if self.proc.poll() is not None:
                out, err = self.proc.communicate()
                raise RuntimeError(
                    f"core died on startup:\n{out.decode()[-2000:]}\n{err.decode()[-2000:]}"
                )
            time.sleep(0.2)
        raise RuntimeError("core did not become healthy in 20s")

    def stop(self) -> None:
        # Terminate THIS process only. Never `pkill -f main.py`: other fleet
        # sessions run cores on this box (dev-1--049 did that and could not
        # prove it had not killed a neighbour's).
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)


def envelope(session: str, agent: str = "agent:repro-rfx211") -> dict:
    """An envelope core answers `require_approval` -> a real pending hold.

    irreversible + broad + production is R2. `systemic` would be R3, a terminal
    deny that raises no hold at all (and is in NON_RESOLVABLE_RULES).
    """
    return {
        "agent": {"id": agent, "session_id": session},
        "action": {"namespace": "repro", "verb": "delete", "ability": "repro/delete-things"},
        "target": {"environment": "production", "system": "repro"},
        "magnitude": {"count": 3},
        "axes": {
            "reversibility": "irreversible",
            "blast_radius": "broad",
            "externality": "internal",
        },
    }


def seed(port: int) -> dict[str, str]:
    """Create one hold in each of three statuses. Returns {status: hold_id}."""
    ids: dict[str, str] = {}
    made: list[str] = []
    for n in range(3):
        # A fresh session per POST: R5 accumulates magnitude.count per session,
        # so a shared session would have later envelopes answered by the budget
        # rule instead of R2 (dev-1--049 §8b).
        code, body = request("POST", "/v1/decide", port,
                             body=envelope(f"repro-rfx211-s{n}"))
        if code != 200 or not isinstance(body, dict):
            raise RuntimeError(f"seed decide failed: HTTP {code} {body}")
        if body.get("decision") != "require_approval":
            raise RuntimeError(
                f"seed envelope was not held -- core answered {body.get('decision')!r} "
                f"under rule {body.get('rule')!r}. The harness cannot measure a "
                f"holds vocabulary with no holds."
            )
        hold_id = body.get("hold_id")
        if not hold_id:
            raise RuntimeError(f"require_approval carried no hold_id: {body}")
        made.append(hold_id)

    ids["pending"] = made[0]
    for hold_id, decision, want in ((made[1], "approve", "approved"),
                                    (made[2], "reject", "rejected")):
        code, body = request(
            "POST", f"/v1/holds/{hold_id}/resolve", port,
            body={"decision": decision, "principal": APPROVER, "reason": "repro"},
            token=APPROVER_TOKEN,
        )
        if code != 200 or not isinstance(body, dict) or body.get("status") != want:
            raise RuntimeError(
                f"seed resolve({decision}) failed: HTTP {code} {body}. "
                f"If this is a 403 naming REQUIRE_VERIFIED_APPROVER the token map "
                f"did not load; that is a harness fault, not a finding."
            )
        ids[want] = hold_id
    return ids


# ---------------------------------------------------------------------------
# The four arms
# ---------------------------------------------------------------------------

def arm_a_status(port: int, ids: dict[str, str]) -> list[tuple[str, bool, str]]:
    """RFX-211: an unrecognised `status` must not read as an all-clear."""
    log("=" * 78)
    log("ARM A (RFX-211) -- GET /v1/holds?status=<word>")
    log("=" * 78)

    code, body = request("GET", "/v1/holds", port)
    total = body.get("count") if isinstance(body, dict) else None
    log(f"  CONTROL  no filter          -> HTTP {code}  count={total}")
    if code != 200 or total != 3:
        raise RuntimeError(
            f"control failed: an unfiltered list must show the 3 seeded holds, "
            f"got HTTP {code} count={total}. Nothing below would mean anything."
        )

    for st in CORE_STATUSES:
        code, body = request("GET", f"/v1/holds?status={st}", port)
        n = body.get("count") if isinstance(body, dict) else None
        log(f"  CONTROL  status={st:<20} -> HTTP {code}  count={n}")
        expected = 1 if st in ids else 0
        if code != 200 or n != expected:
            raise RuntimeError(
                f"control failed: status={st} must be accepted and return "
                f"{expected}, got HTTP {code} count={n}"
            )

    log("")
    results: list[tuple[str, bool, str]] = []
    for word, why in NON_MEMBERS:
        code, body = request("GET",
                             f"/v1/holds?status={urllib.request.quote(word)}", port)
        n = body.get("count") if isinstance(body, dict) else None

        # RFX-211's FIX SHAPE offers TWO acceptable answers, and this harness
        # scores that disjunction rather than one implementation's choice:
        #   "400 on an unrecognised status, and either accept `all` as a synonym
        #    for no filter or reject it -- but not silently return empty."
        # So an arm is OK if it is either REFUSED with a named error, or
        # ACCEPTED with a defined meaning (the full unfiltered set). It is BAD
        # only when it answers 200 with a WRONG count -- which is the defect.
        # Written as a disjunction on purpose: it is red before the fix (0 of 3)
        # and green after, for whichever of the two answers the fix picks, so
        # the goalposts are in the ticket rather than in this file.
        refused = code == 400 and isinstance(body, dict) and "error" in body
        means_no_filter = code == 200 and n == total
        ok = refused or means_no_filter
        verdict = (
            "REFUSED (correct)" if refused else
            f"ACCEPTED as no-filter, count={n} (correct)" if means_no_filter else
            "FALSE ALL-CLEAR" if code == 200 and n == 0 else
            f"UNEXPECTED HTTP {code} count={n}"
        )
        log(f"  status={word!r:<12} -> HTTP {code}  count={n}  {verdict}")
        log(f"      why plausible: {why}")
        results.append((f"status={word!r}", ok, verdict))
    return results


def arm_b_cursor(port: int, ids: dict[str, str]) -> list[tuple[str, bool, str]]:
    """UNFILED sibling: an unrecognised `cursor` is silently ignored."""
    log("")
    log("=" * 78)
    log("ARM B (UNFILED) -- GET /v1/holds?cursor=<token>")
    log("=" * 78)
    log("  holds.py applies the cursor as `if cursor_positions:` with NO else,")
    log("  so a cursor that matches no hold is DROPPED and the caller is served")
    log("  page 1 again -- indistinguishable from a valid first page.")
    log("")

    code, page1 = request("GET", "/v1/holds?limit=1", port)
    if code != 200 or not isinstance(page1, dict) or page1.get("count") != 1:
        raise RuntimeError(f"control failed: limit=1 must yield one item, got {code} {page1}")
    first_id = page1["items"][0]["id"]
    nxt = page1.get("next_cursor")
    log(f"  CONTROL  limit=1                     -> first={first_id[:12]}… next_cursor={str(nxt)[:12]}…")

    code, page2 = request("GET", f"/v1/holds?limit=1&cursor={nxt}", port)
    second_id = page2["items"][0]["id"] if isinstance(page2, dict) and page2.get("items") else None
    log(f"  CONTROL  limit=1&cursor=<valid>      -> HTTP {code} first={str(second_id)[:12]}…")
    if second_id == first_id:
        raise RuntimeError("control failed: a valid cursor did not advance the page")

    results: list[tuple[str, bool, str]] = []
    for cursor, label in (("no-such-hold-id", "nonsense"),
                          (ids["pending"][::-1], "a real id, reversed (typo shape)")):
        code, body = request("GET", f"/v1/holds?limit=1&cursor={cursor}", port)
        got = body["items"][0]["id"] if isinstance(body, dict) and body.get("items") else None
        repeated = got == first_id
        ok = code == 400 and isinstance(body, dict) and "error" in body
        verdict = ("REFUSED (correct)" if ok else
                   "SILENTLY SERVED PAGE 1 AGAIN" if repeated else
                   f"UNEXPECTED HTTP {code}")
        log(f"  cursor=<{label}> -> HTTP {code} first={str(got)[:12]}…  {verdict}")
        results.append((f"cursor=<{label}>", ok, verdict))
    return results


def arm_c_limit(port: int) -> list[tuple[str, bool, str]]:
    """UNFILED sibling: an unparseable/out-of-range `limit` is silently rewritten."""
    log("")
    log("=" * 78)
    log("ARM C (UNFILED) -- GET /v1/holds?limit=<n>")
    log("=" * 78)
    log("  server.py: `except (ValueError, TypeError): limit = 100`, then")
    log("  `max(1, min(limit, 1000))`. So garbage silently means 100, and a")
    log("  caller asking for 0 silently gets 1.")
    log("")

    results: list[tuple[str, bool, str]] = []
    for raw, label in (("banana", "unparseable"), ("0", "zero"), ("-5", "negative")):
        code, body = request("GET", f"/v1/holds?limit={raw}", port)
        n = body.get("count") if isinstance(body, dict) else None
        ok = code == 400 and isinstance(body, dict) and "error" in body
        verdict = "REFUSED (correct)" if ok else f"SILENTLY REWRITTEN (count={n})"
        log(f"  limit={raw!r:<10} ({label:<12}) -> HTTP {code}  count={n}  {verdict}")
        results.append((f"limit={raw!r}", ok, verdict))
    return results


def arm_d_resolve_vocabulary() -> list[tuple[str, bool, str]]:
    """RFX-218: resolve_hold()'s "everything else" arm REJECTS.

    In-process, because that is the only place this is reachable: the HTTP
    handler and the published reeflex-holds client both validate
    `approve|reject` first. Said plainly rather than inflated.
    """
    log("")
    log("=" * 78)
    log("ARM D (RFX-218) -- holds.resolve_hold(decision=<word>), in-process")
    log("=" * 78)

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="rfx218-"))
    sys.path.insert(0, str(CORE))
    os.environ["REEFLEX_HOLDS_PATH"] = str(tmp / "holds.jsonl")
    os.environ["REEFLEX_AUDIT_LOG"] = str(tmp / "decisions.jsonl")
    os.environ.pop("REEFLEX_REQUIRE_VERIFIED_APPROVER", None)
    from app import holds as holds_mod  # noqa: PLC0415

    results: list[tuple[str, bool, str]] = []

    def fresh_hold() -> str:
        # A fresh store per case: resolve_hold() only acts on a PENDING hold, so
        # reusing one would measure the pending-guard instead of the vocabulary.
        holds_mod._reset(str(tmp / f"holds-{time.time_ns()}.jsonl"))
        rec = holds_mod.create_hold(
            envelope("rfx218-session"), rule_id="irreversible_broad_prod",
        )
        return rec["id"]

    # CONTROL: the two words the endpoint validates must keep working.
    for word, want in (("approve", "approved"), ("reject", "rejected")):
        out = holds_mod.resolve_hold(fresh_hold(), word, "human", "supervisor:leo", None)
        got = out.get("status") if isinstance(out, dict) else None
        log(f"  CONTROL  decision={word!r:<12} -> status={got!r}")
        if got != want:
            raise RuntimeError(f"control failed: {word!r} must yield {want!r}, got {got!r}")

    log("")
    # The docstring's own literals, plus the near-misses the ticket names.
    for word in ("approved", "Approve", "approve ", "rejected", "yes", ""):
        hold_id = fresh_hold()
        try:
            out = holds_mod.resolve_hold(hold_id, word, "human", "supervisor:leo", None)
        except (ValueError, TypeError) as exc:
            log(f"  decision={word!r:<12} -> RAISED {type(exc).__name__}: {exc}  REFUSED (correct)")
            results.append((f"resolve_hold({word!r})", True, "REFUSED (correct)"))
            continue
        got = out.get("status") if isinstance(out, dict) else None
        # `approved`/`Approve`/`approve ` silently REJECTING is the defect the
        # ticket filed. `rejected`/`yes`/`""` landing on "rejected" is the same
        # arm; it happens to agree with the caller's intent for `rejected`, and
        # that coincidence is exactly why the bug survived.
        note = "SILENTLY COERCED to 'rejected'"
        if word.strip().lower().startswith("approv"):
            note = "SILENTLY REJECTED -- the caller asked to APPROVE"
        log(f"  decision={word!r:<12} -> status={got!r}  {note}")
        results.append((f"resolve_hold({word!r})", False, note))

    shutil.rmtree(tmp, ignore_errors=True)
    return results


def main() -> int:
    log("RFX-211 + RFX-218 -- the holds surface answers a word it does not know")
    log(f"tree: {REPO}")
    rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO),
                         capture_output=True, text=True).stdout.strip()
    log(f"HEAD: {rev}")
    log("")

    core = Core()
    try:
        try:
            core.start()
            ids = seed(core.port)
        except Exception as exc:  # noqa: BLE001
            # A setup failure must NEVER print a verdict. dev-1--049 shipped a
            # harness that computed findings out of transport errors; this exits
            # 2 with the reason instead.
            log(f"SETUP FAILED -- nothing was measured: {exc}")
            return 2

        log(f"seeded: pending={ids['pending'][:12]}… approved={ids['approved'][:12]}… "
            f"rejected={ids['rejected'][:12]}…")
        log("")

        results: list[tuple[str, bool, str]] = []
        results += arm_a_status(core.port, ids)
        results += arm_b_cursor(core.port, ids)
        results += arm_c_limit(core.port)
    finally:
        core.stop()

    results += arm_d_resolve_vocabulary()

    log("")
    log("=" * 78)
    bad = [r for r in results if not r[1]]
    log(f"SUMMARY: {len(results) - len(bad)} of {len(results)} arms refuse a word "
        f"they do not know; {len(bad)} answer it with a wrong answer.")
    log("=" * 78)
    for name, ok, verdict in results:
        log(f"  {'OK  ' if ok else 'BAD '} {name:<34} {verdict}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
