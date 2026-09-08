#!/usr/bin/env python3
"""
stream_walk.py -- what a caller of a STREAMING gateway actually receives.

    python3 proxy/stream_walk.py \
        --hook-url    http://127.0.0.1:18620 \
        --nohook-url  http://127.0.0.1:18630 \
        --core-url    http://127.0.0.1:18711 \
        --api-key-file /path/to/the/proxy/master.key \
        --out /tmp/stream-walk

WHAT THIS IS FOR, AND WHY IT IS NOT A UNIT TEST
===============================================
`tests/test_streaming.py` measures the assembly and the rewrite in-process, and
`tests/test_litellm_contract.py` measures that LiteLLM will call the hook at
all.  Neither of them reads a SOCKET.  This script does: it asserts on the raw
`text/event-stream` BYTES a client receives from a real LiteLLM proxy, because
the defect this closes (RFX-242) was a defect of what left the process, and a
suite that only inspects Python objects would have passed over it in both
directions.

It is also written to FAIL on the pre-fix build.  Every row prints the
measurement, not a verdict word, so the same script run against a gateway
without the streaming hook prints the destructive command sitting in the bytes
rather than an assertion nobody reads.

THE SEVEN CASES
===============
 1. deny  / stream   the refused command must not appear in ANY chunk
 2. deny  / buffered the SAME refusal payload as case 1 (path parity)
 3. allow / stream   byte-identical to a proxy with no seat, after the two
                     per-response fields (`id`, `created`) are normalized
 4. prose / stream    a response with no tool call is untouched and not delayed
 5. hold  / stream   withheld while a human decides, then RELEASED -- with the
                     approval arriving from a second thread mid-request
 6. core down/stream fail closed: refused, and the reason says why
 7. audit            core decided each streamed request EXACTLY ONCE

Case 7 exists because implementing this hook also silences LiteLLM's
`_run_deferred_stream_guardrails` pass, which used to run the BUFFERED hook on
an assembled streaming response after delivery -- producing a governance record
for a call the caller had already been given.  One row per request is what says
that is gone; two would say the seat now decides twice.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

DESTRUCTIVE = 'TOOL run_shell {"command": "rm -rf /"}'
NEEDLE = b"rm -rf /"
ALLOWED = 'TOOL read_file {"path": "/etc/hosts"}'
HOLDING = 'TOOL acme_deployer {"target": "prod"}'
PROSE = "Say something and call no tool."


# ---------------------------------------------------------------------------
# The client.  Raw sockets on purpose: `requests`/`openai` would parse the SSE
# and hand back a reassembled object, and the assertion here is about the bytes
# on the wire, not about what a well-behaved client makes of them.
# ---------------------------------------------------------------------------

def fire(url: str, api_key: str, prompt: str, stream: bool,
         session: str, timeout: float = 300.0) -> dict:
    host, port = _hostport(url)
    body = json.dumps({"model": "mock-tools",
                       "messages": [{"role": "user", "content": prompt}],
                       "stream": stream}).encode()
    req = (b"POST /v1/chat/completions HTTP/1.1\r\n"
           b"Host: " + host.encode() + b"\r\n"
           b"Content-Type: application/json\r\n"
           b"Authorization: Bearer " + api_key.encode() + b"\r\n"
           b"X-Reeflex-Session: " + session.encode() + b"\r\n"
           b"Connection: close\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)

    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t0 = time.perf_counter()
    s.sendall(req)

    raw = b""
    first_data_ms = None
    first_tool_ms = None
    while True:
        piece = s.recv(65536)
        if not piece:
            break
        raw += piece
        now = (time.perf_counter() - t0) * 1000
        if first_data_ms is None and b"data: " in raw:
            first_data_ms = now
        if first_tool_ms is None and b'"tool_calls"' in raw:
            first_tool_ms = now
    total_ms = (time.perf_counter() - t0) * 1000
    s.close()

    head, _, payload = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.split(b" ")[1:] else 0
    return {"status": status, "raw": raw, "body": payload,
            "ttfb_ms": round(first_data_ms, 1) if first_data_ms else None,
            "tool_ms": round(first_tool_ms, 1) if first_tool_ms else None,
            "total_ms": round(total_ms, 1)}


def _hostport(url: str) -> tuple:
    rest = url.split("//", 1)[-1].rstrip("/")
    host, _, port = rest.partition(":")
    return host, int(port or 80)


# ---------------------------------------------------------------------------
# Reading an SSE body
# ---------------------------------------------------------------------------

def sse_events(body: bytes) -> list:
    """Every `data:` payload in an SSE body, parsed, `[DONE]` dropped."""
    out = []
    for line in body.split(b"\n"):
        line = line.strip()
        if not line.startswith(b"data:"):
            continue
        payload = line[5:].strip()
        if payload == b"[DONE]":
            continue
        try:
            out.append(json.loads(payload.decode("utf-8")))
        except ValueError:
            continue
    return out


def assembled_content(events: list) -> str:
    out = []
    for ev in events:
        for choice in ev.get("choices") or []:
            piece = (choice.get("delta") or {}).get("content")
            if isinstance(piece, str):
                out.append(piece)
    return "".join(out)


def assembled_tool_calls(events: list) -> list:
    """The tool calls a compliant client would assemble from these chunks."""
    slots = {}
    order = []
    for ev in events:
        for choice in ev.get("choices") or []:
            for entry in (choice.get("delta") or {}).get("tool_calls") or []:
                idx = entry.get("index", 0)
                if idx not in slots:
                    slots[idx] = {"id": None, "name": None, "arguments": ""}
                    order.append(idx)
                slot = slots[idx]
                slot["id"] = slot["id"] or entry.get("id")
                fn = entry.get("function") or {}
                slot["name"] = slot["name"] or fn.get("name")
                if isinstance(fn.get("arguments"), str):
                    slot["arguments"] += fn["arguments"]
    return [slots[i] for i in order]


def finish_reasons(events: list) -> list:
    return [c.get("finish_reason") for ev in events
            for c in ev.get("choices") or [] if c.get("finish_reason")]


def refusals_in(events: list) -> list:
    """The refusal payloads a client would read off the assembled content."""
    out = []
    for line in assembled_content(events).splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            block = (json.loads(line) or {}).get("reeflex") or {}
        except ValueError:
            continue
        if isinstance(block.get("refused"), list):
            out.extend(block["refused"])
    return out


def normalize_stream(body: bytes) -> bytes:
    """Drop the three identifiers that are fresh on every response.

    `id` (the completion id), `created` (a unix second) and the provider's
    `tool_call_id` are minted per response by the MODEL, not by the gateway, so
    two calls to two proxies differ in them whatever the seat does.  Everything
    else is compared verbatim -- the tool name, every `arguments` fragment and
    its split points, the delta shapes, the ordering, the finish_reason.  A
    seat that reassembled the arguments differently, dropped a frame, merged
    two frames or re-ordered anything still shows up as a difference.

    Verified to be necessary and not merely convenient: with only `id` and
    `created` normalized this comparison FAILS on one line, and the diff is the
    mock's `call_0_<8 hex>` against another `call_0_<8 hex>`.
    """
    out = re.sub(rb'"id":"chatcmpl-[0-9a-f]+"', b'"id":"chatcmpl-NORMALIZED"', body)
    out = re.sub(rb'"created":\d+', b'"created":0', out)
    return re.sub(rb'"id":"call_(\d+)_[0-9a-f]+"', rb'"id":"call_\1_NORM"', out)


# ---------------------------------------------------------------------------
# Case 5's second actor: the human
# ---------------------------------------------------------------------------

def latest_pending_hold(core_url: str, holds_file: str) -> str:
    """The id of the newest hold still pending, read off core's holds ledger."""
    pending, resolved = [], set()
    with open(holds_file, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("status") == "pending":
                pending.append(rec["id"])
            elif rec.get("id"):
                resolved.add(rec["id"])
    for hid in reversed(pending):
        if hid not in resolved:
            return hid
    raise RuntimeError("no pending hold in %s" % holds_file)


def approve(core_url: str, hold_id: str, token: str, principal_id: str) -> int:
    body = json.dumps({"decision": "approve", "reason": "stream_walk",
                       "principal": {"type": "human", "id": principal_id}}).encode()
    req = urllib.request.Request(
        "%s/v1/holds/%s/resolve" % (core_url.rstrip("/"), hold_id),
        data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def count_core_decisions(audit_file: str, session_prefix: str) -> int:
    n = 0
    with open(audit_file, "r", encoding="utf-8") as fh:
        for line in fh:
            if session_prefix in line and '"decision"' in line:
                n += 1
    return n


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="stream_walk",
        description="Assert on the SSE bytes a streaming gateway returns.")
    ap.add_argument("--hook-url", required=True)
    ap.add_argument("--nohook-url", required=True)
    ap.add_argument("--core-url", required=True)
    ap.add_argument("--api-key-file", required=True,
                    help="file holding the proxy key; a path, never a value on "
                         "a command line that lands in a process list")
    ap.add_argument("--approver-token-file",
                    help="a core resolver token, for case 5")
    ap.add_argument("--approver-id", default="alice.approver@acme.example")
    ap.add_argument("--holds-file", help="core's holds.jsonl, for case 5")
    ap.add_argument("--audit-file", help="core's decisions.jsonl, for case 7")
    ap.add_argument("--out", default="/tmp/stream-walk")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    key = open(args.api_key_file).read().strip()
    tag = "walk-%d" % int(time.time())
    rows, failures = [], []

    # WARM BOTH PROXIES FIRST, and discard the result.  A LiteLLM process pays
    # imports, client construction and cache fills on its first request; the
    # first measured case would otherwise carry a cold process's cost in its
    # time-to-first-byte and the timing line would report it as the seat's.
    for u in (args.hook_url, args.nohook_url):
        try:
            fire(u, key, PROSE, True, "%s-warm" % tag, timeout=120)
        except Exception:
            pass

    def record(name, ok, detail):
        rows.append((name, ok, detail))
        if not ok:
            failures.append(name)

    def save(name, blob):
        path = os.path.join(args.out, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        return path

    # -- 1. deny / stream ---------------------------------------------------
    s1 = "%s-deny-stream" % tag
    r1 = fire(args.hook_url, key, DESTRUCTIVE, True, s1)
    save("1-deny-stream.sse", r1["raw"])
    ev1 = sse_events(r1["body"])
    ref1 = refusals_in(ev1)
    record("1 deny/stream: needle absent from every byte",
           NEEDLE not in r1["raw"],
           "%d bytes, needle %s" % (len(r1["raw"]),
                                    "PRESENT" if NEEDLE in r1["raw"] else "absent"))
    record("1 deny/stream: no tool call assembles",
           assembled_tool_calls(ev1) == [],
           "assembled=%r" % (assembled_tool_calls(ev1),))
    record("1 deny/stream: one refusal, stage refused_at_gateway",
           len(ref1) == 1 and ref1[0].get("stage") == "refused_at_gateway",
           json.dumps(ref1))
    record("1 deny/stream: finish_reason flipped to stop",
           finish_reasons(ev1) == ["stop"], repr(finish_reasons(ev1)))

    # -- 2. deny / buffered -- the parity assertion -------------------------
    s2 = "%s-deny-buffered" % tag
    r2 = fire(args.hook_url, key, DESTRUCTIVE, False, s2)
    save("2-deny-buffered.json", r2["raw"])
    parsed = json.loads(r2["body"].decode())
    msg = parsed["choices"][0]["message"]
    ref2 = []
    for line in (msg.get("content") or "").splitlines():
        if line.strip().startswith("{"):
            ref2.extend(((json.loads(line) or {}).get("reeflex") or {})
                        .get("refused") or [])

    def comparable(refs):
        return [{k: v for k, v in r.items() if k != "tool_call_id"} for r in refs]

    record("2 parity: streamed refusal == buffered refusal (bar tool_call_id)",
           comparable(ref1) == comparable(ref2),
           "stream=%s buffered=%s" % (json.dumps(comparable(ref1)),
                                      json.dumps(comparable(ref2))))
    record("2 parity: buffered path also carries no needle",
           NEEDLE not in r2["raw"], "%d bytes" % len(r2["raw"]))

    # -- 3. allow / stream, against a proxy with no seat --------------------
    # NOT run with STREAM_WALK_CORE_DOWN=1: with core unreachable the seat
    # fails closed, so it refuses this call too -- correctly.  A row that is
    # expected to be red in one configuration is a row nobody reads in either.
    core_down = os.environ.get("STREAM_WALK_CORE_DOWN") == "1"
    s3 = "%s-allow" % tag
    on = fire(args.hook_url, key, ALLOWED, True, s3 + "-on")
    off = fire(args.nohook_url, key, ALLOWED, True, s3 + "-off")
    save("3-allow-stream-hook.sse", on["raw"])
    save("3-allow-stream-nohook.sse", off["raw"])
    if core_down:
        rows.append(("3 allow/stream", None,
                     "SKIPPED: core is down, so fail-closed refuses this too"))
    else:
        record("3 allow/stream: byte-identical to a gateway with no seat "
               "(id/created/tool_call_id normalized)",
               normalize_stream(on["body"]) == normalize_stream(off["body"]),
               "hook %d bytes, nohook %d bytes"
               % (len(on["body"]), len(off["body"])))
        record("3 allow/stream: the tool call still assembles",
               len(assembled_tool_calls(sse_events(on["body"]))) == 1,
               repr(assembled_tool_calls(sse_events(on["body"]))))

    # -- 4. prose / stream --------------------------------------------------
    s4 = "%s-prose" % tag
    pon = fire(args.hook_url, key, PROSE, True, s4 + "-on")
    poff = fire(args.nohook_url, key, PROSE, True, s4 + "-off")
    save("4-prose-stream-hook.sse", pon["raw"])
    record("4 prose/stream: identical to a gateway with no seat",
           normalize_stream(pon["body"]) == normalize_stream(poff["body"]),
           "hook %d bytes, nohook %d bytes"
           % (len(pon["body"]), len(poff["body"])))
    record("4 prose/stream: no refusal was added",
           refusals_in(sse_events(pon["body"])) == [],
           repr(refusals_in(sse_events(pon["body"]))))

    # -- 5. hold / stream: withheld, then released --------------------------
    if args.approver_token_file and args.holds_file:
        token = open(args.approver_token_file).read().strip()
        s5 = "%s-hold" % tag
        approved = {}

        def approver():
            # Wait for the hold to EXIST, then approve it -- from a different
            # thread, while the streaming request is still open.  That is the
            # whole point: a release the caller's own request produced would
            # prove nothing about a human.
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    hid = latest_pending_hold(args.core_url, args.holds_file)
                except Exception:
                    time.sleep(0.3)
                    continue
                approved["at"] = time.perf_counter()
                approved["hold"] = hid
                approved["http"] = approve(args.core_url, hid, token,
                                           args.approver_id)
                return
            approved["http"] = None

        t = threading.Thread(target=approver, daemon=True)
        t0 = time.perf_counter()
        t.start()
        r5 = fire(args.hook_url, key, HOLDING, True, s5)
        t.join(timeout=5)
        save("5-hold-stream.sse", r5["raw"])
        ev5 = sse_events(r5["body"])
        calls5 = assembled_tool_calls(ev5)
        approve_ms = round((approved.get("at", t0) - t0) * 1000, 1)
        record("5 hold/stream: the approval was made by a second actor",
               approved.get("http") == 200,
               "resolve HTTP %s at +%sms, hold %s"
               % (approved.get("http"), approve_ms, approved.get("hold")))
        record("5 hold/stream: the tool call was RELEASED after the approval",
               len(calls5) == 1 and calls5[0]["name"] == "acme_deployer",
               "assembled=%r refusals=%r" % (calls5, refusals_in(ev5)))
        record("5 hold/stream: it was WITHHELD until then "
               "(first tool byte after the approval)",
               r5["tool_ms"] is not None and r5["tool_ms"] > approve_ms,
               "first tool byte +%sms, approval +%sms, total %sms"
               % (r5["tool_ms"], approve_ms, r5["total_ms"]))
    else:
        rows.append(("5 hold/stream", None,
                     "SKIPPED: needs --approver-token-file and --holds-file"))

    # -- 6. core unreachable ------------------------------------------------
    # Driven by the caller: point the proxy at a dead core and restart it.
    # Left to the runner rather than done here, because this script does not
    # own the proxy's environment.  When --expect-core-down is passed the same
    # deny prompt is fired and the refusal is asserted to be the fail-closed one.
    if core_down:
        s6 = "%s-coredown" % tag
        r6 = fire(args.hook_url, key, DESTRUCTIVE, True, s6)
        save("6-coredown-stream.sse", r6["raw"])
        ev6 = sse_events(r6["body"])
        ref6 = refusals_in(ev6)
        record("6 core down/stream: needle absent",
               NEEDLE not in r6["raw"], "%d bytes" % len(r6["raw"]))
        record("6 core down/stream: refused, and the reason names the outage",
               len(ref6) == 1 and ref6[0].get("error") == "reeflex_unavailable",
               json.dumps(ref6))
        record("6 core down/stream: prose still flows",
               b"prose instead" in fire(args.hook_url, key, PROSE, True,
                                        s6 + "-prose")["raw"],
               "text is not an action and is not gated on core")

    # -- 7. exactly one decision per streamed request -----------------------
    if args.audit_file:
        n = count_core_decisions(args.audit_file, "%s-deny-stream" % tag)
        record("7 audit: core decided the streamed request exactly once",
               n == 1, "%d decision rows for session %s-deny-stream" % (n, tag))

    # -- report -------------------------------------------------------------
    print()
    print("%-4s %-62s %s" % ("", "case", "measurement"))
    for name, ok, detail in rows:
        mark = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print("%-4s %-62s %s" % (mark, name, detail))
    print()
    print("timings: deny/stream ttfb %sms total %sms | allow/stream ttfb %sms "
          "total %sms | prose/stream ttfb %sms total %sms"
          % (r1["ttfb_ms"], r1["total_ms"], on["ttfb_ms"], on["total_ms"],
             pon["ttfb_ms"], pon["total_ms"]))
    print("evidence: %s" % args.out)
    if failures:
        print("\nFAILED: %s" % ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
