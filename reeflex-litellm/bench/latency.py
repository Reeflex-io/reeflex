#!/usr/bin/env python3
"""
latency.py -- what the governance seat costs a gateway, measured.

    python3 bench/latency.py \
        --hook-url    http://127.0.0.1:18600 \
        --nohook-url  http://127.0.0.1:18610 \
        --concurrency 1 10 50 \
        --requests    200 500 1000 \
        --out /tmp/latency.json

WHAT IS MEASURED
================
Wall-clock time for `POST /v1/chat/completions`, taken at the gateway's CLIENT,
against two proxies that are identical except that one has the Reeflex
guardrail in its config and one does not (`proxy/config.yaml` vs
`proxy/config-nohook.yaml`).  Both point at the SAME mock model on the same
host, so the model's cost is a constant that cancels in the delta.

`added` in the output is `hook p50 - nohook p50` (and the same at p95).  It is
the honest number for "what does the seat cost per request", because it is the
difference between two measurements of the same thing rather than an
instrumented slice of one of them.

WHY NOT TIME THE HOOK FROM INSIDE ITSELF
========================================
A timer around the hook body reports the hook's own duration and silently
excludes what the hook does to the event loop -- and blocking the loop is the
failure mode that matters at concurrency.  Measuring both proxies from outside
captures it: if the hook serialises the proxy, the hook-on p95 climbs with
concurrency while the hook-off p95 does not, and the delta shows it.

WHAT IS DELIBERATELY HELD CONSTANT
==================================
  * ONE uvicorn worker on each proxy (`--num_workers 1`), so the numbers are
    per-process and a reader can multiply rather than guess.
  * A WARM-UP round per (proxy, concurrency) cell, discarded, defaulting to 200
    requests. A cold LiteLLM process pays imports, client construction and cache
    fills on its first requests; including those puts the cost of a cold process
    into p95.

  * `--repeat` runs each cell N times and prints every repeat. A single cell is
    not a measurement: the variance is the only thing that says whether the
    delta is real. Anything reported from this harness should quote the spread,
    not one number.

  * `--interleave` (THE DEFAULT) fires the hook-off and hook-on requests
    ALTERNATELY inside one worker pool sized at 2x the target concurrency, so
    ~`concurrency` requests are in flight to EACH proxy and both sides sit in
    whatever state the box is in for every request pair. `--no-interleave`
    measures one proxy's whole cell and then the other's; the harness prints
    which design ran, and the two agree on this box.

    IT IS THE DEFAULT BECAUSE A SEQUENTIAL DESIGN ONCE PRODUCED A WRONG TABLE.
    A first version of this harness reported `added p50 +28.0ms` at concurrency
    1. Re-running the identical cell gave +85.9 / +85.5 / +86.6. The cause was
    not the hook and not warm-up: it was THIS HARNESS'S CLIENT (see the client
    section below), which made the BASELINE bimodal, and a sequential design
    happily subtracts a baseline measured in one mode from a hook-on cell
    measured in the other. Interleaving makes that class of error cancel rather
    than land in the reported delta.
  * A UNIQUE session per request, so R5's cumulative budget cannot accumulate
    across the run and flip a verdict from allow to require_approval halfway
    through the sample. A verdict change mid-run would turn a latency
    measurement into a mixture of two different code paths.
  * A tool call that is ALLOWED (`read_file`), so every request pays the full
    normalize -> classify -> envelope -> POST /v1/decide round trip and returns
    unchanged. The rewrite path is cheaper, so this is the cost of the seat on
    the traffic that is NOT refused -- which is the traffic that matters for a
    latency budget.

Every request that did not return HTTP 200 is counted and reported separately.
A cell whose error count is non-zero has its percentiles reported over the
SUCCESSFUL requests only, with the error count printed beside them -- because a
shed request is fast and would otherwise flatter the numbers.

`--stream` MEASURES A DIFFERENT SEAT (RFX-242)
==============================================
With `--stream` the requests carry `stream: true` and are therefore governed by
`async_post_call_streaming_iterator_hook`, not by the buffered post-call hook.
That path has TWO extra numbers, and reporting only one of them would be
misleading in whichever direction the reporter preferred:

  ttft   TIME TO FIRST TOKEN -- the first SSE `data:` frame.  The seat lets
         role and prose frames straight through, so this is ESSENTIALLY
         UNCHANGED.  Quoted alone it reads as "streaming governance is free".
  ttfc   TIME TO FIRST TOOL-CALL FRAME -- the first frame carrying
         `"tool_calls"`.  This is what the seat actually delays, by exactly the
         decision it has to take first.  Quoted alone it reads as "the gateway
         stalls your stream".

Both are printed and both are in the JSON (`added_ttft_*`, `added_ttfc_*`).

A caveat that belongs next to the numbers rather than in a footnote: THE MOCK
MODEL EMITS ITS WHOLE STREAM AT ONCE.  A real provider dribbles tokens out over
hundreds of milliseconds, and the decision overlaps whatever it is still
sending, so what this harness measures is the UPPER BOUND -- the cost with no
provider time to hide behind.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import socket
import statistics
import sys
import threading
import time
import uuid

PROMPT_1 = 'TOOL read_file {"path": "/etc/hosts"}'
PROMPT_2 = ('TOOL read_file {"path": "/etc/hosts"} | '
            'TOOL read_file {"path": "/etc/services"}')
# No directive: the mock answers with prose and NO tool call. The control for
# the streaming table -- the seat never calls core for it, so any added latency
# on this prompt is the cost of the hook being in the pipeline at all, not the
# cost of a decision.
PROMPT_PROSE = "Answer in prose and call no tool."


# ---------------------------------------------------------------------------
# The client, and why it is not urllib.
#
# A first version opened a FRESH CONNECTION PER REQUEST with `urllib`, and the
# baseline it produced was BIMODAL: p50 ~9ms in some runs and p50 ~58ms in
# others, a 49ms step, with each mode held rock-steady for hundreds of
# consecutive requests (per-50 medians 58.0/58.3/57.8/57.6/58.2/57.7/58.1/57.7
# over 400 requests in one run; 9.0-9.6 across three whole cells in another).
# Meanwhile the mock model measured 1.3ms p50 in both modes.
#
# Replacing the client with ONE PERSISTENT KEEP-ALIVE CONNECTION PER WORKER
# THREAD, with TCP_NODELAY set, makes the baseline stable: 13.0-13.6ms p50
# across repeats and across runs. The servers did not change, so the
# bimodality was a property of the client -- and a 49ms step on a fresh
# connection carrying a small write has the shape of a Nagle / delayed-ACK
# interaction. THAT MECHANISM IS AN INFERENCE, not a measurement: no packets
# were captured. What is measured is that the instability lives on the client
# side of the socket and that this client does not have it.
#
# Keep-alive is also what a real client of a gateway does, so the numbers below
# describe a realistic caller rather than a pathological one.
# ---------------------------------------------------------------------------
_local = threading.local()


def _conn(url: str, timeout: float):
    conns = getattr(_local, "conns", None)
    if conns is None:
        conns = _local.conns = {}
    c = conns.get(url)
    if c is None:
        host = url.split("//", 1)[-1]
        c = conns[url] = http.client.HTTPConnection(host, timeout=timeout)
        c.connect()
        c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return c


def _drop_conn(url: str):
    conns = getattr(_local, "conns", None)
    if conns and url in conns:
        try:
            conns[url].close()
        except Exception:
            pass
        del conns[url]


def one_request(url: str, prompt: str, timeout: float,
                stream: bool = False, api_key: str = "sk-bench") -> tuple:
    """(elapsed_ms, http_status_or_None, tool_call_count, ttft_ms_or_None).

    `ttft_ms` -- TIME TO FIRST TOKEN -- is the wall clock from sending the
    request to the first SSE `data:` frame being READ BY THIS CLIENT, and it is
    None for a buffered request, which has no such moment.

    IT IS THE NUMBER THE STREAMING SEAT ACTUALLY MOVES, and p50/p95 of the
    total is not a substitute for it: a gateway that withholds a tool call
    until a decision is taken and then emits the whole tail at once has an
    unchanged total and a first token that arrives at a completely different
    time.  Which of the two a deployment cares about depends on whether the
    response is prose (the user is reading it as it arrives) or a tool call
    (nothing happens until the whole call is there), so both are reported and
    neither is called "the" latency.
    """
    payload = {"model": "mock-tools",
               "messages": [{"role": "user", "content": prompt}]}
    if stream:
        payload["stream"] = True
    body = json.dumps(payload)
    headers = {"Content-Type": "application/json",
               "Authorization": "Bearer " + api_key,
               # A unique session per request -- see the module docstring.
               "X-Reeflex-Session": "bench-" + uuid.uuid4().hex}

    def attempt():
        c = _conn(url, timeout)
        c.request("POST", "/v1/chat/completions", body=body, headers=headers)
        resp = c.getresponse()
        if not stream:
            return resp.read(), resp.status, None, None
        # Read frame by frame so the FIRST one can be timed.  `read1` returns
        # as soon as some bytes are available rather than filling a buffer,
        # which is what makes this a measurement of arrival rather than of the
        # buffer size.
        raw, first, first_tool = b"", None, None
        while True:
            piece = resp.read1(65536)
            if not piece:
                break
            raw += piece
            now = (time.perf_counter() - t0) * 1000
            if first is None and b"data:" in raw:
                first = now
            # Matched on the ACCUMULATED bytes, not on this read: the marker
            # can straddle two reads, and a per-read match would then time the
            # frame after the one that actually carried the tool call.
            if first_tool is None and b'"tool_calls"' in raw:
                first_tool = now
        return raw, resp.status, first, first_tool

    t0 = time.perf_counter()
    try:
        raw, status, ttft, ttfc = attempt()
    except Exception:
        # A dropped keep-alive connection must not be reported as latency:
        # discard it and retry once on a fresh one.
        _drop_conn(url)
        try:
            raw, status, ttft, ttfc = attempt()
        except Exception:
            _drop_conn(url)
            return (time.perf_counter() - t0) * 1000, None, 0, None, None
    ms = (time.perf_counter() - t0) * 1000
    return ms, status, _count_tool_calls(raw, stream), ttft, ttfc


def _count_tool_calls(raw: bytes, stream: bool) -> int:
    """How many tool calls a client would end up holding.

    Counted for both shapes because it is the guard against measuring the
    wrong thing: a cell whose responses carry ZERO tool calls is a cell where
    the seat refused everything, and its latency describes the refusal path,
    not the allow path the table claims to be about.
    """
    try:
        if not stream:
            parsed = json.loads(raw.decode())
            return sum(len((ch.get("message") or {}).get("tool_calls") or [])
                       for ch in parsed.get("choices") or [])
        seen = set()
        for line in raw.split(b"\n"):
            line = line.strip()
            if not line.startswith(b"data:") or line[5:].strip() == b"[DONE]":
                continue
            ev = json.loads(line[5:].strip().decode())
            for ch in ev.get("choices") or []:
                for e in (ch.get("delta") or {}).get("tool_calls") or []:
                    seen.add(e.get("index", 0))
        return len(seen)
    except Exception:
        return 0


def run_interleaved(off_url: str, on_url: str, prompt: str, concurrency: int,
                    requests: int, timeout: float, warmup: int,
                    stream: bool = False, api_key: str = "sk-bench") -> tuple:
    """Fire OFF and ON requests alternately in one pool. (off_cell, on_cell).

    `requests` is per side, so 2*requests are sent. Even indices go to the
    hook-off proxy, odd to the hook-on one, and the pool interleaves them, so a
    latency mode the box happens to be in is shared by both sides.
    """
    def fire(i):
        url = off_url if i % 2 == 0 else on_url
        return (i % 2, ) + one_request(url, prompt, timeout, stream, api_key)

    total = requests * 2
    # 2x the pool, so ~`concurrency` requests are in flight to EACH proxy --
    # otherwise interleaving silently halves the load each side sees and the
    # row is labelled with a concurrency neither proxy experienced.
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency * 2) as pool:
        if warmup:
            list(pool.map(fire, range(warmup * 2)))
        t0 = time.perf_counter()
        results = list(pool.map(fire, range(total)))
        wall = time.perf_counter() - t0

    return (_summarize(off_url, [r[1:] for r in results if r[0] == 0],
                       concurrency, requests, wall),
            _summarize(on_url, [r[1:] for r in results if r[0] == 1],
                       concurrency, requests, wall))


def run_cell(url: str, prompt: str, concurrency: int, requests: int,
             timeout: float, warmup: int, stream: bool = False,
             api_key: str = "sk-bench") -> dict:
    def fire(_):
        return one_request(url, prompt, timeout, stream, api_key)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        if warmup:
            list(pool.map(fire, range(warmup)))
        t0 = time.perf_counter()
        results = list(pool.map(fire, range(requests)))
        wall = time.perf_counter() - t0

    return _summarize(url, results, concurrency, requests, wall)


def _summarize(url, results, concurrency, requests, wall) -> dict:
    ok = [ms for ms, st, _n, _t, _c in results if st == 200]
    errors = {}
    for _ms, st, _n, _t, _c in results:
        if st != 200:
            errors[str(st)] = errors.get(str(st), 0) + 1
    calls = [n for _ms, st, n, _t, _c in results if st == 200]
    ttfts = sorted(t for _ms, st, _n, t, _c in results
                   if st == 200 and t is not None)
    ttfcs = sorted(c for _ms, st, _n, _t, c in results
                   if st == 200 and c is not None)
    ok.sort()
    out = {
        "url": url, "concurrency": concurrency, "requests": requests,
        "ok": len(ok), "errors": errors,
        "p50_ms": round(pct(ok, 50), 1), "p95_ms": round(pct(ok, 95), 1),
        "p99_ms": round(pct(ok, 99), 1),
        "min_ms": round(ok[0], 1) if ok else None,
        "max_ms": round(ok[-1], 1) if ok else None,
        "mean_ms": round(statistics.fmean(ok), 1) if ok else None,
        "wall_s": round(wall, 2),
        "throughput_rps": round(len(ok) / wall, 1) if wall > 0 else None,
        "tool_calls_returned_total": sum(calls),
    }
    if ttfts:
        out["ttft_p50_ms"] = round(pct(ttfts, 50), 1)
        out["ttft_p95_ms"] = round(pct(ttfts, 95), 1)
    if ttfcs:
        # TIME TO FIRST TOOL-CALL FRAME. Reported separately from TTFT because
        # they are different facts and only one of them moves: the seat lets the
        # role/prose frames through untouched, so TTFT is unchanged, while the
        # first frame carrying an ACTION cannot leave until the decision is in.
        # Quoting only TTFT would be a true number that reads as "the seat is
        # free", and quoting only this one would read as "prose is delayed".
        out["ttfc_p50_ms"] = round(pct(ttfcs, 50), 1)
        out["ttfc_p95_ms"] = round(pct(ttfcs, 95), 1)
        out["ttfc_n"] = len(ttfcs)
    return out


def pct(sorted_vals, p) -> float:
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def main():
    ap = argparse.ArgumentParser(
        prog="latency",
        description="Measure what the Reeflex gateway seat costs per request, "
                    "hook on vs hook off, at several concurrencies.")
    ap.add_argument("--hook-url", required=True)
    ap.add_argument("--nohook-url", required=True)
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 10, 50])
    ap.add_argument("--requests", type=int, nargs="+", default=[200, 500, 1000],
                    help="one per concurrency level, or one value for all")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--warmup", type=int, default=200,
                    help="requests fired and discarded before each cell; 200 "
                         "because 20 was measurably too few (see the module "
                         "docstring)")
    ap.add_argument("--repeat", type=int, default=3,
                    help="times to run each cell; every repeat is reported")
    ap.add_argument("--no-interleave", dest="interleave", action="store_false",
                    help="measure each proxy's cell separately (the design that "
                         "produced a wrong table -- see the module docstring)")
    ap.set_defaults(interleave=True)
    ap.add_argument("--stream", action="store_true",
                    help="send `stream: true`, and report TIME TO FIRST TOKEN "
                         "alongside the totals. Without it the buffered path is "
                         "measured, which is a different seat (RFX-242).")
    ap.add_argument("--api-key-file",
                    help="file holding the proxy key. A path, never a value: a "
                         "key on a command line lands in every process list on "
                         "the box.")
    ap.add_argument("--prose", action="store_true",
                    help="send a prompt the model answers with PROSE and no "
                         "tool call -- the control for --stream: this traffic "
                         "is never withheld and never reaches core")
    ap.add_argument("--two-calls", action="store_true",
                    help="send a response carrying TWO tool calls, to measure "
                         "the per-tool-call cost of deciding in order")
    ap.add_argument("--out")
    args = ap.parse_args()

    reqs = args.requests
    if len(reqs) == 1:
        reqs = reqs * len(args.concurrency)
    if len(reqs) != len(args.concurrency):
        print("--requests must have one value, or one per --concurrency level",
              file=sys.stderr)
        return 2

    if args.prose:
        prompt, calls_per_response = PROMPT_PROSE, 0
    else:
        prompt = PROMPT_2 if args.two_calls else PROMPT_1
        calls_per_response = 2 if args.two_calls else 1
    api_key = (open(args.api_key_file).read().strip()
               if args.api_key_file else "sk-bench")
    print("design: %s | warmup %d | repeat %d | %d tool call(s) per response "
          "| %s"
          % ("INTERLEAVED (off/on alternating in one pool)" if args.interleave
             else "SEQUENTIAL cells", args.warmup, args.repeat,
             calls_per_response,
             "STREAMING (stream: true)" if args.stream else "buffered"),
          flush=True)

    rows = []
    for c, n in zip(args.concurrency, reqs):
        for rep in range(1, args.repeat + 1):
            # Warm up only on the first repeat of a cell -- by the second the
            # proxy is warm and another 200 requests would only cost time.
            warm = args.warmup if rep == 1 else max(args.warmup // 10, 5)
            if args.interleave:
                off, on = run_interleaved(args.nohook_url, args.hook_url,
                                          prompt, c, n, args.timeout, warm,
                                          args.stream, api_key)
            else:
                off = run_cell(args.nohook_url, prompt, c, n, args.timeout,
                               warm, args.stream, api_key)
                on = run_cell(args.hook_url, prompt, c, n, args.timeout,
                              warm, args.stream, api_key)
            row = {
                "concurrency": c, "requests": n, "repeat": rep,
                "interleaved": args.interleave, "stream": args.stream,
                "tool_calls_per_response": calls_per_response,
                "hook_off": off, "hook_on": on,
                "added_p50_ms": round(on["p50_ms"] - off["p50_ms"], 1),
                "added_p95_ms": round(on["p95_ms"] - off["p95_ms"], 1),
            }
            if "ttft_p50_ms" in on and "ttft_p50_ms" in off:
                row["added_ttft_p50_ms"] = round(
                    on["ttft_p50_ms"] - off["ttft_p50_ms"], 1)
                row["added_ttft_p95_ms"] = round(
                    on["ttft_p95_ms"] - off["ttft_p95_ms"], 1)
            if "ttfc_p50_ms" in on and "ttfc_p50_ms" in off:
                row["added_ttfc_p50_ms"] = round(
                    on["ttfc_p50_ms"] - off["ttfc_p50_ms"], 1)
                row["added_ttfc_p95_ms"] = round(
                    on["ttfc_p95_ms"] - off["ttfc_p95_ms"], 1)
            rows.append(row)
            r = rows[-1]
            print("c=%-3d n=%-5d rep=%d  OFF p50 %7.1f p95 %8.1f err %-10s | "
                  "ON p50 %7.1f p95 %8.1f err %-10s | ADDED p50 %+7.1f p95 %+8.1f"
                  % (c, n, rep, off["p50_ms"], off["p95_ms"],
                     json.dumps(off["errors"]), on["p50_ms"], on["p95_ms"],
                     json.dumps(on["errors"]), r["added_p50_ms"],
                     r["added_p95_ms"]), flush=True)
            for label, key in (("TTFT ", "ttft"), ("TTFCall", "ttfc")):
                if "added_%s_p50_ms" % key not in r:
                    continue
                print("%18s %s OFF p50 %7.1f p95 %8.1f            | "
                      "ON p50 %7.1f p95 %8.1f            | ADDED p50 %+7.1f "
                      "p95 %+8.1f"
                      % ("", label, off["%s_p50_ms" % key],
                         off["%s_p95_ms" % key], on["%s_p50_ms" % key],
                         on["%s_p95_ms" % key], r["added_%s_p50_ms" % key],
                         r["added_%s_p95_ms" % key]), flush=True)
            # A cell in which the seat returned NO tool calls is not a
            # measurement of the allow path -- it is a measurement of a refusal
            # or of a misconfigured rig, and its numbers would be quoted as the
            # seat's cost. Say so loudly rather than writing it into the table.
            if (calls_per_response and on["tool_calls_returned_total"] == 0
                    and on["ok"]):
                print("  !! hook-on returned ZERO tool calls in this cell: the "
                      "seat refused them, so these numbers are NOT the allow "
                      "path", flush=True)

    out = {"measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "tool_calls_per_response": calls_per_response,
           "warmup": args.warmup, "repeat": args.repeat,
           "interleaved": args.interleave, "stream": args.stream,
           "rows": rows}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
