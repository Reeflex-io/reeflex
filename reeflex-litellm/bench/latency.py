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


def one_request(url: str, prompt: str, timeout: float) -> tuple:
    """(elapsed_ms, http_status_or_None, tool_call_count)."""
    body = json.dumps({"model": "mock-tools",
                       "messages": [{"role": "user", "content": prompt}]})
    headers = {"Content-Type": "application/json",
               "Authorization": "Bearer sk-bench",
               # A unique session per request -- see the module docstring.
               "X-Reeflex-Session": "bench-" + uuid.uuid4().hex}
    t0 = time.perf_counter()
    try:
        c = _conn(url, timeout)
        c.request("POST", "/v1/chat/completions", body=body, headers=headers)
        resp = c.getresponse()
        raw = resp.read()
        status = resp.status
    except Exception:
        # A dropped keep-alive connection must not be reported as latency:
        # discard it and retry once on a fresh one.
        _drop_conn(url)
        try:
            c = _conn(url, timeout)
            c.request("POST", "/v1/chat/completions", body=body, headers=headers)
            resp = c.getresponse()
            raw = resp.read()
            status = resp.status
        except Exception:
            _drop_conn(url)
            return (time.perf_counter() - t0) * 1000, None, 0
    ms = (time.perf_counter() - t0) * 1000
    n = 0
    try:
        parsed = json.loads(raw.decode())
        for ch in parsed.get("choices") or []:
            n += len((ch.get("message") or {}).get("tool_calls") or [])
    except Exception:
        pass
    return ms, status, n


def run_interleaved(off_url: str, on_url: str, prompt: str, concurrency: int,
                    requests: int, timeout: float, warmup: int) -> tuple:
    """Fire OFF and ON requests alternately in one pool. (off_cell, on_cell).

    `requests` is per side, so 2*requests are sent. Even indices go to the
    hook-off proxy, odd to the hook-on one, and the pool interleaves them, so a
    latency mode the box happens to be in is shared by both sides.
    """
    def fire(i):
        url = off_url if i % 2 == 0 else on_url
        return (i % 2, ) + one_request(url, prompt, timeout)

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
             timeout: float, warmup: int) -> dict:
    def fire(_):
        return one_request(url, prompt, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        if warmup:
            list(pool.map(fire, range(warmup)))
        t0 = time.perf_counter()
        results = list(pool.map(fire, range(requests)))
        wall = time.perf_counter() - t0

    return _summarize(url, results, concurrency, requests, wall)


def _summarize(url, results, concurrency, requests, wall) -> dict:
    ok = [ms for ms, st, _ in results if st == 200]
    errors = {}
    for _, st, _ in results:
        if st != 200:
            errors[str(st)] = errors.get(str(st), 0) + 1
    calls = [n for _, st, n in results if st == 200]
    ok.sort()
    return {
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

    prompt = PROMPT_2 if args.two_calls else PROMPT_1
    calls_per_response = 2 if args.two_calls else 1
    print("design: %s | warmup %d | repeat %d | %d tool call(s) per response"
          % ("INTERLEAVED (off/on alternating in one pool)" if args.interleave
             else "SEQUENTIAL cells", args.warmup, args.repeat,
             calls_per_response), flush=True)

    rows = []
    for c, n in zip(args.concurrency, reqs):
        for rep in range(1, args.repeat + 1):
            # Warm up only on the first repeat of a cell -- by the second the
            # proxy is warm and another 200 requests would only cost time.
            warm = args.warmup if rep == 1 else max(args.warmup // 10, 5)
            if args.interleave:
                off, on = run_interleaved(args.nohook_url, args.hook_url,
                                          prompt, c, n, args.timeout, warm)
            else:
                off = run_cell(args.nohook_url, prompt, c, n, args.timeout, warm)
                on = run_cell(args.hook_url, prompt, c, n, args.timeout, warm)
            rows.append({
                "concurrency": c, "requests": n, "repeat": rep,
                "interleaved": args.interleave,
                "tool_calls_per_response": calls_per_response,
                "hook_off": off, "hook_on": on,
                "added_p50_ms": round(on["p50_ms"] - off["p50_ms"], 1),
                "added_p95_ms": round(on["p95_ms"] - off["p95_ms"], 1),
            })
            r = rows[-1]
            print("c=%-3d n=%-5d rep=%d  OFF p50 %7.1f p95 %8.1f err %-10s | "
                  "ON p50 %7.1f p95 %8.1f err %-10s | ADDED p50 %+7.1f p95 %+8.1f"
                  % (c, n, rep, off["p50_ms"], off["p95_ms"],
                     json.dumps(off["errors"]), on["p50_ms"], on["p95_ms"],
                     json.dumps(on["errors"]), r["added_p50_ms"],
                     r["added_p95_ms"]), flush=True)

    out = {"measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "tool_calls_per_response": calls_per_response,
           "warmup": args.warmup, "repeat": args.repeat,
           "interleaved": args.interleave, "rows": rows}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
