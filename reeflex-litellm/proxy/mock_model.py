#!/usr/bin/env python3
"""
mock_model.py -- an OpenAI-compatible model that returns tool calls ON DEMAND.

    python3 proxy/mock_model.py --port 18602

Serves `POST /v1/chat/completions` (and `/chat/completions`) plus `GET /health`.

WHY A MOCK IS THE RIGHT INSTRUMENT HERE
=======================================
The thing under test is the GATEWAY SEAT, not a model.  A real model makes the
one variable that matters -- which tool call comes back, with which arguments --
nondeterministic, so a red run could always be the model changing its mind.
This mock makes the tool call an INPUT, so every latency number and every
verdict in this package's evidence is attributable to the seat.

What it therefore does NOT prove: that a real model's tool-call shapes all
normalize correctly.  That is what `REEFLEX_LITELLM_TOOL_MAP` and
`reeflex-litellm normalize` are for, and it is stated as a limit in the README.

DRIVING IT
==========
Put a directive in the last user message:

    TOOL run_shell {"command": "rm -rf /"}
    TOOL read_file {"path": "/etc/hosts"}
    TOOL run_shell {"command": "rm -rf ./build"} | TOOL read_file {"path": "/etc/hosts"}

Several directives separated by ` | ` become several tool calls on one response.
A message with no directive gets a prose answer and no tool calls -- which is
how the "text still flows" case is driven.

`--latency-ms N` adds a fixed think-time, so a latency measurement can be taken
against a model whose own cost is known and constant.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIRECTIVE = re.compile(r"TOOL\s+([A-Za-z0-9_.\-]+)\s+(\{.*?\})\s*(?=\||$)", re.S)

LATENCY_MS = 0


def _tool_calls_from(messages):
    text = ""
    for m in reversed(messages or []):
        if isinstance(m, dict) and m.get("role") == "user":
            content = m.get("content")
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = " ".join(p.get("text", "") for p in content
                                if isinstance(p, dict))
            break
    calls = []
    for i, (name, args) in enumerate(DIRECTIVE.findall(text)):
        try:
            json.loads(args)  # validate; the STRING is what goes on the wire
        except ValueError:
            continue
        calls.append({
            "id": "call_%d_%s" % (i, uuid.uuid4().hex[:8]),
            "type": "function",
            "function": {"name": name, "arguments": args},
        })
    return calls


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-model"

    def log_message(self, *_a):
        pass

    def _json(self, status, payload):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.rstrip("/") in ("/health", "/healthz"):
            return self._json(200, {"status": "ok"})
        if self.path.rstrip("/").endswith("/models"):
            return self._json(200, {"object": "list", "data": [
                {"id": "mock-tools", "object": "model", "owned_by": "reeflex"}]})
        self._json(404, {"error": "not_found"})

    def _sse(self, chunks):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for chunk in chunks:
            payload = ("data: %s\n\n" % json.dumps(chunk)).encode("utf-8")
            self.wfile.write(b"%x\r\n%s\r\n" % (len(payload), payload))
        done = b"data: [DONE]\n\n"
        self.wfile.write(b"%x\r\n%s\r\n" % (len(done), done))
        self.wfile.write(b"0\r\n\r\n")

    def _stream(self, model, calls):
        """Real SSE, with tool_call deltas -- so a measurement of the gateway's
        streaming path measures the GATEWAY and not this mock's shortcuts."""
        cid = "chatcmpl-" + uuid.uuid4().hex[:16]
        created = int(time.time())

        def frame(delta, finish=None):
            return {"id": cid, "object": "chat.completion.chunk",
                    "created": created, "model": model,
                    "choices": [{"index": 0, "delta": delta,
                                 "finish_reason": finish}]}

        chunks = [frame({"role": "assistant", "content": None})]
        if not calls:
            chunks.append(frame({"content": "No tool call was requested, so "
                                            "here is prose instead."}))
            chunks.append(frame({}, "stop"))
            return self._sse(chunks)
        for i, c in enumerate(calls):
            chunks.append(frame({"tool_calls": [{
                "index": i, "id": c["id"], "type": "function",
                "function": {"name": c["function"]["name"], "arguments": ""}}]}))
            # The arguments arrive split across frames, which is what a real
            # provider does and what makes the streaming path hard to govern.
            args = c["function"]["arguments"]
            mid = max(len(args) // 2, 1)
            for piece in (args[:mid], args[mid:]):
                chunks.append(frame({"tool_calls": [{
                    "index": i, "function": {"arguments": piece}}]}))
        chunks.append(frame({}, "tool_calls"))
        return self._sse(chunks)

    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            return self._json(404, {"error": "not_found"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except ValueError:
            return self._json(400, {"error": "bad_json"})

        if LATENCY_MS:
            time.sleep(LATENCY_MS / 1000.0)

        calls = _tool_calls_from(body.get("messages"))

        if body.get("stream"):
            return self._stream(body.get("model") or "mock-tools", calls)
        message = {"role": "assistant", "content": None if calls
                   else "No tool call was requested, so here is prose instead."}
        if calls:
            message["tool_calls"] = calls

        self._json(200, {
            "id": "chatcmpl-" + uuid.uuid4().hex[:16],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model") or "mock-tools",
            "choices": [{"index": 0, "message": message,
                         "finish_reason": "tool_calls" if calls else "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7,
                      "total_tokens": 18},
        })


def main():
    global LATENCY_MS
    ap = argparse.ArgumentParser(
        prog="mock_model",
        description="An OpenAI-compatible model that returns the tool calls you "
                    "name in the prompt. For measuring a gateway, not a model.")
    ap.add_argument("--port", type=int, default=18602)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--latency-ms", type=int, default=0,
                    help="fixed think-time, so the model's own cost is a known "
                         "constant in a latency measurement")
    args = ap.parse_args()
    LATENCY_MS = args.latency_ms
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("mock model on http://%s:%d/v1 (latency %dms)"
          % (args.host, args.port, LATENCY_MS), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
