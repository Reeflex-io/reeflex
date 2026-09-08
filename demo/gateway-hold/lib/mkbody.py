#!/usr/bin/env python3
"""mkbody.py -- build one chat-completions request body from a prompt string.

Exists so `run.sh` never has to quote a JSON document containing a shell
command containing quotes inside a bash `-d` argument. That nesting was the
source of two silently malformed requests while this demo was being written:
bash ate a backslash, the mock model's directive regex did not match, the model
answered with prose, and the walk printed "no tool call" as though the gateway
had done something.
"""

from __future__ import annotations

import json
import sys

prompt = sys.argv[1]
print(json.dumps({
    "model": "mock-tools",
    "messages": [{"role": "user", "content": prompt}],
}))
