# reeflex-openhands

A Reeflex gate as an [OpenHands Software Agent SDK](https://github.com/OpenHands/software-agent-sdk)
security analyzer. Every action an OpenHands agent proposes is decided by your
Reeflex gate before it runs: allowed actions run, denied actions are rejected,
held actions wait for a human in the Reeflex portal, and every decision is
recorded as signed evidence.

```python
from reeflex_openhands import ReeflexSecurityAnalyzer, run_governed

ReeflexSecurityAnalyzer(environment="production").attach(conversation)
conversation.send_message("...")
run_governed(conversation)
```

Configuration, the verdict-to-risk table, how actions are priced, and the
limits (`execute_tool()` bypasses the analyzer, a bare `run()` after a stop is
the SDK's approve, approval is per batch) are in
[`docs/integrations/openhands.md`](../../docs/integrations/openhands.md).

Measured against `openhands-sdk` 1.56.0. Apache-2.0.

```bash
pip install './integrations/openhands[tools]' pytest
cd integrations/openhands && python -m pytest tests -q
```

`examples/governed_session.py` is a scripted session with real tools that
exercises allow, hold (approve and reject in the portal) and deny.
