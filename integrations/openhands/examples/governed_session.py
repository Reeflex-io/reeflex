"""A scripted OpenHands session governed by Reeflex, end to end.

The model is the SDK's own `TestLLM`, so the session is reproducible: it
proposes the same five shell commands every time.  The TOOLS are real
(`openhands-tools` TerminalTool + FileEditorTool), so whatever Reeflex lets
through actually runs, in a scratch workspace this script creates.

    pip install './integrations/openhands[tools]'
    export REEFLEX_CORE_URL=...        REEFLEX_CORE_TOKEN=...
    export REEFLEX_PORTAL_URL=https://app.reeflex.io
    export REEFLEX_CONNECTOR_GATE_TOKEN=...  REEFLEX_CONNECTOR_EVIDENCE_SIGNING_KEY=...
    python examples/governed_session.py --out session.json

While it waits on a hold it prints the hold id; approve or reject it in the
portal's Holds inbox.  Every command below is chosen to be harmless if it ran:
`./build` is inside the scratch workspace, the workspace has no git remote,
`unknown.example` is a reserved name that does not resolve, and the
DROP DATABASE targets port 1, where nothing listens.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time

os.environ.setdefault("OPENHANDS_SUPPRESS_BANNER", "1")

from openhands.sdk import Agent, Conversation, Tool  # noqa: E402
from openhands.sdk.event import SecurityAnalysisEvent, UserRejectObservation  # noqa: E402
from openhands.sdk.event.llm_convertible import ObservationEvent  # noqa: E402
from openhands.sdk.llm import Message, MessageToolCall, TextContent  # noqa: E402
from openhands.sdk.testing import TestLLM  # noqa: E402
from openhands.tools.file_editor import FileEditorTool  # noqa: E402
from openhands.tools.preset.default import register_default_tools  # noqa: E402
from openhands.tools.terminal import TerminalTool  # noqa: E402

from reeflex_openhands import ReeflexSecurityAnalyzer, run_governed  # noqa: E402

SCRIPT = [
    "ls -la",
    "rm -rf ./build",
    "git push --force origin main",
    "curl -sS --max-time 5 https://unknown.example/",
    'psql -h 127.0.0.1 -p 1 -c "DROP DATABASE rfx_demo_nonexistent"',
]


def scripted_llm() -> TestLLM:
    msgs = []
    for i, cmd in enumerate(SCRIPT):
        msgs.append(Message(role="assistant", content=[TextContent(text="")],
                            tool_calls=[MessageToolCall(
                                id="call_%d" % i, name="terminal",
                                arguments=json.dumps({"command": cmd, "security_risk": "LOW",
                                                      "summary": cmd[:40]}),
                                origin="completion")]))
    msgs.append(Message(role="assistant", content=[TextContent(text="All done.")]))
    return TestLLM.from_messages(msgs)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--environment", default="production")
    ap.add_argument("--max-wait", type=float, default=900)
    args = ap.parse_args(argv)

    workspace = tempfile.mkdtemp(prefix="reeflex-openhands-demo-")
    os.makedirs(os.path.join(workspace, "build"))
    open(os.path.join(workspace, "build", "artifact.o"), "w").write("synthetic\n")

    register_default_tools(enable_browser=False)
    agent = Agent(llm=scripted_llm(),
                  tools=[Tool(name=TerminalTool.name), Tool(name=FileEditorTool.name)])
    conversation = Conversation(agent=agent, workspace=workspace, persistence_dir=None,
                                visualizer=None)
    analyzer = ReeflexSecurityAnalyzer(environment=args.environment, agent_id="openhands-demo")
    analyzer.attach(conversation)
    print("conversation", conversation.id, "workspace", workspace, flush=True)

    def on_wait(state):
        print(time.strftime("%H:%M:%SZ", time.gmtime()), "waiting on hold(s)",
              state["waiting_on"], "error=%s" % state["error"], flush=True)

    conversation.send_message("Clean the build, push, check the site, drop the old db.")
    stops = run_governed(conversation, analyzer, poll=3.0, max_wait=args.max_wait,
                         on_wait=on_wait)
    analyzer.flush()

    events = conversation.state.events
    record = {
        "conversation_id": str(conversation.id),
        "workspace": workspace,
        "build_dir_exists_after": os.path.exists(os.path.join(workspace, "build")),
        "decisions": list(analyzer.decisions.values()),
        "stops": stops,
        "security_analysis_events": [e.model_dump(mode="json") for e in events
                                     if isinstance(e, SecurityAnalysisEvent)],
        "rejections": [{"action_id": e.action_id, "reason": e.rejection_reason}
                       for e in events if isinstance(e, UserRejectObservation)],
        "executed": [{"tool": e.tool_name, "command": getattr(e.action, "command", None)}
                     for e in events if type(e).__name__ == "ActionEvent"
                     and any(isinstance(o, ObservationEvent) and o.action_id == e.id
                             for o in events)],
        "evidence_pushes": [{"path": x["path"], "decision_ids": [r.get("decision_id")
                                                                 for r in x["records"]],
                             "result": x["result"]} for x in analyzer.evidence_log],
    }
    with open(args.out, "w") as fh:
        json.dump(record, fh, indent=1, default=str)
    conversation.close()
    for d in record["decisions"]:
        print("%-46s %-17s %-40s risk=%-7s hold=%s evidence=%s" % (
            (d.get("tool_name") or "") + " " + str(d.get("verb")), d["verdict"], d["rule"],
            d["risk"], d.get("hold_id"), d.get("evidence_pushed")))
    print("executed:", [x["command"] for x in record["executed"]])
    print("rejected:", [x["reason"] for x in record["rejections"]])
    return 0


if __name__ == "__main__":
    sys.exit(main())
