"""A real openhands-sdk Conversation with a scripted model and a RECORDING
shell tool: the tool is named `terminal` (so the analyzer routes it exactly as
it routes the real TerminalTool) but appends the command to a list instead of
running it.  So a test can tell "the SDK executed this action" from "it did
not" without a shell, tmux, or a filesystem side effect."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Sequence
from typing import ClassVar

from pydantic import Field

from openhands.sdk import Agent, Conversation, Tool
from openhands.sdk.llm import Message, MessageToolCall, TextContent
from openhands.sdk.testing import TestLLM
from openhands.sdk.tool.registry import register_tool
from openhands.sdk.tool.tool import Action, Observation, ToolAnnotations, ToolDefinition, ToolExecutor

EXECUTED: list[str] = []


class RecordedShellAction(Action):
    command: str = Field(description="shell command")
    is_input: bool = Field(default=False)


class RecordedShellObservation(Observation):
    pass


class _Exec(ToolExecutor):
    def __call__(self, action, conversation=None):
        EXECUTED.append(action.command)
        return RecordedShellObservation.from_text(text="recorded: " + action.command)


class RecordingTerminalTool(ToolDefinition[RecordedShellAction, RecordedShellObservation]):
    name: ClassVar[str] = "terminal"

    @classmethod
    def create(cls, conv_state=None, **params) -> Sequence["RecordingTerminalTool"]:
        return [cls(description="run a shell command (recorded, not executed)",
                    action_type=RecordedShellAction, observation_type=RecordedShellObservation,
                    executor=_Exec(),
                    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                                                idempotentHint=False, openWorldHint=True))]


register_tool("rfx_recording_terminal", RecordingTerminalTool)


def shell_calls(*commands: str) -> list:
    msgs = [Message(role="assistant", content=[TextContent(text="")],
                    tool_calls=[MessageToolCall(id="c%d" % i, name="terminal",
                                                arguments=json.dumps({"command": c}),
                                                origin="completion")])
            for i, c in enumerate(commands)]
    msgs.append(Message(role="assistant", content=[TextContent(text="done")]))
    return msgs


def batch_call(*commands: str) -> list:
    """ONE model response carrying several tool calls (a parallel batch)."""
    return [Message(role="assistant", content=[TextContent(text="")],
                    tool_calls=[MessageToolCall(id="b%d" % i, name="terminal",
                                                arguments=json.dumps({"command": c}),
                                                origin="completion")
                                for i, c in enumerate(commands)]),
            Message(role="assistant", content=[TextContent(text="done")])]


def conversation(messages: list):
    EXECUTED.clear()
    llm = TestLLM.from_messages(messages)
    agent = Agent(llm=llm, tools=[Tool(name="rfx_recording_terminal")])
    return Conversation(agent=agent, workspace=tempfile.mkdtemp(prefix="rfx-oh-test-"),
                        persistence_dir=None, visualizer=None)
