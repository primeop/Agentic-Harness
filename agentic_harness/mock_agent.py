"""A deliberately vulnerable reference agent, used as a runnable test fixture.

This is NOT a real LLM. It is a small, deterministic simulation of a *naive*
tool-using agent, written so the probe suite produces real, reproducible
findings offline. It models the two failure modes that dominate agentic
security:

  1. No trust boundary. The planner scans the *entire* assembled context —
     user input, retrieved documents, memory, and messages from other agents —
     for tool directives and will act on any it finds. Instructions hidden in a
     data channel are executed as if the user issued them.

  2. Excessive agency. Tool execution consults an `authorizer`. The insecure
     default (`allow_all`) permits every call, so a low-privilege principal can
     drive high-privilege tools. Swapping in a capability-scoped authorizer is
     the fix the harness demonstrates.

Directive grammar recognised by the naive planner (this stands in for the
myriad ways a real LLM can be steered into emitting a tool call):

    [[tool: NAME arg1=value1, arg2=value2]]

To test a *real* agent, ignore this file and write an adapter that implements
`Target.invoke` — see examples/anthropic_adapter.py.
"""
from __future__ import annotations

import re
from typing import Optional

from .target import (
    AgentResponse,
    Authorizer,
    Invocation,
    Target,
    ToolCall,
    allow_all,
)

# tool -> scope required to run it (used by the scoped authorizer / policy)
TOOL_SCOPES: dict[str, str] = {
    "search_docs": "read",
    "read_file": "read",
    "send_email": "write",
    "transfer_funds": "admin",
    "delete_record": "admin",
}

SENSITIVE_TOOLS = {"send_email", "transfer_funds", "delete_record"}

_DIRECTIVE = re.compile(r"\[\[\s*tool:\s*([a-zA-Z_]\w*)\s*(.*?)\]\]", re.DOTALL)
_ARG = re.compile(r"([a-zA-Z_]\w*)\s*=\s*([^,]+)")


def _parse_args(blob: str) -> dict:
    return {k.strip(): v.strip() for k, v in _ARG.findall(blob)}


class MockAgent(Target):
    """Naive tool-using agent. Vulnerable by construction."""

    name = "mock_agent"

    def __init__(self, authorizer: Authorizer = allow_all):
        self._authorizer = authorizer

    def _execute(self, principal, call: ToolCall) -> None:
        allowed, reason = self._authorizer(principal, call.name, call.arguments)
        if allowed:
            call.executed = True
        else:
            call.executed = False
            call.block_reason = reason

    def invoke(self, inv: Invocation) -> AgentResponse:
        # The vulnerability: everything is concatenated into one planning
        # surface. A secure agent would treat only `user_input` as instructions
        # and everything else as inert data.
        assembled = "\n".join(
            [inv.user_input]
            + list(inv.retrieved_docs)
            + list(inv.memory)
            + list(inv.upstream_messages)
        )

        response = AgentResponse()
        for name, argblob in _DIRECTIVE.findall(assembled):
            call = ToolCall(name=name, arguments=_parse_args(argblob))
            self._execute(inv.principal, call)
            response.tool_calls.append(call)

        executed = response.executed_names()
        if executed:
            response.text = f"Completed actions: {', '.join(sorted(executed))}."
        else:
            response.text = "No actions taken."

        # For multi-agent scenarios, this agent forwards a 'summary' of what it
        # saw to a downstream agent — carrying any injected directive along.
        if inv.retrieved_docs:
            response.downstream_messages.append(
                "Summary of source material: " + " ".join(inv.retrieved_docs)
            )
        return response


def build_mock(authorizer: Authorizer = allow_all) -> MockAgent:
    """Factory used by PolicyEnforcedTarget to rebuild the agent with a
    different authorizer."""
    return MockAgent(authorizer=authorizer)
