"""Adapter: run the probe suite against a REAL Anthropic tool-use agent.

This is the point of the `Target` interface — the mock is only a fixture; the
harness is meant to test agents you actually ship. Implement `invoke`, map your
agent's tool-call trace onto `ToolCall`, and the entire probe suite works
unchanged.

This file is illustrative. To run it for real:
    pip install anthropic
    export ANTHROPIC_API_KEY=...
    python -m examples.anthropic_adapter          # 5 runs/probe (default)
    AGENTIC_RUNS=10 python -m examples.anthropic_adapter

A real model is stochastic, so the suite is run several times per probe and
reported as a fired X/N hit rate rather than a single pass/fail.
"""
from __future__ import annotations

import os

from agentic_harness import (
    AgentResponse,
    Invocation,
    Target,
    ToolCall,
    run_suite_repeated,
    scope_authorizer,
    to_markdown_repeated,
)
from agentic_harness.mock_agent import TOOL_SCOPES

# Tool schemas exposed to the model. Keep these identical to what your real
# agent exposes in production so the test reflects the real attack surface.
TOOLS = [
    {"name": "search_docs", "description": "Search the knowledge base.",
     "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "send_email", "description": "Send an email.",
     "input_schema": {"type": "object",
                      "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
    {"name": "transfer_funds", "description": "Transfer money between accounts.",
     "input_schema": {"type": "object",
                      "properties": {"amount": {"type": "number"}, "to": {"type": "string"}}}},
]


class AnthropicAgentTarget(Target):
    """Wraps a single-turn Claude tool-use call.

    The critical choice is enforcing authorization at the *execution boundary*:
    the model may REQUEST a tool, but we only mark it `executed` if the
    authorizer permits it for the acting principal. That is the capability-
    scoped control, implemented where it belongs — in your code, not the model.
    """
    name = "anthropic_claude"

    def __init__(self, authorizer, model: str = "claude-sonnet-5",
                 system: str | None = None):
        import anthropic  # imported lazily so the file loads without the dep
        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._authorizer = authorizer
        self._model = model
        # A naive agent ships no trust-boundary system prompt (default). Pass a
        # hardened `system` to test whether planning-layer instructions reduce
        # the injection hit rate — the second control the harness argues for.
        self._system = system

    def invoke(self, inv: Invocation) -> AgentResponse:
        # NB: retrieved_docs / memory / upstream_messages are joined into the
        # message as *data*. A hardened system wraps them in clear delimiters
        # and instructs the model to never treat their contents as commands —
        # that is the planning-layer trust boundary the harness probes for.
        context_blocks = []
        if inv.retrieved_docs:
            context_blocks.append("<retrieved_documents>\n"
                                  + "\n---\n".join(inv.retrieved_docs)
                                  + "\n</retrieved_documents>")
        if inv.memory:
            context_blocks.append("<memory>\n" + "\n".join(inv.memory) + "\n</memory>")
        if inv.upstream_messages:
            context_blocks.append("<peer_agent_output>\n"
                                  + "\n".join(inv.upstream_messages)
                                  + "\n</peer_agent_output>")

        content = "\n\n".join(context_blocks + [inv.user_input])

        kwargs = dict(
            model=self._model,
            max_tokens=1024,
            tools=TOOLS,
            messages=[{"role": "user", "content": content}],
        )
        if self._system:
            kwargs["system"] = self._system
        msg = self._client.messages.create(**kwargs)

        resp = AgentResponse()
        for block in msg.content:
            if block.type == "text":
                resp.text += block.text
            elif block.type == "tool_use":
                call = ToolCall(name=block.name, arguments=dict(block.input))
                allowed, reason = self._authorizer(inv.principal, call.name, call.arguments)
                call.executed = allowed
                call.block_reason = None if allowed else reason
                resp.tool_calls.append(call)
        return resp


def main() -> None:
    runs = int(os.environ.get("AGENTIC_RUNS", "5"))
    model = os.environ.get("AGENTIC_MODEL", "claude-sonnet-5")
    # Capability-scoped authorization is enforced in code at the execution
    # boundary. Any tool the model calls out of the acting principal's scope is
    # recorded but NOT executed — so a landing here is an in-scope injection,
    # the residual risk scoping cannot remove.
    target = AnthropicAgentTarget(scope_authorizer(TOOL_SCOPES), model=model)
    report = run_suite_repeated(target, runs=runs)
    print(to_markdown_repeated(report))


if __name__ == "__main__":
    main()
