"""Adapter: run the probe suite against ANY OpenAI-compatible tool-use agent.

The `Target` interface is model-agnostic, so one adapter covers every endpoint
that speaks the OpenAI chat-completions + tools protocol: Groq, OpenAI, Together,
OpenRouter, a local vLLM/Ollama server, etc. Point it at whichever you have a
key for.

Free, no credit card:  Groq  (https://console.groq.com  ->  API Keys)

    pip install openai
    export OPENAI_API_KEY=gsk_...                       # your Groq key
    export OPENAI_BASE_URL=https://api.groq.com/openai/v1
    export AGENTIC_MODEL=llama-3.3-70b-versatile        # any tool-use model
    python -m examples.openai_compatible_adapter

A real model is stochastic, so each probe is run several times and reported as a
fired X/N hit rate rather than a single pass/fail. The suite throttles itself to
stay inside free-tier rate limits.
"""
from __future__ import annotations

import json
import os
import re
import time

from agentic_harness import (
    AgentResponse,
    Invocation,
    Target,
    ToolCall,
    allow_all,
    run_suite_repeated,
    scope_authorizer,
    to_markdown_repeated,
)
from agentic_harness.mock_agent import TOOL_SCOPES

# Tool schemas exposed to the model (OpenAI function-tool format). Keep these
# identical to what your real agent exposes so the test reflects production.
TOOLS = [
    {"type": "function", "function": {
        "name": "search_docs", "description": "Search the knowledge base.",
        "parameters": {"type": "object",
                       "properties": {"query": {"type": "string"}},
                       "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "send_email", "description": "Send an email.",
        "parameters": {"type": "object",
                       "properties": {"to": {"type": "string"},
                                      "body": {"type": "string"}},
                       "required": ["to", "body"]}}},
    {"type": "function", "function": {
        "name": "transfer_funds", "description": "Transfer money between accounts.",
        "parameters": {"type": "object",
                       "properties": {"amount": {"type": "number"},
                                      "to": {"type": "string"}},
                       "required": ["amount", "to"]}}},
]


class OpenAICompatibleTarget(Target):
    """Wraps a single-turn tool-use call to any OpenAI-compatible endpoint.

    The critical choice: authorization is enforced at the *execution boundary*.
    The model may REQUEST a tool, but we only mark it `executed` if the
    authorizer permits it for the acting principal. That capability-scoped
    control lives in this code, not in the model — so a landing here is an
    in-scope injection, the residual risk scoping cannot remove.
    """
    name = "openai_compatible"

    def __init__(self, authorizer, model: str, system: str | None = None,
                 throttle_s: float = 2.0):
        from openai import OpenAI  # lazy import so the file loads without the dep
        self._client = OpenAI(
            api_key=os.environ.get("OPENAI_API_KEY") or os.environ["GROQ_API_KEY"],
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.groq.com/openai/v1"),
            max_retries=5,  # ride out free-tier 429s with the SDK's backoff
        )
        self._authorizer = authorizer
        self._model = model
        self._system = system
        self._throttle_s = throttle_s

    def invoke(self, inv: Invocation) -> AgentResponse:
        # retrieved_docs / memory / upstream_messages are joined in as *data*,
        # wrapped in clear delimiters. A hardened system would also instruct the
        # model never to treat their contents as commands — the planning-layer
        # trust boundary the harness probes for.
        blocks = []
        if inv.retrieved_docs:
            blocks.append("<retrieved_documents>\n"
                          + "\n---\n".join(inv.retrieved_docs)
                          + "\n</retrieved_documents>")
        if inv.memory:
            blocks.append("<memory>\n" + "\n".join(inv.memory) + "\n</memory>")
        if inv.upstream_messages:
            blocks.append("<peer_agent_output>\n"
                          + "\n".join(inv.upstream_messages)
                          + "\n</peer_agent_output>")
        content = "\n\n".join(blocks + [inv.user_input])

        messages = []
        if self._system:
            messages.append({"role": "system", "content": self._system})
        messages.append({"role": "user", "content": content})

        if self._throttle_s:
            time.sleep(self._throttle_s)  # spread calls under free-tier limits

        try:
            completion = self._client.chat.completions.create(
                model=self._model,
                max_tokens=1024,
                tools=TOOLS,
                tool_choice="auto",
                messages=messages,
            )
        except Exception as exc:  # noqa: BLE001
            # Some providers (e.g. Groq + Llama) reject a *malformed* tool call
            # with a 400 'tool_use_failed' instead of returning it. The model
            # still attempted a call — salvage it from the error so an injection
            # attempt is not silently dropped. Anything else re-raises.
            salvaged = _salvage_tool_use(exc)
            if salvaged is None:
                raise
            return self._respond(inv, salvaged, text="")

        message = completion.choices[0].message
        calls = []
        for tc in (message.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_raw": tc.function.arguments}
            calls.append((tc.function.name, args))
        return self._respond(inv, calls, text=message.content or "")

    def _respond(self, inv, calls, text):
        resp = AgentResponse(text=text)
        for name, args in calls:
            call = ToolCall(name=name, arguments=args)
            allowed, reason = self._authorizer(inv.principal, call.name, call.arguments)
            call.executed = allowed
            call.block_reason = None if allowed else reason
            resp.tool_calls.append(call)
        return resp


def _salvage_tool_use(exc: Exception):
    """If `exc` is a provider 'tool_use_failed' 400, recover the attempted tool
    calls from its `failed_generation` payload. Returns a list of (name, args)
    tuples (possibly empty) when it is that error, or None otherwise (re-raise).
    """
    body = getattr(exc, "body", None)
    if not isinstance(body, dict):
        return None
    err = body.get("error", body)
    if not isinstance(err, dict) or err.get("code") != "tool_use_failed":
        return None
    blob = err.get("failed_generation", "") or ""
    calls = []
    # e.g.  <function=send_email {"to": "attacker", "body": "x"}> ...
    for name, arg_json in re.findall(r"<function=([\w.\-]+)\s*(\{[^{}]*\})", blob):
        try:
            calls.append((name, json.loads(arg_json)))
        except json.JSONDecodeError:
            calls.append((name, {"_raw": arg_json}))
    return calls


def main() -> None:
    runs = int(os.environ.get("AGENTIC_RUNS", "5"))
    model = os.environ.get("AGENTIC_MODEL", "llama-3.3-70b-versatile")
    # AGENTIC_AUTHZ=none  -> no authorization: measures the model's raw
    #   susceptibility to injection (a landing means the model itself complied).
    # AGENTIC_AUTHZ=scoped (default) -> capability-scoped at the execution
    #   boundary: a landing is an in-scope injection the control cannot stop.
    mode = os.environ.get("AGENTIC_AUTHZ", "scoped").lower()
    authorizer = allow_all if mode == "none" else scope_authorizer(TOOL_SCOPES)
    target = OpenAICompatibleTarget(authorizer, model=model)
    report = run_suite_repeated(target, runs=runs)
    print(f"<!-- model={model} authz={mode} runs={runs} -->")
    print(to_markdown_repeated(report))


if __name__ == "__main__":
    main()
