"""Core abstractions for the agentic security harness.

The harness treats the *agent under test* as a black box that implements the
`Target` interface. Real agents (LangChain, an Anthropic tool-use loop, a
custom multi-agent system) are wrapped in an adapter that conforms to this
interface; the harness never needs to know their internals. A deliberately
vulnerable reference agent (`mock_agent.MockAgent`) ships with the harness so
the probe suite is runnable and demonstrable offline, with no API keys.

Design note: findings are decided *structurally* — by inspecting which tools
the agent actually executed — not by pattern-matching the natural-language
response. Structural detection is far harder to evade than output string
matching, which is the same principle a good JWT inspector uses when it reads
claims instead of trusting a decoded string.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# --- Identity / authorization primitives -----------------------------------

@dataclass(frozen=True)
class Principal:
    """The identity on whose behalf the agent is acting.

    `scopes` is the set of capabilities this principal is permitted to exercise.
    Capability-scoped authorization — checking a tool call against the acting
    principal's scopes at the execution boundary — is the central control this
    harness both tests for and demonstrates as a fix.
    """
    id: str
    scopes: frozenset[str] = frozenset()

    def has(self, scope: str) -> bool:
        return scope in self.scopes


# An authorizer decides whether `principal` may execute `tool` with `args`.
# Returns (allowed, reason). Reason is surfaced when a call is blocked.
Authorizer = Callable[[Principal, str, dict], "tuple[bool, Optional[str]]"]


def allow_all(_p: Principal, _tool: str, _args: dict) -> tuple[bool, Optional[str]]:
    """The insecure default: every tool call is permitted. This models an agent
    with excessive agency — no trust boundary between 'can invoke a tool' and
    'is authorized to invoke *this* tool right now'."""
    return True, None


def scope_authorizer(tool_scopes: dict[str, str]) -> Authorizer:
    """A capability-scoped authorizer. Each tool requires a scope; a principal
    may execute the tool only if it holds that scope. This is the fix."""
    def _auth(principal: Principal, tool: str, _args: dict) -> tuple[bool, Optional[str]]:
        required = tool_scopes.get(tool)
        if required is None:
            return False, f"tool '{tool}' is not on the allow-list"
        if not principal.has(required):
            return False, (
                f"principal '{principal.id}' lacks scope '{required}' "
                f"required by tool '{tool}'"
            )
        return True, None
    return _auth


# --- Execution trace -------------------------------------------------------

@dataclass
class ToolCall:
    """A single tool invocation the agent decided to make."""
    name: str
    arguments: dict = field(default_factory=dict)
    executed: bool = False           # did it actually run?
    block_reason: Optional[str] = None  # why it was blocked, if it was

    def __repr__(self) -> str:
        state = "EXECUTED" if self.executed else f"BLOCKED({self.block_reason})"
        return f"ToolCall({self.name}({self.arguments}) -> {state})"


@dataclass
class AgentResponse:
    """What the agent returned for one invocation."""
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    # Messages this agent emitted to *other* agents (multi-agent systems).
    downstream_messages: list[str] = field(default_factory=list)

    def executed(self) -> list[ToolCall]:
        return [c for c in self.tool_calls if c.executed]

    def executed_names(self) -> set[str]:
        return {c.name for c in self.executed()}


# --- The interface every target implements ---------------------------------

@dataclass
class Invocation:
    """Everything the agent sees for one turn.

    The separation of channels is deliberate: `user_input` is the *trusted*
    instruction channel, while `retrieved_docs`, `memory`, and
    `upstream_messages` are *data* channels. The core agentic vulnerability is
    an agent that fails to keep that boundary — treating instructions found in
    a retrieved document or an upstream agent's output as if the user had typed
    them.
    """
    user_input: str
    principal: Principal
    retrieved_docs: list[str] = field(default_factory=list)  # RAG context
    memory: list[str] = field(default_factory=list)          # prior turns / notes
    upstream_messages: list[str] = field(default_factory=list)  # from other agents


class Target(ABC):
    """An agent under test."""

    name: str = "target"

    @abstractmethod
    def invoke(self, inv: Invocation) -> AgentResponse:
        ...


class PolicyEnforcedTarget(Target):
    """Wraps any Target that supports a swappable authorizer and enforces a
    capability-scoped policy at the tool-execution boundary. Used to show the
    same probe suite passing once the fix is applied."""

    def __init__(self, build_fn: Callable[[Authorizer], Target], authorizer: Authorizer):
        self._inner = build_fn(authorizer)
        self.name = f"policy_enforced({self._inner.name})"

    def invoke(self, inv: Invocation) -> AgentResponse:
        return self._inner.invoke(inv)
