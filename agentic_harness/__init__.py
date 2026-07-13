"""agentic-harness: a red-team harness for LLM tool-using / multi-agent systems.

Tests the agentic attack surface (tool-call injection, indirect/RAG injection,
excessive agency, cross-agent trust, memory poisoning) and demonstrates the fix
via capability-scoped tool authorization.
"""
from .mock_agent import MockAgent, TOOL_SCOPES, build_mock
from .report import to_json, to_markdown
from .runner import Report, run_suite
from .target import (
    AgentResponse,
    Authorizer,
    Invocation,
    PolicyEnforcedTarget,
    Principal,
    Target,
    ToolCall,
    allow_all,
    scope_authorizer,
)

__version__ = "0.1.0"
__all__ = [
    "MockAgent", "TOOL_SCOPES", "build_mock",
    "run_suite", "Report", "to_markdown", "to_json",
    "Target", "Invocation", "Principal", "AgentResponse", "ToolCall",
    "Authorizer", "allow_all", "scope_authorizer", "PolicyEnforcedTarget",
]
