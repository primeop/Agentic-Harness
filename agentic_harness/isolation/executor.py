"""The execution seam: one interface, one backend per isolation mechanism.

Everything above this line (agents, probes, attack scripts) emits ToolCalls.
Everything below it decides where the tool's code actually runs and what it
can reach. Swapping the executor is the only thing that changes between
columns of the containment matrix, so a difference in outcome is
attributable to the runtime control and nothing else.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..target import ToolCall
from .policy import Tier, ToolPolicy
from .tools import run_tool

CRED_ENV_VAR = "AH_API_KEY"
CONTAINER_WORKSPACE = "/workspace"
CONTAINER_CRED_FILE = "/home/agent/.svc/credentials"
# docker's own exit codes: 125 = daemon/CLI error, 126/127 = command could not
# be invoked. These mean the harness failed, not that the attack was contained.
DOCKER_INFRA_CODES = {125, 126, 127}


@dataclass
class SandboxContext:
    """Lab facts the executor needs; owned by Lab, shared by all tiers."""
    workspace: Path                 # host path of the agent's workspace
    cred_file: Path                 # host path of the ambient credentials file
    cred_env_value: str             # value of the ambient API key
    docker: list[str] = field(default_factory=lambda: ["docker"])
    image: str = "python:3.12-alpine"
    network: str = "ah-lab"
    internal_network: str = "ah-internal"
    egress_proxy: str | None = None  # http://<proxy ip>:3128 as seen from the internal network
    tools_dir: Path = Path(run_tool.__file__).resolve().parent


@dataclass
class ExecResult:
    tool: str
    args: dict
    status: str                     # "ok" | "tool_error" | "infra_error" | "timeout"
    output: str = ""
    error: str = ""
    argv: list[str] | None = None   # the exact docker command, for the report
    seconds: float = 0.0

    @property
    def text(self) -> str:
        return self.output + "\n" + self.error


class ToolExecutor(ABC):
    def __init__(self, tier: Tier, ctx: SandboxContext):
        self.tier, self.ctx = tier, ctx

    @abstractmethod
    def _run(self, tool: str, args: dict, policy: ToolPolicy) -> ExecResult:
        ...

    def execute(self, call: ToolCall) -> ExecResult:
        t0 = time.monotonic()
        res = self._run(call.name, call.arguments, self.tier.policy_for(call.name))
        res.seconds = round(time.monotonic() - t0, 3)
        call.executed = res.status in ("ok", "tool_error")
        if not call.executed:
            call.block_reason = f"{res.status}: {res.error[:200]}"
        return res


class InProcessExecutor(ToolExecutor):
    """Tier C0: the tool runs inside the harness process, as most agent
    frameworks run tools by default. No boundary of any kind."""

    def _run(self, tool, args, policy):
        saved = os.environ.get(CRED_ENV_VAR)
        if policy.ambient_env_creds:
            os.environ[CRED_ENV_VAR] = self.ctx.cred_env_value
        try:
            r = run_tool.dispatch(tool, args)
        finally:
            if saved is None:
                os.environ.pop(CRED_ENV_VAR, None)
            else:
                os.environ[CRED_ENV_VAR] = saved
        return ExecResult(tool, args, "ok" if r["ok"] else "tool_error",
                          r["output"], r["error"])


def build_docker_argv(tier: Tier, policy: ToolPolicy, ctx: SandboxContext,
                      name: str, tool: str, args: dict) -> list[str]:
    """Translate a ToolPolicy into a `docker run` command. Pure function so
    the policy-to-flags mapping is unit-testable without a Docker daemon."""
    argv = [*ctx.docker, "run", "--rm", "--name", name]
    if tier.runtime:
        argv += ["--runtime", tier.runtime]
    argv += ["--network", {"none": "none", "lab": ctx.network,
                           "egress": ctx.internal_network}[policy.network]]
    if policy.user:
        argv += ["--user", policy.user]
    if policy.cap_drop_all:
        argv += ["--cap-drop", "ALL"]
    if policy.no_new_privileges:
        argv += ["--security-opt", "no-new-privileges"]
    if policy.seccomp:
        argv += ["--security-opt", f"seccomp={policy.seccomp}"]
    if policy.read_only_rootfs:
        argv += ["--read-only", "--tmpfs", "/tmp"]
    if policy.pids_limit:
        argv += ["--pids-limit", str(policy.pids_limit)]
    if policy.memory:
        argv += ["--memory", policy.memory]
    argv += ["-e", "PYTHONDONTWRITEBYTECODE=1"]
    if policy.network == "egress":
        if not ctx.egress_proxy:
            raise RuntimeError("policy asks for egress control but no proxy is running")
        argv += ["-e", f"AH_EGRESS_PROXY={ctx.egress_proxy}"]
    if policy.ambient_env_creds:
        argv += ["-e", f"{CRED_ENV_VAR}={ctx.cred_env_value}"]
    argv += ["-v", f"{ctx.tools_dir}:/tools:ro",
             "-v", f"{ctx.workspace}:{CONTAINER_WORKSPACE}:{policy.workspace_mode}"]
    if policy.ambient_cred_file:
        argv += ["-v", f"{ctx.cred_file}:{CONTAINER_CRED_FILE}:ro"]
    argv += [ctx.image, "python3", "/tools/run_tool.py", tool, json.dumps(args)]
    return argv


class DockerExecutor(ToolExecutor):
    """One fresh container per tool call, configured from the tool's policy.
    The container runtime (runc, runsc, ...) comes from the tier."""

    timeout = 60

    def _run(self, tool, args, policy):
        name = f"ah-tool-{uuid.uuid4().hex[:10]}"
        argv = build_docker_argv(self.tier, policy, self.ctx, name, tool, args)
        try:
            p = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                               timeout=self.timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            subprocess.run([*self.ctx.docker, "kill", name], capture_output=True,
                           stdin=subprocess.DEVNULL)
            return ExecResult(tool, args, "timeout", error="outer timeout", argv=argv)
        if p.returncode in DOCKER_INFRA_CODES:
            return ExecResult(tool, args, "infra_error", p.stdout, p.stderr, argv)
        lines = p.stdout.strip().splitlines()
        try:
            r = json.loads(lines[-1])
            return ExecResult(tool, args, "ok" if r["ok"] else "tool_error",
                              r["output"], r["error"], argv)
        except (IndexError, ValueError, KeyError, TypeError):
            # The tool process died without reporting (e.g. killed by a limit).
            return ExecResult(tool, args, "tool_error", p.stdout,
                              f"exit {p.returncode}: {p.stderr}", argv)


def make_executor(tier: Tier, ctx: SandboxContext) -> ToolExecutor:
    return InProcessExecutor(tier, ctx) if tier.backend == "inprocess" else DockerExecutor(tier, ctx)
