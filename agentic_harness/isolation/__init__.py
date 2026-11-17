"""Execution-isolation layer: run agent tool calls under increasingly strict
runtime controls and measure, with ground-truth canaries, which attacks each
control contains."""
from .executor import DockerExecutor, ExecResult, InProcessExecutor, ToolExecutor, build_docker_argv
from .matrix import run_matrix, to_markdown
from .policy import Tier, ToolPolicy, load_tiers

__all__ = ["ToolExecutor", "InProcessExecutor", "DockerExecutor", "ExecResult",
           "build_docker_argv", "Tier", "ToolPolicy", "load_tiers", "run_matrix", "to_markdown"]
