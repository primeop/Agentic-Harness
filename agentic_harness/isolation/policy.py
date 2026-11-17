"""Declarative runtime policy for tool execution.

`target.py` answers "may this principal call this tool?" (capability scope).
This module answers the next question: "given that the tool runs, what can
its process reach?" A Tier is one column of the containment matrix: a
backend (in-process or Docker), a container runtime, a default ToolPolicy,
and optional per-tool overrides. Tiers are data (tiers.json), so adding a
control layer is a config change that the evals then measure.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Optional

DEFAULT_TIERS = Path(__file__).with_name("tiers.json")


@dataclass(frozen=True)
class ToolPolicy:
    # "lab"    = bridged network with a route to everything (no egress control)
    # "none"   = no network interface at all
    # "egress" = internal-only network; the only way out is the allowlisting proxy
    network: str = "lab"
    user: Optional[str] = None        # e.g. "65534:65534"; None = image default (root)
    cap_drop_all: bool = False
    no_new_privileges: bool = False
    read_only_rootfs: bool = False
    workspace_mode: str = "rw"        # "rw" | "ro"
    pids_limit: Optional[int] = None
    memory: Optional[str] = None      # e.g. "256m"
    seccomp: Optional[str] = None     # path to a profile; None = Docker's default
    ambient_env_creds: bool = True    # long-lived API key present in the environment
    ambient_cred_file: bool = True    # credentials file mounted into the sandbox

    def __post_init__(self):
        if self.network not in ("lab", "none", "egress"):
            raise ValueError(f"unknown network mode: {self.network!r}")
        if self.workspace_mode not in ("rw", "ro"):
            raise ValueError(f"unknown workspace_mode: {self.workspace_mode!r}")


_POLICY_FIELDS = {f.name for f in fields(ToolPolicy)}


def _policy(base: ToolPolicy, overrides: dict) -> ToolPolicy:
    unknown = set(overrides) - _POLICY_FIELDS
    if unknown:  # a typo in a security policy must fail loudly, not be ignored
        raise ValueError(f"unknown policy keys: {sorted(unknown)}")
    return replace(base, **overrides)


@dataclass(frozen=True)
class Tier:
    id: str
    label: str
    backend: str                      # "inprocess" | "docker"
    runtime: Optional[str] = None     # docker --runtime value, e.g. "runc", "runsc"
    default: ToolPolicy = field(default_factory=ToolPolicy)
    per_tool: dict = field(default_factory=dict)

    def policy_for(self, tool: str) -> ToolPolicy:
        return self.per_tool.get(tool, self.default)


def load_tiers(path: Path = DEFAULT_TIERS) -> dict[str, Tier]:
    raw = json.loads(Path(path).read_text())
    tiers: dict[str, Tier] = {}
    for t in raw["tiers"]:
        if t["backend"] not in ("inprocess", "docker"):
            raise ValueError(f"tier {t['id']}: unknown backend {t['backend']!r}")
        default = _policy(ToolPolicy(), t.get("policy", {}))
        per_tool = {name: _policy(default, o) for name, o in t.get("tools", {}).items()}
        tiers[t["id"]] = Tier(t["id"], t["label"], t["backend"], t.get("runtime"),
                              default, per_tool)
    return tiers
