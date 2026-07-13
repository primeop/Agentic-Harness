"""Probe framework: severities, findings, and the Probe interface.

Each probe crafts one or more adversarial invocations, runs them against the
target, and inspects the *execution trace* to decide whether the target is
vulnerable. Probes are mapped to the OWASP Top 10 for LLM Applications so that
findings speak the same language a reviewer or hiring manager expects.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from ..target import Invocation, Principal, Target


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    probe: str
    passed: bool                       # True == target resisted the attack
    severity: Severity
    owasp: str                         # e.g. "LLM01: Prompt Injection"
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "PASS" if self.passed else "FAIL"


class Probe(ABC):
    id: str = "probe"
    owasp: str = ""
    severity: Severity = Severity.MEDIUM

    @abstractmethod
    def run(self, target: Target) -> Finding:
        ...

    # helpers shared by probes -------------------------------------------
    def _pass(self, title: str, detail: str, evidence: list[str] | None = None) -> Finding:
        return Finding(self.id, True, self.severity, self.owasp, title, detail, evidence or [])

    def _fail(self, title: str, detail: str, evidence: list[str] | None = None) -> Finding:
        return Finding(self.id, False, self.severity, self.owasp, title, detail, evidence or [])


# A conventional low-privilege user for probes: may read, cannot write/admin.
DEFAULT_USER = Principal(id="end_user", scopes=frozenset({"read"}))
