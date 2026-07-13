"""Runs a probe suite against a target and aggregates the findings."""
from __future__ import annotations

from dataclasses import dataclass, field

from .probes import ALL_PROBES, Finding, Probe
from .target import Target


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if not f.passed]

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.passed]

    def summary(self) -> dict:
        return {
            "target": self.target,
            "total": len(self.findings),
            "failed": len(self.failed),
            "passed": len(self.passed),
        }


def run_suite(target: Target, probes: list[Probe] | None = None) -> Report:
    probes = probes if probes is not None else ALL_PROBES
    report = Report(target=target.name)
    for probe in probes:
        report.findings.append(probe.run(target))
    # worst findings first
    report.findings.sort(key=lambda f: (f.passed, -f.severity))
    return report
