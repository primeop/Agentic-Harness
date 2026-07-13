"""Runs a probe suite against a target and aggregates the findings."""
from __future__ import annotations

from dataclasses import dataclass, field

from .probes import ALL_PROBES, Finding, Probe
from .probes.base import Severity
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


# --------------------------------------------------------------------------
# Repeated runs for stochastic targets (real LLM agents)
#
# The mock is deterministic, so one pass is the whole truth. A real model is
# not: whether an injection lands can vary run to run. Reporting a single
# pass/fail for a stochastic system is misleading. `run_suite_repeated` runs
# the suite N times and reports, per probe, how often the attack landed —
# a fired X/N hit rate — which is the honest way to characterize a
# probabilistic control failure.
# --------------------------------------------------------------------------


@dataclass
class ProbeStats:
    probe: str
    owasp: str
    severity: Severity
    runs: int
    fails: int  # runs where the target was vulnerable (attack landed)
    title: str = ""
    detail: str = ""
    example_evidence: list[str] = field(default_factory=list)

    @property
    def passes(self) -> int:
        return self.runs - self.fails

    @property
    def hit_rate(self) -> float:
        return self.fails / self.runs if self.runs else 0.0


@dataclass
class RepeatedReport:
    target: str
    runs: int
    stats: list[ProbeStats] = field(default_factory=list)

    @property
    def ever_failed(self) -> list[ProbeStats]:
        return [s for s in self.stats if s.fails]

    def summary(self) -> dict:
        return {
            "target": self.target,
            "runs": self.runs,
            "probes": len(self.stats),
            "probes_ever_vulnerable": len(self.ever_failed),
        }


def run_suite_repeated(
    target: Target, runs: int = 5, probes: list[Probe] | None = None
) -> RepeatedReport:
    """Run the suite `runs` times and aggregate per-probe hit rates.

    Each invocation of a probe hits the target afresh (for a real LLM adapter,
    that means a new API call), so variance across runs is captured.
    """
    if runs < 1:
        raise ValueError("runs must be >= 1")
    probes = probes if probes is not None else ALL_PROBES
    agg: dict[str, ProbeStats] = {}
    for _ in range(runs):
        for probe in probes:
            f = probe.run(target)
            st = agg.get(f.probe)
            if st is None:
                st = ProbeStats(
                    probe=f.probe, owasp=f.owasp, severity=f.severity,
                    runs=0, fails=0,
                )
                agg[f.probe] = st
            st.runs += 1
            if not f.passed:
                st.fails += 1
                # keep evidence + wording from a representative failing run
                if not st.example_evidence:
                    st.title, st.detail = f.title, f.detail
                    st.example_evidence = f.evidence
    report = RepeatedReport(target=target.name, runs=runs, stats=list(agg.values()))
    # worst first: by hit rate, then severity
    report.stats.sort(key=lambda s: (-s.hit_rate, -s.severity))
    return report
