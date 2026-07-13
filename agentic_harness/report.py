"""Render a Report to markdown or JSON."""
from __future__ import annotations

import json

from .runner import RepeatedReport, Report


def to_markdown(report: Report) -> str:
    s = report.summary()
    lines: list[str] = []
    lines.append(f"# Agentic security report — `{report.target}`")
    lines.append("")
    verdict = "🔴 vulnerable" if s["failed"] else "🟢 no findings"
    lines.append(f"**{verdict}** — {s['failed']} failed / {s['passed']} passed "
                 f"of {s['total']} probes.")
    lines.append("")
    lines.append("| Probe | OWASP | Severity | Result |")
    lines.append("|---|---|---|---|")
    for f in report.findings:
        mark = "❌ FAIL" if not f.passed else "✅ PASS"
        lines.append(f"| `{f.probe}` | {f.owasp} | {f.severity.label()} | {mark} |")
    lines.append("")

    if report.failed:
        lines.append("## Findings")
        lines.append("")
        for f in report.failed:
            lines.append(f"### ❌ {f.title}")
            lines.append(f"*{f.probe} · {f.owasp} · {f.severity.label()}*")
            lines.append("")
            lines.append(f.detail)
            if f.evidence:
                lines.append("")
                lines.append("```")
                lines.extend(f.evidence)
                lines.append("```")
            lines.append("")

    if report.passed:
        lines.append("## Controls that held")
        lines.append("")
        for f in report.passed:
            lines.append(f"- ✅ **{f.title}** ({f.probe}) — {f.detail}")
        lines.append("")
    return "\n".join(lines)


def to_markdown_repeated(report: RepeatedReport) -> str:
    """Render a stochastic (multi-run) report with per-probe hit rates."""
    s = report.summary()
    lines: list[str] = []
    lines.append(f"# Agentic security report — `{report.target}`")
    lines.append(f"*{report.runs} runs per probe · stochastic target*")
    lines.append("")
    n = s["probes_ever_vulnerable"]
    verdict = f"🔴 vulnerable — {n} of {s['probes']} probes landed at least once" \
        if n else "🟢 no findings across all runs"
    lines.append(f"**{verdict}.**")
    lines.append("")
    lines.append("| Probe | OWASP | Severity | Hit rate | Landed |")
    lines.append("|---|---|---|---|---|")
    for st in report.stats:
        pct = f"{st.hit_rate * 100:.0f}%"
        mark = "❌" if st.fails else "✅"
        lines.append(
            f"| `{st.probe}` | {st.owasp} | {st.severity.label()} | "
            f"{pct} | {mark} {st.fails}/{st.runs} |"
        )
    lines.append("")

    if report.ever_failed:
        lines.append("## Findings")
        lines.append("")
        for st in report.ever_failed:
            lines.append(f"### ❌ {st.title or st.probe} — fired {st.fails}/{st.runs}")
            lines.append(f"*{st.probe} · {st.owasp} · {st.severity.label()}*")
            lines.append("")
            if st.detail:
                lines.append(st.detail)
            if st.example_evidence:
                lines.append("")
                lines.append("```")
                lines.extend(st.example_evidence)
                lines.append("```")
            lines.append("")
    return "\n".join(lines)


def to_json(report: Report) -> str:
    return json.dumps(
        {
            "summary": report.summary(),
            "findings": [
                {
                    "probe": f.probe,
                    "owasp": f.owasp,
                    "severity": f.severity.label(),
                    "passed": f.passed,
                    "title": f.title,
                    "detail": f.detail,
                    "evidence": f.evidence,
                }
                for f in report.findings
            ],
        },
        indent=2,
    )
