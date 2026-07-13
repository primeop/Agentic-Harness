"""Render a Report to markdown or JSON."""
from __future__ import annotations

import json

from .runner import Report


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
