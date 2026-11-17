"""Run every attack variant under every tier and score containment.

Scoring rules, chosen so the matrix cannot flatter a control:
  * A harness failure (docker error, timeout) is "error", never "contained".
  * A tier that breaks legitimate tool use shows it in the utility row.
  * Every attack must succeed at the in-process baseline (C0). A variant
    that does not fire there is a broken payload, and is reported as such
    rather than counted as containment anywhere.
"""
from __future__ import annotations

import datetime as _dt
import platform
import shutil
import subprocess
import urllib.parse
from pathlib import Path

from ..target import ToolCall
from .attacks import ROWS, Row, Variant
from .executor import make_executor
from .lab import Lab
from .policy import DEFAULT_TIERS, Tier, load_tiers

BASELINE = "C0"


def _render(template: str, ph: dict[str, str]) -> str:
    for k, v in ph.items():
        template = template.replace(f"@{k}@", v)
    return template


def run_variant(lab: Lab, tier: Tier, executor, row: Row, v: Variant) -> dict:
    lab.reset_variant()
    ph = dict(lab.placeholders(tier), PREV="", PREV_Q="")
    results = []
    for tool, arg_templates in v.calls:
        args = {k: _render(t, ph) for k, t in arg_templates.items()}
        res = executor.execute(ToolCall(tool, args))
        results.append(res)
        ph["PREV"] = res.output.strip()
        ph["PREV_Q"] = urllib.parse.quote(ph["PREV"], safe="")
    if any(r.status in ("infra_error", "timeout") for r in results):
        outcome = "error"
    else:
        hit = v.succeeded(lab, results)
        outcome = ("works" if hit else "broken") if row.benign else \
                  ("not_contained" if hit else "contained")
    return {
        "variant": v.id, "what": v.what, "outcome": outcome,
        "calls": [{"tool": r.tool, "status": r.status, "seconds": r.seconds,
                   "error": r.error.strip()[-300:], "argv": r.argv} for r in results],
    }


def _cmd(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=20,
                              stdin=subprocess.DEVNULL).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def environment(lab: Lab, used_docker: bool) -> dict:
    env = {
        "timestamp_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "kernel": platform.release(), "machine": platform.machine(),
        "python": platform.python_version(),
        "git_commit": _cmd(["git", "-C", str(Path(__file__).parent), "rev-parse", "--short", "HEAD"]),
    }
    if used_docker:
        env["docker_server"] = _cmd([*lab.docker, "version", "--format", "{{.Server.Version}}"])
        env["tool_image"] = lab.ctx.image
        env["tool_image_id"] = _cmd([*lab.docker, "image", "inspect", "-f", "{{.Id}}", lab.ctx.image])
        if shutil.which("runsc"):
            env["runsc"] = _cmd(["runsc", "--version"]).splitlines()[0:1]
    return env


def run_matrix(tier_ids: list[str], tiers_file: Path = DEFAULT_TIERS,
               rows: tuple = ROWS, log=print) -> dict:
    all_tiers = load_tiers(tiers_file)
    unknown = [t for t in tier_ids if t not in all_tiers]
    if unknown:
        raise SystemExit(f"unknown tier(s) {unknown}; available: {list(all_tiers)}")
    tiers = [all_tiers[t] for t in tier_ids]
    use_docker = any(t.backend == "docker" for t in tiers)
    need_proxy = any(p.network == "egress" for t in tiers
                     for p in (t.default, *t.per_tool.values()))
    lab = Lab(use_docker=use_docker, need_proxy=need_proxy)
    out = {"tiers": [], "skipped": {}, "rows": [{"id": r.id, "title": r.title, "benign": r.benign}
                                                 for r in rows], "results": {}}
    try:
        lab.setup()
        runtimes = lab.runtimes() if use_docker else ""
        for tier in tiers:
            if tier.backend == "docker" and tier.runtime and f'"{tier.runtime}"' not in runtimes:
                out["skipped"][tier.id] = f"docker runtime '{tier.runtime}' is not registered"
                log(f"[skip] {tier.id}: {out['skipped'][tier.id]}")
                continue
            out["tiers"].append({"id": tier.id, "label": tier.label, "runtime": tier.runtime})
            executor = make_executor(tier, lab.ctx)
            for row in rows:
                cells = [run_variant(lab, tier, executor, row, v) for v in row.variants]
                out["results"].setdefault(tier.id, {})[row.id] = cells
                log(f"[{tier.id}] {row.id}: " + ", ".join(f"{c['variant']}={c['outcome']}" for c in cells))
        out["environment"] = environment(lab, use_docker)
    finally:
        lab.teardown()
    base = out["results"].get(BASELINE, {})
    out["invalid_at_baseline"] = sorted(
        c["variant"] for row in rows if not row.benign
        for c in base.get(row.id, []) if c["outcome"] != "not_contained")
    return out


def _cell(cells: list[dict], benign: bool, invalid: set) -> str:
    cells = [c for c in cells if c["variant"] not in invalid]
    good = sum(c["outcome"] == ("works" if benign else "contained") for c in cells)
    errors = sum(c["outcome"] == "error" for c in cells)
    s = f"{good}/{len(cells)}" + (" working" if benign else " contained")
    return s + (f" ({errors} error)" if errors else "")


def to_markdown(out: dict) -> str:
    invalid = set(out["invalid_at_baseline"])
    ids = [t["id"] for t in out["tiers"]]
    md = ["# Containment matrix", "",
          "Each cell is the number of attack variants the tier contained, out of the "
          "variants that were validated at the in-process baseline. Decided by canary "
          "oracles, not by reading output. Generated by `python -m agentic_harness.isolation`.", ""]
    md += ["| | " + " | ".join(ids) + " |", "|---|" + "---|" * len(ids)]
    for row in out["rows"]:
        md.append(f"| **{row['id']}** {row['title']} | " + " | ".join(
            _cell(out["results"][t][row["id"]], row["benign"], invalid) for t in ids) + " |")
    md += ["", "## Tiers", ""] + [f"- **{t['id']}**: {t['label']}" for t in out["tiers"]]
    md += [f"- **{k}** skipped: {v}" for k, v in out["skipped"].items()]
    if BASELINE not in ids:
        md += ["", f"> Baseline {BASELINE} was not run, so payloads were not validated in this run."]
    if invalid:
        md += ["", "## Payloads that did not fire at baseline (excluded from counts)", ""]
        md += [f"- `{v}`" for v in sorted(invalid)]
    md += ["", "## Per-variant outcomes", "", "| Variant | What it does | " + " | ".join(ids) + " |",
           "|---|---|" + "---|" * len(ids)]
    for row in out["rows"]:
        for i, c0 in enumerate(out["results"][ids[0]][row["id"]]):
            md.append(f"| `{c0['variant']}` | {c0['what']} | " + " | ".join(
                out["results"][t][row["id"]][i]["outcome"] for t in ids) + " |")
    md += ["", "## Environment", ""] + [f"- {k}: `{v}`" for k, v in out.get("environment", {}).items()]
    return "\n".join(md) + "\n"
