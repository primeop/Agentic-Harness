"""CLI:  python -m agentic_harness.isolation --tiers C0,C1,C2,C3,C3-gvisor"""
import argparse
import json
import sys
from pathlib import Path

from .matrix import run_matrix, to_markdown
from .policy import DEFAULT_TIERS


def main() -> int:
    ap = argparse.ArgumentParser(prog="agentic_harness.isolation")
    ap.add_argument("--tiers", default="C0,C1,C2,C3,C3-gvisor",
                    help="comma-separated tier ids from the tiers file")
    ap.add_argument("--tiers-file", type=Path, default=DEFAULT_TIERS)
    ap.add_argument("--out", type=Path, default=Path("reports/containment"))
    a = ap.parse_args()
    out = run_matrix([t for t in a.tiers.split(",") if t], a.tiers_file)
    if not out["tiers"]:
        print("no tier could run", file=sys.stderr)
        return 2
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "results.json").write_text(json.dumps(out, indent=2))
    md = to_markdown(out)
    (a.out / "matrix.md").write_text(md)
    print("\n" + md.split("## Per-variant")[0])
    print(f"wrote {a.out}/matrix.md and {a.out}/results.json")
    errors = sum(c["outcome"] == "error" for t in out["results"].values()
                 for cells in t.values() for c in cells)
    broken = sum(c["outcome"] == "broken" for t in out["results"].values()
                 for cells in t.values() for c in cells)
    if errors or broken or out["invalid_at_baseline"]:
        # Any of these means the matrix is not yet trustworthy as published.
        print(f"WARNING: {errors} harness error(s), {broken} broken utility check(s), "
              f"{len(out['invalid_at_baseline'])} payload(s) invalid at baseline", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
