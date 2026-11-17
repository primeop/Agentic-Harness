"""Tests that need no Docker daemon.

    python -m unittest tests.test_isolation -v

Covers the policy-to-flags mapping, policy loading, and a full in-process
(C0) run against a real local sink. Docker tiers are exercised by running
the matrix itself on a machine with Docker.
"""
import os
import unittest
from pathlib import Path

from agentic_harness.isolation.executor import SandboxContext, build_docker_argv
from agentic_harness.isolation.matrix import run_matrix, to_markdown
from agentic_harness.isolation.policy import ToolPolicy, _policy, load_tiers

CTX = SandboxContext(workspace=Path("/lab/ws"), cred_file=Path("/lab/cred"),
                     cred_env_value="SECRET", tools_dir=Path("/repo/tools"))


def argv_for(tier_id, tool="shell"):
    tier = load_tiers()[tier_id]
    return build_docker_argv(tier, tier.policy_for(tool), CTX, "n", tool, {"cmd": "id"})


class PolicyToFlags(unittest.TestCase):
    def test_default_docker_is_unhardened(self):
        a = argv_for("C1")
        self.assertEqual(a[a.index("--runtime") + 1], "runc")
        for flag in ("--user", "--cap-drop", "--read-only", "--pids-limit"):
            self.assertNotIn(flag, a)
        self.assertIn("AH_API_KEY=SECRET", a)

    def test_hardened_flags(self):
        a = argv_for("C2")
        self.assertEqual(a[a.index("--user") + 1], "65534:65534")
        self.assertEqual(a[a.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges", a)
        self.assertIn("--read-only", a)
        self.assertIn("/lab/ws:/workspace:rw", a)
        self.assertIn("/repo/tools:/tools:ro", a)

    def test_gvisor_differs_from_c2_only_in_runtime(self):
        c2, g = argv_for("C2"), argv_for("C2-gvisor")
        self.assertEqual(g[g.index("--runtime") + 1], "runsc")
        g[g.index("--runtime") + 1] = "runc"
        self.assertEqual(c2, g)

    def test_network_none_and_no_ambient_creds(self):
        tier = load_tiers()["C2"]
        p = _policy(tier.default, {"network": "none", "ambient_env_creds": False,
                                   "ambient_cred_file": False})
        a = build_docker_argv(tier, p, CTX, "n", "shell", {})
        self.assertEqual(a[a.index("--network") + 1], "none")
        self.assertFalse(any("SECRET" in x or "/lab/cred" in x for x in a))

    def test_policy_typos_fail_loudly(self):
        with self.assertRaises(ValueError):
            _policy(ToolPolicy(), {"cap_drop_al": True})
        with self.assertRaises(ValueError):
            ToolPolicy(network="host")


class InProcessBaseline(unittest.TestCase):
    def test_every_attack_fires_with_no_isolation(self):
        os.environ.setdefault("NO_PROXY", "127.0.0.1")
        os.environ.setdefault("no_proxy", "127.0.0.1")
        out = run_matrix(["C0"], log=lambda *_: None)
        self.assertEqual(out["invalid_at_baseline"], [])
        for row in out["rows"]:
            want = "works" if row["benign"] else "not_contained"
            for cell in out["results"]["C0"][row["id"]]:
                self.assertEqual(cell["outcome"], want, cell)
        self.assertIn("| **R1**", to_markdown(out))
        self.assertNotIn("AH_API_KEY", os.environ)  # the ambient key must not leak into the harness env


if __name__ == "__main__":
    unittest.main()
