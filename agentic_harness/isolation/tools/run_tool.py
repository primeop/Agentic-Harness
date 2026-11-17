"""Real tool implementations for the containment evals.

Unlike the mock tools in `mock_agent.py` (which only record that they were
called), these tools do real things: read files, run shell commands, make
HTTP requests. They are deliberately naive -- no path checks, no command
filtering -- because the point of the isolation layer is to measure what the
*runtime* contains when the tool itself does not defend anything.

This file is standalone (stdlib only, no package imports) so the same code
runs in two places:
  * imported in-process by InProcessExecutor (tier C0), and
  * executed as `python3 /tools/run_tool.py <tool> <json-args>` inside a
    container by DockerExecutor (every other tier).

Output contract: exactly one JSON object on the last line of stdout:
    {"ok": bool, "output": str, "error": str}
"""
import json
import os
import subprocess
import sys
import urllib.request

MAX_OUT = 65536


def read_file(path):
    with open(path, "r", errors="replace") as f:
        return {"ok": True, "output": f.read(MAX_OUT), "error": ""}


def shell(cmd, timeout=20):
    p = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True,
                       text=True, errors="replace", timeout=timeout)
    return {"ok": p.returncode == 0, "output": p.stdout[:MAX_OUT],
            "error": p.stderr[:MAX_OUT]}


def http_fetch(url, timeout=5):
    # The tool only uses a proxy if the runtime policy hands it one. A
    # payload that ignores the proxy must be stopped by the network, not here.
    proxy = os.environ.get("AH_EGRESS_PROXY")
    handler = urllib.request.ProxyHandler({"http": proxy} if proxy else {})
    opener = urllib.request.build_opener(handler)
    with opener.open(url, timeout=timeout) as r:
        body = r.read(MAX_OUT).decode("utf-8", "replace")
    return {"ok": True, "output": body, "error": ""}


TOOLS = {"read_file": read_file, "shell": shell, "http_fetch": http_fetch}


def dispatch(tool, args):
    """Run one tool. Tool-level failures are data, not exceptions."""
    fn = TOOLS.get(tool)
    if fn is None:
        return {"ok": False, "output": "", "error": "unknown tool: %s" % tool}
    try:
        return fn(**args)
    except Exception as e:  # noqa: BLE001 - every failure is reported as data
        return {"ok": False, "output": "", "error": "%s: %s" % (type(e).__name__, e)}


if __name__ == "__main__":
    print(json.dumps(dispatch(sys.argv[1], json.loads(sys.argv[2]))))
