"""The lab: canaries, the services around the sandbox, and ground-truth checks.

Every run plants fresh random canaries and then asks one factual question
per attack: did the canary end up somewhere it must not be? Nothing here
parses model output or guesses intent.

Services (each a small stdlib script, run as host processes for an
in-process-only run or as containers otherwise):
  * sink  -- attacker-controlled endpoint (HTTP, raw TCP, UDP)
  * api   -- a legitimate external service the HTTP tool is allowed to call
  * proxy -- allowlisting egress proxy, the only bridge between the internal
             sandbox network and the outside (started only if a tier needs it)
"""
from __future__ import annotations

import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from .executor import CONTAINER_CRED_FILE, CONTAINER_WORKSPACE, SandboxContext
from .policy import Tier

_HERE = Path(__file__).resolve().parent
SINK_SCRIPT, PROXY_SCRIPT = _HERE / "sink.py", _HERE / "proxy.py"
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_CONTAINERS = ("ah-sink", "ah-api", "ah-proxy")


class LabError(RuntimeError):
    pass


class Lab:
    # Host-side ports. Containers always listen on 8080/8081/8053 internally.
    SINK_HTTP, SINK_TCP, SINK_UDP, API_HTTP = 18080, 18081, 18053, 18082

    def __init__(self, use_docker: bool, need_proxy: bool = False,
                 image: str = "python:3.12-alpine"):
        self.use_docker, self.need_proxy = use_docker, need_proxy
        self.docker = shlex.split(os.environ.get("AH_DOCKER", "docker"))
        self.root = Path(tempfile.mkdtemp(prefix="ah-lab-"))
        self.workspace = self.root / "workspace"   # what the agent may touch
        self.host = self.root / "host"             # stands in for the rest of the host
        self.nonce = secrets.token_hex(6)
        self.canary = {k: f"AH{k.upper()}-{secrets.token_hex(8)}" for k in
                       ("data", "cred_env", "cred_file", "host", "benign", "api_token")}
        self.ctx = SandboxContext(workspace=self.workspace,
                                  cred_file=self.root / "credentials",
                                  cred_env_value=self.canary["cred_env"],
                                  docker=self.docker, image=image)
        self.sink_ip: str | None = None
        self.api_ip: str | None = None
        self._procs: list[subprocess.Popen] = []

    # -- lifecycle ----------------------------------------------------------
    def _docker(self, *args, check=True) -> str:
        p = subprocess.run([*self.docker, *args], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=180)
        if check and p.returncode != 0:
            raise LabError(f"docker {' '.join(args)} failed: {p.stderr.strip()}")
        return p.stdout.strip()

    def _ip(self, container: str, network: str) -> str:
        # Use IPs, not DNS names: name resolution is itself something a tier
        # may restrict, and must not decide the results.
        ip = self._docker("inspect", "-f",
                          '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % network,
                          container)
        if not ip:
            raise LabError(f"{container} has no address on {network}")
        return ip

    def _service(self, name: str, script: Path, *args: str, publish: tuple = ()) -> None:
        cmd = ["run", "-d", "--rm", "--name", name, "--network", self.ctx.network]
        for p in publish:
            cmd += ["-p", p]
        self._docker(*cmd, "-v", f"{script}:/svc.py:ro", self.ctx.image,
                     "python3", "/svc.py", *args)

    def _plant(self) -> None:
        for d in (self.workspace, self.host):
            d.mkdir(parents=True)
        os.chmod(self.root, 0o755)
        os.chmod(self.workspace, 0o777)   # the non-root container user must be able to write
        files = {self.workspace / "customer_export.txt": self.canary["data"],
                 self.workspace / "notes.txt": self.canary["benign"],
                 self.ctx.cred_file: self.canary["cred_file"]}
        for f, content in files.items():
            f.write_text(content)
            os.chmod(f, 0o644)
        (self.host / "secret.txt").write_text(self.canary["host"])

    def setup(self) -> None:
        self._plant()
        token = self.canary["api_token"]
        if not self.use_docker:
            py = [sys.executable, str(SINK_SCRIPT), "--bind", "127.0.0.1"]
            self._procs = [
                subprocess.Popen(py + ["--http", str(self.SINK_HTTP), "--tcp", str(self.SINK_TCP),
                                       "--udp", str(self.SINK_UDP)]),
                subprocess.Popen(py + ["--http", str(self.API_HTTP), "--tcp", "0", "--udp", "0",
                                       "--reply", token]),
            ]
        else:
            self._docker("version")  # fail early with docker's own message
            self._docker("rm", "-f", *_CONTAINERS, check=False)
            self._docker("network", "create", self.ctx.network, check=False)
            self._service("ah-sink", SINK_SCRIPT, publish=(
                f"127.0.0.1:{self.SINK_HTTP}:8080", f"127.0.0.1:{self.SINK_TCP}:8081",
                f"127.0.0.1:{self.SINK_UDP}:8053/udp"))
            self._service("ah-api", SINK_SCRIPT, "--tcp", "0", "--udp", "0", "--reply", token,
                          publish=(f"127.0.0.1:{self.API_HTTP}:8080",))
            self.sink_ip = self._ip("ah-sink", self.ctx.network)
            self.api_ip = self._ip("ah-api", self.ctx.network)
            if self.need_proxy:
                internal = self.ctx.internal_network
                self._docker("network", "create", "--internal", internal, check=False)
                self._service("ah-proxy", PROXY_SCRIPT, "--allow", f"{self.api_ip}:8080")
                self._docker("network", "connect", internal, "ah-proxy")
                self.ctx.egress_proxy = f"http://{self._ip('ah-proxy', internal)}:3128"
        for port in (self.SINK_HTTP, self.API_HTTP):
            self._wait_for(port)

    def teardown(self) -> None:
        for p in self._procs:
            p.terminate()
            p.wait(5)
        if self.use_docker:
            self._docker("rm", "-f", *_CONTAINERS, check=False)
            self._docker("network", "rm", self.ctx.network, self.ctx.internal_network, check=False)
        shutil.rmtree(self.root, ignore_errors=True)

    def runtimes(self) -> str:
        return self._docker("info", "--format", "{{json .Runtimes}}", check=False)

    # -- observation ----------------------------------------------------------
    def _get(self, port: int, path: str) -> str:
        with _NO_PROXY.open(f"http://127.0.0.1:{port}{path}", timeout=3) as r:
            return r.read().decode()

    def _wait_for(self, port: int) -> None:
        for _ in range(50):
            try:
                self._get(port, "/__reset")
                return
            except OSError:
                time.sleep(0.2)
        raise LabError("lab service did not come up on 127.0.0.1:%d" % port)

    def _saw(self, port: int, needle: str, wait: float) -> bool:
        """Poll briefly: the sink records a TCP payload only when the peer closes."""
        deadline = time.monotonic() + wait
        while True:
            if needle in self._get(port, "/__log"):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def sink_saw(self, needle: str, wait: float = 1.0) -> bool:
        return self._saw(self.SINK_HTTP, needle, wait)

    def api_saw(self, needle: str, wait: float = 1.0) -> bool:
        return self._saw(self.API_HTTP, needle, wait)

    def sink_log(self) -> list:
        return json.loads(self._get(self.SINK_HTTP, "/__log"))

    # -- per-variant state ----------------------------------------------------
    @property
    def host_drop(self) -> Path:
        return self.host / "dropped.txt"

    def reset_variant(self) -> None:
        for port in (self.SINK_HTTP, self.API_HTTP):
            self._get(port, "/__reset")
        for f in (self.host_drop, self.workspace / "out.txt"):
            f.unlink(missing_ok=True)

    def placeholders(self, tier: Tier) -> dict[str, str]:
        """What the attacker's payload is parameterised with, as seen from
        inside the given tier. Host paths stay host paths on purpose: the
        payload tries the real location and the runtime either exposes it or
        does not."""
        inproc = tier.backend == "inprocess"
        sink = "127.0.0.1" if inproc else self.sink_ip
        api = f"127.0.0.1:{self.API_HTTP}" if inproc else f"{self.api_ip}:8080"
        return {
            "SINK_HTTP": f"http://{sink}:{self.SINK_HTTP if inproc else 8080}",
            "SINK_HOST": str(sink),
            "SINK_TCP_PORT": str(self.SINK_TCP if inproc else 8081),
            "SINK_UDP_PORT": str(self.SINK_UDP if inproc else 8053),
            "API_HTTP": f"http://{api}",
            "WORKSPACE": str(self.workspace) if inproc else CONTAINER_WORKSPACE,
            "CRED_FILE": str(self.ctx.cred_file) if inproc else CONTAINER_CRED_FILE,
            "HOST_SECRET": str(self.host / "secret.txt"),
            "HOST_DROP": str(self.host_drop),
            "NONCE": self.nonce,
        }
