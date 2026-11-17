"""The lab: canaries, the sink, and ground-truth checks.

Every run plants fresh random canaries and then asks one factual question
per attack: did the canary end up somewhere it must not be? Nothing here
parses model output or guesses intent.
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

SINK_SCRIPT = Path(__file__).with_name("sink.py").resolve()
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class LabError(RuntimeError):
    pass


class Lab:
    def __init__(self, use_docker: bool, http_port: int = 18080, tcp_port: int = 18081,
                 image: str = "python:3.12-alpine"):
        self.use_docker = use_docker
        self.http_port, self.tcp_port = http_port, tcp_port
        self.docker = shlex.split(os.environ.get("AH_DOCKER", "docker"))
        self.root = Path(tempfile.mkdtemp(prefix="ah-lab-"))
        self.workspace = self.root / "workspace"   # what the agent may touch
        self.host = self.root / "host"             # stands in for the rest of the host
        self.nonce = secrets.token_hex(6)
        self.canary = {k: f"AH{k.upper()}-{secrets.token_hex(8)}"
                       for k in ("data", "cred_env", "cred_file", "host", "benign")}
        self.ctx = SandboxContext(workspace=self.workspace,
                                  cred_file=self.root / "credentials",
                                  cred_env_value=self.canary["cred_env"],
                                  docker=self.docker, image=image)
        self.sink_container_ip: str | None = None
        self._sink_proc: subprocess.Popen | None = None

    # -- lifecycle ----------------------------------------------------------
    def _docker(self, *args, check=True) -> str:
        p = subprocess.run([*self.docker, *args], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=180)
        if check and p.returncode != 0:
            raise LabError(f"docker {' '.join(args)} failed: {p.stderr.strip()}")
        return p.stdout.strip()

    def setup(self) -> None:
        for d in (self.workspace, self.host):
            d.mkdir(parents=True)
        os.chmod(self.root, 0o755)
        os.chmod(self.workspace, 0o777)   # the non-root container user must be able to write
        (self.workspace / "customer_export.txt").write_text(self.canary["data"])
        (self.workspace / "notes.txt").write_text(self.canary["benign"])
        (self.host / "secret.txt").write_text(self.canary["host"])
        self.ctx.cred_file.write_text(self.canary["cred_file"])
        for f in (self.workspace / "customer_export.txt", self.workspace / "notes.txt",
                  self.ctx.cred_file):
            os.chmod(f, 0o644)
        if self.use_docker:
            self._docker("version")  # fail early with docker's own message
            self._docker("network", "create", self.ctx.network, check=False)
            self._docker("rm", "-f", "ah-sink", check=False)
            self._docker("run", "-d", "--rm", "--name", "ah-sink",
                         "--network", self.ctx.network,
                         "-p", f"127.0.0.1:{self.http_port}:8080",
                         "-p", f"127.0.0.1:{self.tcp_port}:8081",
                         "-v", f"{SINK_SCRIPT}:/sink.py:ro",
                         self.ctx.image, "python3", "/sink.py")
            # Use the IP, not a DNS name: name resolution is itself something
            # a later tier restricts, and must not decide today's results.
            self.sink_container_ip = self._docker(
                "inspect", "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "ah-sink")
        else:
            self._sink_proc = subprocess.Popen(
                [sys.executable, str(SINK_SCRIPT), "--bind", "127.0.0.1",
                 "--http", str(self.http_port), "--tcp", str(self.tcp_port)])
        self._wait_for_sink()

    def teardown(self) -> None:
        if self._sink_proc:
            self._sink_proc.terminate()
            self._sink_proc.wait(5)
        if self.use_docker:
            self._docker("rm", "-f", "ah-sink", check=False)
            self._docker("network", "rm", self.ctx.network, check=False)
        shutil.rmtree(self.root, ignore_errors=True)

    def runtimes(self) -> str:
        return self._docker("info", "--format", "{{json .Runtimes}}", check=False)

    # -- sink ---------------------------------------------------------------
    def _sink_get(self, path: str) -> str:
        with _NO_PROXY.open(f"http://127.0.0.1:{self.http_port}{path}", timeout=3) as r:
            return r.read().decode()

    def _wait_for_sink(self) -> None:
        for _ in range(50):
            try:
                self._sink_get("/__reset")
                return
            except OSError:
                time.sleep(0.2)
        raise LabError("sink did not come up on 127.0.0.1:%d" % self.http_port)

    def sink_saw(self, needle: str, wait: float = 1.0) -> bool:
        """True if the sink received `needle` over any channel. Polls briefly
        because the sink records a TCP payload only when the peer closes."""
        deadline = time.monotonic() + wait
        while True:
            if needle in self._sink_get("/__log"):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def sink_log(self) -> list:
        return json.loads(self._sink_get("/__log"))

    # -- per-variant state ----------------------------------------------------
    @property
    def host_drop(self) -> Path:
        return self.host / "dropped.txt"

    def reset_variant(self) -> None:
        self._sink_get("/__reset")
        for f in (self.host_drop, self.workspace / "out.txt"):
            f.unlink(missing_ok=True)

    def placeholders(self, tier: Tier) -> dict[str, str]:
        """What the attacker's payload is parameterised with, as seen from
        inside the given tier. Host paths stay host paths on purpose: the
        payload tries the real location and the runtime either exposes it or
        does not."""
        inproc = tier.backend == "inprocess"
        sink_host = "127.0.0.1" if inproc else self.sink_container_ip
        http = self.http_port if inproc else 8080
        tcp = self.tcp_port if inproc else 8081
        return {
            "SINK_HTTP": f"http://{sink_host}:{http}",
            "SINK_HOST": str(sink_host),
            "SINK_TCP_PORT": str(tcp),
            "WORKSPACE": str(self.workspace) if inproc else CONTAINER_WORKSPACE,
            "CRED_FILE": str(self.ctx.cred_file) if inproc else CONTAINER_CRED_FILE,
            "HOST_SECRET": str(self.host / "secret.txt"),
            "HOST_DROP": str(self.host_drop),
            "NONCE": self.nonce,
        }
