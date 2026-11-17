"""Canary sink: the attacker-controlled endpoint in the lab.

Records every HTTP request and every raw TCP payload it receives. The
harness reads the log back to decide, from ground truth, whether a secret
actually left the sandbox. Standalone and stdlib-only so it can run as a
host process or inside a container.

Control endpoints (HTTP):  GET /__log   -> JSON list of everything received
                           GET /__reset -> clear the log
"""
import argparse
import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = []
LOCK = threading.Lock()


def record(entry):
    with LOCK:
        LOG.append(entry)


class Http(BaseHTTPRequestHandler):
    def _reply(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/__log":
            with LOCK:
                return self._reply(json.dumps(LOG))
        if self.path == "/__reset":
            with LOCK:
                LOG.clear()
            return self._reply("reset")
        record({"proto": "http", "method": "GET", "path": self.path, "body": ""})
        self._reply("ok")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(n, 65536)).decode("utf-8", "replace")
        record({"proto": "http", "method": "POST", "path": self.path, "body": body})
        self._reply("ok")

    def log_message(self, *_):
        pass


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        chunks = []
        try:
            while sum(map(len, chunks)) < 65536:
                b = self.request.recv(4096)
                if not b:
                    break
                chunks.append(b)
        except OSError:
            pass
        record({"proto": "tcp", "body": b"".join(chunks).decode("utf-8", "replace")})


class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--http", type=int, default=8080)
    ap.add_argument("--tcp", type=int, default=8081)
    a = ap.parse_args()
    tcp = TcpServer((a.bind, a.tcp), Tcp)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer((a.bind, a.http), Http).serve_forever()
