"""Egress proxy: the only way out of the internal network.

A minimal HTTP forward proxy with a destination allowlist (host:port).
Anything not on the list gets a 403 and is never connected to. CONNECT is
refused outright, so the proxy cannot be used as an opaque tunnel.

Sandboxed tools sit on a Docker `--internal` network with no route out; this
proxy is the one container attached to both that network and the outside.
A payload that ignores the proxy has nowhere to send packets; a payload that
uses it is limited to allowlisted destinations. Standalone, stdlib only.
"""
import argparse
import http.client
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ALLOW = set()


class Proxy(BaseHTTPRequestHandler):
    def _deny(self, why):
        print(f"DENY {self.command} {self.path} ({why})", flush=True)
        body = f"blocked by egress policy: {why}".encode()
        self.send_response(403)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self):
        u = urlsplit(self.path)
        if u.scheme != "http" or not u.hostname:
            return self._deny("only absolute http:// URLs are proxied")
        dest = f"{u.hostname}:{u.port or 80}"
        if dest not in ALLOW:
            return self._deny(f"{dest} is not allowlisted")
        n = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(n) if n else None
        try:
            conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=5)
            conn.request(self.command, (u.path or "/") + (f"?{u.query}" if u.query else ""),
                         body=payload)
            r = conn.getresponse()
            data = r.read()
        except OSError as e:
            self.send_error(502, f"upstream error: {e}")
            return
        print(f"ALLOW {self.command} {self.path}", flush=True)
        self.send_response(r.status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = _forward

    def do_CONNECT(self):
        self._deny("CONNECT tunnels are not allowed")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3128)
    ap.add_argument("--allow", action="append", default=[], help="host:port, repeatable")
    a = ap.parse_args()
    ALLOW.update(a.allow)
    print(f"egress proxy on {a.bind}:{a.port}, allow={sorted(ALLOW)}", file=sys.stderr, flush=True)
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer((a.bind, a.port), Proxy).serve_forever()
