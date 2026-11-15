"""
Low-interaction fake HTTP decoy.

Serves a believable but inert "admin login" page, records every request path,
method, and any submitted/Basic-Auth credentials, and always returns a generic
response. No server-side logic runs on the input — it is only recorded.
"""
from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .events import record

PORT = 8081

_LOGIN_PAGE = (
    b"<!doctype html><html><head><title>Router Admin</title></head>"
    b"<body style='font-family:sans-serif'><h2>Administration Login</h2>"
    b"<form method='POST' action='/login'>"
    b"User: <input name='username'><br>Pass: <input name='password' type='password'><br>"
    b"<button>Sign in</button></form></body></html>"
)


class _Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"  # look ordinary
    sys_version = ""

    def _client_ip(self):
        return self.client_address[0]

    def _record(self, creds=None):
        auth = self.headers.get("Authorization", "")
        user = pw = None
        if creds:
            user, pw = creds
        elif auth.startswith("Basic "):
            try:
                dec = base64.b64decode(auth[6:]).decode("utf-8", "replace")
                user, _, pw = dec.partition(":")
            except Exception:
                pass
        record("http", self._client_ip(), self.client_address[1],
               username=user, password=pw,
               path_or_cmd=f"{self.command} {self.path}")

    def do_GET(self):
        self._record()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("WWW-Authenticate", 'Basic realm="Admin"')
        self.end_headers()
        self.wfile.write(_LOGIN_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = parse_qs(body)
        creds = (form.get("username", [None])[0], form.get("password", [None])[0])
        self._record(creds)
        self.send_response(401)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Invalid credentials</body></html>")

    def log_message(self, *a):
        pass  # silence default stderr logging; we record our own


def serve(port: int = PORT) -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    print(f"[honeypot] fake HTTP listening on :{port}")
    httpd.serve_forever()
