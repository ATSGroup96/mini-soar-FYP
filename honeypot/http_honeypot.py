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
MAX_BODY = 4096          # bytes of a request body that are read and kept
READ_TIMEOUT = 10        # seconds a slow client may take

_LOGIN_PAGE = (
    b"<!doctype html><html><head><title>Router Admin</title></head>"
    b"<body style='font-family:sans-serif'><h2>Administration Login</h2>"
    b"<form method='POST' action='/login'>"
    b"User: <input name='username'><br>Pass: <input name='password' type='password'><br>"
    b"<button>Sign in</button></form></body></html>"
)
_DENIED = b"<html><body>Invalid credentials</body></html>"


class _Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"  # look ordinary
    sys_version = ""
    timeout = READ_TIMEOUT

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
               path_or_cmd=f"{self.command} {self.path}"[:512])

    def _read_body(self) -> str:
        """At most MAX_BODY bytes; a wrong or huge Content-Length is harmless."""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return ""
        if length <= 0:
            return ""
        return self.rfile.read(min(length, MAX_BODY)).decode("utf-8", "replace")

    def _reply(self, status: int, body: bytes, challenge: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        if challenge:
            self.send_header("WWW-Authenticate", 'Basic realm="Admin"')
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._record()
        self._reply(200, _LOGIN_PAGE, challenge=True)

    do_HEAD = do_GET

    def do_POST(self):
        form = parse_qs(self._read_body())
        creds = (form.get("username", [None])[0], form.get("password", [None])[0])
        self._record(creds if any(creds) else None)
        self._reply(401, _DENIED)

    def _other(self):
        self._read_body()
        self._record()
        self._reply(405, _DENIED)

    do_PUT = do_DELETE = do_OPTIONS = do_PATCH = _other

    def log_message(self, *a):
        pass  # silence default stderr logging; we record our own


def make_server(port: int = PORT, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    return httpd


def serve(port: int = PORT) -> None:
    httpd = make_server(port)
    print(f"[honeypot] fake HTTP listening on :{port}")
    httpd.serve_forever()
