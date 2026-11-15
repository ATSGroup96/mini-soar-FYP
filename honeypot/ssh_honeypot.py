"""
Low-interaction fake SSH decoy.

Speaks just enough of the SSH protocol (via paramiko's server interface) to make
a scanner/bot believe it reached a real sshd, records the username + password
tried, and ALWAYS denies authentication. It never opens a shell, never runs a
command, never grants access. Purely a tripwire.
"""
from __future__ import annotations

import socket
import threading

from .events import record

PORT = 2222
BANNER = "SSH-2.0-OpenSSH_7.4"  # looks like a common real server


def _make_server_key():
    import paramiko
    return paramiko.RSAKey.generate(2048)


class _HoneyServer:
    """paramiko ServerInterface that logs creds and refuses everything."""
    def __init__(self, src_ip, src_port):
        import paramiko
        self._paramiko = paramiko
        self.src_ip = src_ip
        self.src_port = src_port

    def check_auth_password(self, username, password):
        record("ssh", self.src_ip, self.src_port, username=username, password=password)
        return self._paramiko.AUTH_FAILED  # never accept

    def check_auth_publickey(self, username, key):
        record("ssh", self.src_ip, self.src_port, username=username, password="<pubkey>")
        return self._paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        return self._paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def _handle(client_sock, addr, host_key):
    import paramiko
    src_ip, src_port = addr
    try:
        t = paramiko.Transport(client_sock)
        t.local_version = BANNER
        t.add_server_key(host_key)
        server = _HoneyServer(src_ip, src_port)
        try:
            t.start_server(server=server)
        except Exception:
            pass
        # give the client a moment to attempt auth, then drop
        chan = t.accept(8)
        if chan is not None:
            chan.close()
        t.close()
    except Exception:
        try:
            client_sock.close()
        except Exception:
            pass


def serve(port: int = PORT) -> None:
    host_key = _make_server_key()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(100)
    print(f"[honeypot] fake SSH listening on :{port}")
    while True:
        try:
            client, addr = srv.accept()
            threading.Thread(target=_handle, args=(client, addr, host_key),
                             daemon=True).start()
        except Exception:
            continue
