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
AUTH_WAIT_SECONDS = 20          # how long one client may keep trying passwords
MAX_CLIENTS = 50                # connections handled at the same time


def _make_server_key():
    import paramiko
    return paramiko.RSAKey.generate(2048)


def _new_server(src_ip: str, src_port: int):
    """
    The paramiko "server side" object for one connection.

    It must inherit from paramiko.ServerInterface: paramiko calls several
    methods on it during the login (get_banner, check_auth_none, ...) and a
    plain class without them makes the connection crash before the password
    is ever seen. Built here (not at import time) so the module still loads
    when paramiko is not installed.
    """
    import paramiko

    class HoneyServer(paramiko.ServerInterface):
        """Logs every credential and refuses everything."""

        def check_auth_password(self, username, password):
            record("ssh", src_ip, src_port, username=username, password=password)
            return paramiko.AUTH_FAILED  # never accept

        def check_auth_publickey(self, username, key):
            record("ssh", src_ip, src_port, username=username, password="<pubkey>")
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    return HoneyServer()


def _handle(client_sock, addr, host_key) -> None:
    import paramiko
    src_ip, src_port = addr[0], addr[1]
    transport = None
    try:
        client_sock.settimeout(AUTH_WAIT_SECONDS)
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        transport.start_server(server=_new_server(src_ip, src_port))
        # nothing is ever accepted, so no channel will open: this only gives
        # the client time to try its passwords before we hang up
        chan = transport.accept(AUTH_WAIT_SECONDS)
        if chan is not None:
            chan.close()
    except Exception:
        pass  # scanners send garbage / hang up mid-handshake all the time
    finally:
        try:
            if transport is not None:
                transport.close()
            client_sock.close()
        except Exception:
            pass


def listen(port: int = PORT, host: str = "0.0.0.0") -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    return srv


def accept_loop(srv: socket.socket, host_key) -> None:
    """Serve until the listening socket is closed."""
    slots = threading.BoundedSemaphore(MAX_CLIENTS)

    def run(client, addr):
        try:
            _handle(client, addr, host_key)
        finally:
            slots.release()

    while True:
        try:
            client, addr = srv.accept()
        except OSError:
            return  # socket closed -> stop
        if not slots.acquire(blocking=False):
            client.close()  # too many at once: drop instead of piling up threads
            continue
        threading.Thread(target=run, args=(client, addr), daemon=True).start()


def serve(port: int = PORT) -> None:
    host_key = _make_server_key()
    srv = listen(port)
    print(f"[honeypot] fake SSH listening on :{port}")
    accept_loop(srv, host_key)
