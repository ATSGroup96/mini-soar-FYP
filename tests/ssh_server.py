"""
A tiny real SSH server for tests (paramiko, loopback only).

It lets the engine's real SSH code run end to end - key login, password login,
exec with exit codes - without any VM. Commands are not executed: a handler
function decides the output and exit code, and every command is recorded.
"""
from __future__ import annotations

import socket
import threading
import time

import paramiko


class FakeTarget:
    def __init__(self, passwords: dict | None = None, pubkey: paramiko.PKey | None = None,
                 pubkey_user: str = "soar", handler=None):
        self.passwords = passwords or {}
        self.pubkey, self.pubkey_user = pubkey, pubkey_user
        self.handler = handler or (lambda cmd: (0, ""))
        self.commands: list[str] = []
        self.logins: list[tuple[str, str]] = []
        self._host_key = paramiko.RSAKey.generate(2048)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(20)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def close(self):
        self._stop = True
        self._sock.close()

    def _loop(self):
        while not self._stop:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        target = self

        class Server(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return "password,publickey"

            def check_auth_password(self, username, password):
                target.logins.append((username, password))
                ok = target.passwords.get(username) == password
                return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

            def check_auth_publickey(self, username, key):
                ok = (target.pubkey is not None and username == target.pubkey_user
                      and key.get_base64() == target.pubkey.get_base64())
                return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == "session" \
                    else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                cmd = command.decode("utf-8", "replace")
                target.commands.append(cmd)

                def run():
                    # let paramiko send the "exec accepted" reply first
                    time.sleep(0.05)
                    try:
                        rc, out = target.handler(cmd)
                        if out:
                            channel.sendall(out.encode())
                        channel.send_exit_status(rc)
                    finally:
                        channel.close()
                threading.Thread(target=run, daemon=True).start()
                return True

        try:
            t = paramiko.Transport(client)
            t.add_server_key(self._host_key)
            t.start_server(server=Server())
            while t.is_active() and not self._stop:
                chan = t.accept(0.5)
                if chan is None and not t.is_active():
                    break
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass
