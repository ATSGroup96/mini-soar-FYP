"""The engine's real SSH code against a real (loopback) SSH server:
default-password check, command execution, fix verification, readiness check."""
import pytest

paramiko = pytest.importorskip("paramiko")

from scanner import default_creds                      # noqa: E402
from soar import enroll, remediation, verify            # noqa: E402
from soar.remediation import CommandFailed, RemediationError  # noqa: E402
from tests.ssh_server import FakeTarget                 # noqa: E402

LOCAL = "127.0.0.1"


@pytest.fixture
def engine_key(tmp_path, set_env):
    key = paramiko.RSAKey.generate(2048)
    path = tmp_path / "lab_id_rsa"
    key.write_private_key_file(str(path))
    set_env(SSH_PRIVATE_KEY_PATH=str(path), SSH_USERNAME="soar")
    return key


@pytest.fixture
def target(engine_key, monkeypatch):
    made = []

    def make(handler=None, **kw):
        t = FakeTarget(pubkey=engine_key, handler=handler, **kw)
        made.append(t)
        real_connect = paramiko.SSHClient.connect

        def connect(self, hostname, *a, **k):         # the engine always uses port 22
            k.setdefault("port", t.port)
            return real_connect(self, hostname, *a, **k)
        monkeypatch.setattr(paramiko.SSHClient, "connect", connect)
        return t

    yield make
    for t in made:
        t.close()


# ---- default-credential check over real SSH ----------------------------------
def test_ssh_default_password_is_found(engine_key):
    t = FakeTarget(passwords={"msfadmin": "msfadmin"})
    try:
        f = default_creds._check_ssh(LOCAL, t.port)
    finally:
        t.close()
    assert f and (f.service, f.username, f.password) == ("ssh", "msfadmin", "msfadmin")


def test_ssh_strong_password_is_not_flagged(engine_key):
    t = FakeTarget(passwords={"admin": "Tr0ub4dor&3-very-long"})
    try:
        assert default_creds._check_ssh(LOCAL, t.port) is None
        tried = {u for u, _ in t.logins}
    finally:
        t.close()
    assert tried == {u for u, _ in default_creds.DEFAULT_CREDS}        # one try each, no more
    assert len(t.logins) == len(default_creds.DEFAULT_CREDS)


def test_ssh_check_on_dead_port_is_quiet():
    import socket
    s = socket.socket(); s.bind((LOCAL, 0)); port = s.getsockname()[1]; s.close()
    assert default_creds._check_ssh(LOCAL, port) is None


# ---- running commands --------------------------------------------------------
def test_run_remote_returns_output_and_exit_code(target):
    t = target(handler=lambda cmd: (0, "uid=1001(soar)\n") if cmd == "id" else (0, ""))
    assert remediation.run_remote(LOCAL, ["id"]) == [("id", 0, "uid=1001(soar)")]
    assert t.commands == ["id"]


def test_run_remote_raises_when_a_command_fails_and_stops(target):
    t = target(handler=lambda cmd: (3, "service telnet not found\n") if "first" in cmd else (0, ""))
    with pytest.raises(CommandFailed, match="rc=3"):
        remediation.run_remote(LOCAL, ["first", "second"])
    assert t.commands == ["first"]                     # the second command never ran


def test_run_remote_without_check_keeps_going(target):
    target(handler=lambda cmd: (1, "no"))
    out = remediation.run_remote(LOCAL, ["a", "b"], check=False)
    assert [rc for _, rc, _ in out] == [1, 1]


def test_wrong_key_cannot_log_in(target, tmp_path, set_env):
    target()
    other = tmp_path / "other_key"
    paramiko.RSAKey.generate(2048).write_private_key_file(str(other))
    set_env(SSH_PRIVATE_KEY_PATH=str(other))
    with pytest.raises(RemediationError, match="SSH to 127.0.0.1 failed"):
        remediation.run_remote(LOCAL, ["id"])


def test_unreadable_key_file_is_reported(tmp_path, set_env):
    bad = tmp_path / "bad_key"
    bad.write_text("this is not a key")
    set_env(SSH_PRIVATE_KEY_PATH=str(bad))
    with pytest.raises(RemediationError, match="Cannot load SSH key"):
        remediation._connect(LOCAL)


def test_apply_and_rollback_over_real_ssh(target):
    t = target()
    plan = remediation.build_plan("block_port", LOCAL, {"port": 23})
    out = remediation.apply(plan, approved=True, totp_verified=True)
    assert "[rc=0]" in out and "iptables -I INPUT -p tcp --dport 23 -j DROP" in t.commands[0]
    remediation.rollback(plan)
    assert t.commands[1].endswith("iptables -D INPUT -p tcp --dport 23 -j DROP")


# ---- verification of a fix ---------------------------------------------------
@pytest.mark.parametrize("status_line,locked", [
    ("msfadmin L 05/20/2012 0 99999 7 -1", True),
    ("msfadmin LK 2012-05-20 0 99999 7 -1 (Password locked.)", True),
    ("msfadmin P 05/20/2012 0 99999 7 -1", False),
    ("passwd: user 'msfadmin' does not exist", False),
])
def test_verify_account_lock_reads_passwd_status(target, status_line, locked, audit_actions):
    t = target(handler=lambda cmd: (0, status_line + "\n"))
    assert verify.verify_fix(LOCAL, {"username": "msfadmin"}, "disable_account") is locked
    assert "passwd -S msfadmin" in t.commands[0]
    assert "remediation.verify" in audit_actions()


def test_verify_port_closed_and_open():
    import socket
    srv = socket.socket(); srv.bind((LOCAL, 0)); srv.listen(1)
    port = srv.getsockname()[1]
    assert verify.verify_fix(LOCAL, {"port": port}, "block_port") is False      # still open
    srv.close()
    assert verify.verify_fix(LOCAL, {"port": port}, "block_port") is True       # closed now


def test_verify_stop_service_uses_known_port():
    import socket
    s = socket.socket(); s.bind((LOCAL, 0)); free = s.getsockname()[1]; s.close()
    assert verify.verify_fix(LOCAL, {"service": "telnet", "port": free}, "stop_service") is True
    assert verify.SERVICE_PORTS["telnet"] == 23 and verify.SERVICE_PORTS["tlntsvr"] == 23


def test_verify_stop_service_without_port_asks_the_host(target):
    target(handler=lambda cmd: (0, "STOPPED\n"))
    assert verify.verify_fix(LOCAL, {"service": "customd"}, "stop_service") is True
    target(handler=lambda cmd: (0, "RUNNING\n"))
    assert verify.verify_fix(LOCAL, {"service": "customd"}, "stop_service") is False


def test_verify_without_anything_to_check_is_not_fixed():
    assert verify.verify_fix(LOCAL, {}, "block_port") is False


def test_verify_is_not_fixed_when_host_unreachable(set_env):
    set_env(SSH_PRIVATE_KEY_PATH="/nope", SSH_USERNAME="soar")
    assert verify.verify_fix(LOCAL, {"username": "msfadmin"}, "disable_account") is False


# ---- readiness check ("Test" button) -----------------------------------------
def test_check_target_ready(target):
    def handler(cmd):
        if " -l" in cmd:
            return 0, "User soar may run: (ALL) NOPASSWD: /sbin/iptables\n"
        return 0, ""
    target(handler=handler)
    r = enroll.check_target(LOCAL)
    assert r["ready"] is True and r["hint"] == ""
    assert [c["ok"] for c in r["checks"]] == [True, True, True, True]


def test_check_target_not_ready_without_sudo(target):
    target(handler=lambda cmd: (1, "sudo: a password is required\n"))
    r = enroll.check_target(LOCAL)
    assert r["ready"] is False and "enroll" in r["hint"]
    assert r["checks"][0]["ok"] is True and r["checks"][1]["ok"] is False


def test_check_target_reports_login_failure(set_env, tmp_path):
    key = tmp_path / "k"
    paramiko.RSAKey.generate(2048).write_private_key_file(str(key))
    set_env(SSH_PRIVATE_KEY_PATH=str(key), SSH_USERNAME="soar")
    import socket
    s = socket.socket(); s.bind((LOCAL, 0)); s.close()
    r = enroll.check_target(LOCAL)                      # nothing listens on port 22 here
    assert r["ready"] is False and r["checks"][0]["ok"] is False


def test_enroll_settings_rules(set_env, tmp_path):
    set_env(SSH_USERNAME="root", SSH_PRIVATE_KEY_PATH=str(tmp_path / "k"))
    with pytest.raises(enroll.EnrollError, match="dedicated user"):
        enroll._settings_ok()
    set_env(SSH_USERNAME="", SSH_PRIVATE_KEY_PATH="")
    with pytest.raises(enroll.EnrollError, match="must be set"):
        enroll._settings_ok()


def test_public_key_line_is_derived_from_private_key(engine_key):
    line = enroll.public_key_line()
    assert line == f"ssh-rsa {engine_key.get_base64()} mini-soar-engine"


def test_enroll_refuses_out_of_scope_and_own_account(engine_key):
    from common.allowlist import ScopeError
    with pytest.raises(ScopeError):
        enroll.enroll("8.8.8.8", "msfadmin", "pw")
    with pytest.raises(enroll.EnrollError, match="existing admin"):
        enroll.enroll(LOCAL, "soar", "pw")


def test_full_enroll_flow_over_ssh(target, audit_actions):
    """Admin password login -> user, key, sudo rules, lock -> key login + sudo check."""
    def handler(cmd):
        if "includedir" in cmd:
            return 1, ""                                   # old sudo (Metasploitable)
        if "test -x" in cmd:
            ok = any(p in cmd for p in ("/sbin/iptables", "/usr/bin/passwd", "/bin/sed"))
            return (0 if ok else 1), ""
        if " -l" in cmd and "sudo" in cmd and "sh -c" not in cmd:
            return 0, "(ALL) NOPASSWD: /sbin/iptables\n"
        return 0, ""
    t = target(handler=handler, passwords={"msfadmin": "msfadmin"})
    r = enroll.enroll(LOCAL, "msfadmin", "msfadmin", log=lambda *_: None)
    assert r["ready"] is True
    assert "/sbin/iptables" in r["allowed_commands"] and "managed block" in r["sudoers"]
    joined = "\n".join(t.commands)
    assert "useradd -m -s /bin/bash soar" in joined
    assert "authorized_keys" in joined and "visudo -cf" in joined and "passwd -l soar" in joined
    assert "msfadmin\n" not in joined                      # the password is never in a command
    assert {"enroll.start", "enroll.done"} <= set(audit_actions())


def test_enroll_wrong_admin_password(target):
    target(passwords={"msfadmin": "right"})
    with pytest.raises(enroll.EnrollError, match="wrong username or password"):
        enroll.enroll(LOCAL, "msfadmin", "wrong", log=lambda *_: None)


def test_enroll_stops_when_iptables_is_missing(target):
    target(handler=lambda cmd: (1, "") if "test -x" in cmd else (0, ""),
           passwords={"msfadmin": "msfadmin"})
    with pytest.raises(enroll.EnrollError, match="iptables not found"):
        enroll.enroll(LOCAL, "msfadmin", "msfadmin", log=lambda *_: None)
