"""Suggested fixes (playbooks), plan building and its safety refusals."""
import base64

import pytest

from common.allowlist import ScopeError
from soar import playbooks, remediation
from soar.remediation import RemediationError

META = "192.168.56.101"


def svc(port, name="", product="", version=""):
    return {"port": port, "service_name": name, "product": product, "version": version}


# ---- playbook selection ------------------------------------------------------
def test_default_password_locks_the_account():
    s = playbooks.suggest(svc(22, "ssh"), default_cred_user="msfadmin")
    assert s["action_type"] == "disable_account"
    assert s["params"] == {"username": "msfadmin", "os": "linux"}


def test_anonymous_ftp_blocks_the_port():
    s = playbooks.suggest(svc(21, "ftp"), default_cred_user="anonymous")
    assert (s["action_type"], s["params"]["port"]) == ("block_port", 21)


@pytest.mark.parametrize("name,service", [("telnet", "telnet"), ("shell", "shell"),
                                          ("login", "login"), ("exec", "exec")])
def test_cleartext_services_are_stopped(name, service):
    s = playbooks.suggest(svc(23, name))
    assert s["action_type"] == "stop_service" and s["params"]["service"] == service
    assert s["params"]["port"] == 23


@pytest.mark.parametrize("port", [1524, 6667, 3632, 1099, 8787])
def test_backdoor_ports_are_blocked(port):
    s = playbooks.suggest(svc(port, "unknown"))
    assert s["action_type"] == "block_port" and s["params"]["port"] == port


@pytest.mark.parametrize("port", [3306, 5432, 5900, 2049, 3389, 445])
def test_exposed_admin_services_are_blocked(port):
    assert playbooks.suggest(svc(port, "x"))["action_type"] == "block_port"


def test_backdoored_build_is_blocked():
    s = playbooks.suggest(svc(21, "ftp", "vsftpd", "2.3.4"))
    assert s["action_type"] == "block_port" and "backdoored" in s["reason"]


def test_any_other_cve_blocks_until_patched():
    s = playbooks.suggest(svc(80, "http", "Apache httpd", "2.2.8"), cve={"cve_id": "CVE-2010-0001"})
    assert s["action_type"] == "block_port" and "CVE-2010-0001" in s["reason"]


def test_ssh_port_is_never_suggested_for_blocking():
    assert playbooks.suggest(svc(22, "ssh", "OpenSSH", "4.7p1"), cve={"cve_id": "CVE-X"}) is None


def test_nothing_to_suggest_without_port_or_finding():
    assert playbooks.suggest(None) is None
    assert playbooks.suggest(svc(80, "http")) is None


def test_windows_target_gets_windows_params():
    s = playbooks.suggest(svc(23, "telnet"), os="windows")
    assert s["params"]["service"] == "TlntSvr" and s["params"]["os"] == "windows"
    assert playbooks.suggest(svc(3389, "ms-wbt-server"), os="windows")["params"]["os"] == "windows"


def test_every_suggestion_builds_a_valid_plan():
    """Whatever the playbook suggests must be accepted by the plan builder."""
    cases = [playbooks.suggest(svc(23, "telnet")), playbooks.suggest(svc(1524, "x")),
             playbooks.suggest(svc(3306, "mysql")),
             playbooks.suggest(svc(22, "ssh"), default_cred_user="msfadmin"),
             playbooks.suggest(svc(21, "ftp"), default_cred_user="anonymous"),
             playbooks.suggest(svc(3389, "rdp"), os="windows"),
             playbooks.suggest(svc(23, "telnet"), os="windows")]
    for s in cases:
        plan = remediation.build_plan(s["action_type"], META, s["params"])
        assert plan.apply_cmds and plan.rollback_cmds


# ---- Linux plans -------------------------------------------------------------
def test_block_port_plan():
    p = remediation.build_plan("block_port", META, {"port": 23, "proto": "tcp"})
    assert "iptables -I INPUT -p tcp --dport 23 -j DROP" in p.apply_cmds[0]
    assert "iptables -D INPUT -p tcp --dport 23 -j DROP" in p.apply_cmds[0]   # idempotent
    assert p.rollback_cmds[0].endswith("sudo iptables -D INPUT -p tcp --dport 23 -j DROP")
    assert p.description == f"Block inbound tcp/23 on {META}"


def test_stop_service_plan_covers_systemd_initd_and_inetd():
    p = remediation.build_plan("stop_service", META, {"service": "telnet"})
    for piece in ("systemctl stop telnet", "/etc/init.d/telnet stop", "/etc/inetd.conf", "#SOAR# telnet"):
        assert piece in p.apply_cmds[0]
    for piece in ("systemctl enable telnet", "/etc/init.d/telnet start", "s/^#SOAR# telnet"):
        assert piece in p.rollback_cmds[0]


def test_disable_account_plan():
    p = remediation.build_plan("disable_account", META, {"username": "msfadmin"})
    assert p.apply_cmds[0].endswith("sudo passwd -l msfadmin")
    assert "passwd -u msfadmin" in p.rollback_cmds[0] and "chage -E -1 msfadmin" in p.rollback_cmds[0]


# ---- refusals (the engine must not lock itself out or run junk) --------------
@pytest.mark.parametrize("action,params,msg", [
    ("block_port", {"port": 22}, "SSH access"),
    ("block_port", {"port": 0}, "Invalid port"),
    ("block_port", {"port": 70000}, "Invalid port"),
    ("block_port", {"port": 80, "proto": "icmp"}, "Invalid protocol"),
    ("block_port", {"port": 80, "proto": "tcp; rm -rf /"}, "Unsafe"),
    ("stop_service", {"service": "ssh"}, "stopping SSH"),
    ("stop_service", {"service": "sshd"}, "stopping SSH"),
    ("stop_service", {"service": "telnet; reboot"}, "Unsafe"),
    ("stop_service", {"service": "$(id)"}, "Unsafe"),
    ("disable_account", {"username": "root"}, "lock out"),
    ("disable_account", {"username": "soar"}, "lock out"),          # the engine's own account
    ("disable_account", {"username": "a b"}, "Unsafe"),
    ("disable_account", {"username": "x`id`"}, "Unsafe"),
    ("format_disk", {}, "Unknown action_type"),
])
def test_dangerous_or_invalid_plans_are_refused(action, params, msg):
    with pytest.raises(RemediationError, match=msg):
        remediation.build_plan(action, META, params)


def test_plan_for_out_of_scope_host_is_refused():
    with pytest.raises(ScopeError):
        remediation.build_plan("block_port", "10.9.9.9", {"port": 23})
    with pytest.raises(ScopeError):
        remediation.build_plan("block_port", "192.168.56.1", {"port": 23})      # deny list


# ---- Windows plans -----------------------------------------------------------
def decode(cmd):
    enc = cmd.split("-EncodedCommand ")[1]
    return base64.b64decode(enc).decode("utf-16-le")


def test_windows_block_port_plan():
    p = remediation.build_plan("block_port", META, {"port": 3389, "os": "windows"})
    assert p.apply_cmds[0].startswith("powershell -NoProfile -NonInteractive")
    script = decode(p.apply_cmds[0])
    assert "New-NetFirewallRule -DisplayName 'MiniSOAR-Block-TCP-3389'" in script
    assert "-Action Block" in script
    assert "Remove-NetFirewallRule -DisplayName 'MiniSOAR-Block-TCP-3389'" in decode(p.rollback_cmds[0])


def test_windows_stop_service_saves_start_type_for_rollback():
    p = remediation.build_plan("stop_service", META, {"service": "TlntSvr", "os": "windows"})
    assert "Set-Service -Name 'TlntSvr' -StartupType Disabled" in decode(p.apply_cmds[0])
    assert "svc-TlntSvr.txt" in decode(p.apply_cmds[0]) and "Start-Service" in decode(p.rollback_cmds[0])


def test_windows_disable_account_plan_and_refusals():
    p = remediation.build_plan("disable_account", META, {"username": "guest", "os": "windows"})
    assert "Disable-LocalUser -Name 'guest'" in decode(p.apply_cmds[0])
    assert "Enable-LocalUser -Name 'guest'" in decode(p.rollback_cmds[0])
    for bad in ("Administrator", "SOAR"):
        with pytest.raises(RemediationError):
            remediation.build_plan("disable_account", META, {"username": bad, "os": "windows"})
    with pytest.raises(RemediationError):
        remediation.build_plan("stop_service", META, {"service": "sshd", "os": "windows"})
    with pytest.raises(RemediationError):
        remediation.build_plan("block_port", META, {"port": 22, "os": "windows"})


@pytest.mark.parametrize("guess,family", [("Microsoft Windows 10", "windows"), ("Linux 2.6.X", "linux"),
                                          ("", "linux"), (None, "linux")])
def test_os_family(guess, family):
    assert remediation.os_family(guess) == family


# ---- dry-run / apply gates ---------------------------------------------------
def test_dry_run_shows_commands_and_runs_nothing(monkeypatch, audit_actions):
    monkeypatch.setattr(remediation, "run_remote",
                        lambda *a, **k: pytest.fail("dry-run must not connect"))
    p = remediation.build_plan("block_port", META, {"port": 23})
    text = remediation.dry_run(p)
    assert "DRY-RUN" in text and "iptables -I INPUT -p tcp --dport 23 -j DROP" in text
    assert "rollback (stored for undo)" in text
    assert "remediation.dryrun" in audit_actions()


def test_windows_dry_run_is_readable():
    p = remediation.build_plan("block_port", META, {"port": 3389, "os": "windows"})
    text = remediation.dry_run(p)
    assert "[PowerShell]" in text and "New-NetFirewallRule" in text and "EncodedCommand" not in text


def test_apply_needs_approval_and_totp(monkeypatch):
    monkeypatch.setattr(remediation, "run_remote",
                        lambda *a, **k: pytest.fail("must not run without the gates"))
    p = remediation.build_plan("block_port", META, {"port": 23})
    with pytest.raises(RemediationError, match="not admin-approved"):
        remediation.apply(p, approved=False, totp_verified=True)
    with pytest.raises(RemediationError, match="TOTP"):
        remediation.apply(p, approved=True, totp_verified=False)


def test_force_dry_run_is_a_kill_switch(monkeypatch, set_env, audit_actions):
    set_env(FORCE_DRY_RUN="true")
    monkeypatch.setattr(remediation, "run_remote",
                        lambda *a, **k: pytest.fail("kill-switch on: nothing may run"))
    p = remediation.build_plan("block_port", META, {"port": 23})
    assert "not executed" in remediation.apply(p, approved=True, totp_verified=True)
    assert "not executed" in remediation.rollback(p)
    assert "remediation.blocked_force_dryrun" in audit_actions()


def test_apply_and_rollback_run_the_planned_commands(monkeypatch, audit_actions):
    ran = []
    monkeypatch.setattr(remediation, "run_remote",
                        lambda ip, cmds, check=True: ran.append((ip, cmds)) or [(c, 0, "ok") for c in cmds])
    p = remediation.build_plan("block_port", META, {"port": 23})
    out = remediation.apply(p, approved=True, totp_verified=True)
    assert ran[0] == (META, p.apply_cmds) and "[rc=0] ok" in out
    remediation.rollback(p)
    assert ran[1] == (META, p.rollback_cmds)
    assert {"remediation.execute", "remediation.execute.done", "remediation.rollback"} <= set(audit_actions())


def test_ssh_settings_are_required(set_env):
    set_env(SSH_USERNAME="", SSH_PRIVATE_KEY_PATH="")
    with pytest.raises(RemediationError, match="SSH_PRIVATE_KEY_PATH"):
        remediation._connect(META)


def test_run_remote_refuses_out_of_scope():
    with pytest.raises(ScopeError):
        remediation.run_remote("8.8.8.8", ["id"])
