"""
One-step target enrollment for auto-remediation (Linux targets).

    ./start.sh enroll 192.168.103.105          (runs this inside the engine container)
    python -m soar.enroll 192.168.103.105 --admin-user msfadmin

What it does on the target, over SSH, as an existing admin (asked once):
  1. creates the management user (SSH_USERNAME, e.g. "soar") if missing
  2. installs the engine's public key for that user
  3. allows ONLY the commands the playbooks need, without a password (sudoers),
     checked with `visudo -c` first and rolled back if the check fails
  4. locks that user's password (key login only) and clears any account expiry
  5. tests key login + sudo and prints a ready / not-ready checklist

The admin password is typed once, hidden, used for this session only, and is
never stored, logged or sent anywhere else. Old servers (Metasploitable 2,
OpenSSH 4.7, sudo 1.6) and modern ones (Ubuntu, /etc/sudoers.d) both work.
"""
from __future__ import annotations

import argparse
import getpass
import shlex
import sys

from common.allowlist import assert_in_scope
from common.audit import log_event
from common.config import get_settings

TOOLS = ["iptables", "passwd", "chage", "sed", "pkill", "systemctl", "update-rc.d"]
DIRS = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
MARK_BEGIN = "# >>> mini-soar (managed by soar.enroll, do not edit) >>>"
MARK_END = "# <<< mini-soar <<<"
PATHFIX = 'PATH="$PATH:/usr/sbin:/sbin"; export PATH; '
# non-interactive sudo that also works on sudo 1.6 (no "-n" there): an empty stdin
# makes it fail at once instead of waiting if a password would be needed
SUDO_NI = "sudo -S -p '' "
NO_IN = " </dev/null"


class EnrollError(RuntimeError):
    pass


# --------------------------------------------------------------------------- helpers
def _settings_ok():
    s = get_settings()
    if not s.ssh_username or not s.ssh_private_key_path:
        raise EnrollError("SSH_USERNAME and SSH_PRIVATE_KEY_PATH must be set in .env")
    if s.ssh_username in ("root", "administrator"):
        raise EnrollError("SSH_USERNAME must be a dedicated user such as 'soar', not root")
    return s


def public_key_line() -> str:
    """Public key text derived from the engine's private key (no .pub file needed)."""
    from soar.remediation import _load_key
    key = _load_key(_settings_ok().ssh_private_key_path)
    return f"{key.get_name()} {key.get_base64()} mini-soar-engine"


def _admin_connect(ip: str, user: str, password: str):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=user, password=password, timeout=10,
                       allow_agent=False, look_for_keys=False,
                       banner_timeout=15, auth_timeout=15)
    except paramiko.AuthenticationException:
        raise EnrollError(f"login as '{user}' failed: wrong username or password")
    except Exception as e:
        raise EnrollError(f"cannot reach {ip} over SSH: {e}")
    return client


def _run(client, cmd: str) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=90)
    stdin.close()
    out = stdout.read().decode("utf-8", "replace") + stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out.strip()


def _root(client, admin: str, password: str, script: str) -> tuple[int, str]:
    """Run a shell script as root: directly if admin is root, else via sudo -S.
    The password goes only to sudo's stdin, never into the command line."""
    if admin == "root":
        return _run(client, "sh -c " + shlex.quote(script))
    stdin, stdout, stderr = client.exec_command(
        "sudo -S -p '' sh -c " + shlex.quote(script), timeout=90)
    stdin.write(password + "\n")
    stdin.flush()
    stdin.channel.shutdown_write()
    out = stdout.read().decode("utf-8", "replace") + stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    if rc != 0 and ("incorrect password" in out.lower() or "not in the sudoers" in out.lower()):
        raise EnrollError(f"'{admin}' cannot use sudo on this host: {out.strip()[:200]}")
    return rc, out.strip()


def _find_tools(client) -> list[str]:
    found = []
    for t in TOOLS:
        for d in DIRS:
            rc, _ = _run(client, f"test -x {d}/{t}")
            if rc == 0:
                found.append(f"{d}/{t}")
    rc, _ = _run(client, "test -d /etc/init.d")
    if rc == 0:
        found.append("/etc/init.d/*")
    if not any(p.endswith("/iptables") for p in found):
        raise EnrollError("iptables not found on the target; block_port would not work")
    return found


# --------------------------------------------------------------------------- steps
def _step_user(client, admin, pw, u):
    rc, out = _root(client, admin, pw, f"id {u} >/dev/null 2>&1 || useradd -m -s /bin/bash {u}")
    if rc != 0:
        raise EnrollError(f"could not create user {u}: {out[:200]}")


def _step_key(client, admin, pw, u, pub):
    q = shlex.quote(pub)
    script = (f'H=$(getent passwd {u} | cut -d: -f6); [ -n "$H" ] || exit 3; '
              f'mkdir -p "$H/.ssh" && touch "$H/.ssh/authorized_keys" && '
              f'(grep -qF {q} "$H/.ssh/authorized_keys" || echo {q} >> "$H/.ssh/authorized_keys") && '
              f'chmod 700 "$H/.ssh" && chmod 600 "$H/.ssh/authorized_keys" && chown -R {u}: "$H/.ssh"')
    rc, out = _root(client, admin, pw, script)
    if rc != 0:
        raise EnrollError(f"could not install the key: {out[:200]}")


def _step_sudoers(client, admin, pw, u, paths) -> str:
    line = f"{u} ALL=(ALL) NOPASSWD: " + ", ".join(paths)
    ql, qb, qe = shlex.quote(line), shlex.quote(MARK_BEGIN), shlex.quote(MARK_END)
    rc, _ = _root(client, admin, pw,
                  "grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers && test -d /etc/sudoers.d")
    if rc == 0:   # modern: own file in /etc/sudoers.d
        script = (f"T=$(mktemp) && printf '%s\\n' {ql} > \"$T\" && visudo -cf \"$T\" >/dev/null && "
                  f"install -m 0440 -o root -g root \"$T\" /etc/sudoers.d/mini-soar; R=$?; rm -f \"$T\"; exit $R")
        where = "/etc/sudoers.d/mini-soar"
    else:         # old sudo (Metasploitable): managed block inside /etc/sudoers, with backup
        script = (f"cp -p /etc/sudoers /etc/sudoers.mini-soar.bak && T=$(mktemp) && "
                  f"sed -e '/^# >>> mini-soar/,/^# <<< mini-soar/d' -e '/^{u}[[:space:]][[:space:]]*ALL=/d' "
                  f"/etc/sudoers.mini-soar.bak > \"$T\" && printf '%s\\n%s\\n%s\\n' {qb} {ql} {qe} >> \"$T\" && "
                  f"visudo -cf \"$T\" >/dev/null && cat \"$T\" > /etc/sudoers && chmod 0440 /etc/sudoers; "
                  f"R=$?; rm -f \"$T\"; exit $R")
        where = "/etc/sudoers (managed block, backup in /etc/sudoers.mini-soar.bak)"
    rc, out = _root(client, admin, pw, script)
    if rc != 0:
        raise EnrollError(f"sudoers check failed, nothing was changed: {out[:200]}")
    return where


def _step_lock(client, admin, pw, u):
    _root(client, admin, pw,
          f"{PATHFIX}passwd -l {u} >/dev/null 2>&1; chage -E -1 {u} 2>/dev/null || true")


# --------------------------------------------------------------------------- checks
def check_target(ip: str, os_guess: str | None = None) -> dict:
    """Is this host ready for auto-fix? Uses only the engine key (no admin password)."""
    from soar.remediation import _connect, os_family, RemediationError
    assert_in_scope(ip)
    s = get_settings()
    checks: list[dict] = []

    def add(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    try:
        client = _connect(ip)
    except (RemediationError, Exception) as e:
        add(f"key login as '{s.ssh_username}'", False, str(e)[:160])
        return {"ip": ip, "ready": False, "checks": checks,
                "hint": f"Run on the engine: ./start.sh enroll {ip}"}
    try:
        add(f"key login as '{s.ssh_username}'", True)
        if os_family(os_guess) == "windows":
            rc, out = _run(client, "whoami")
            add("Windows shell", rc == 0, out[:80])
        else:
            rc, out = _run(client, f"{PATHFIX}{SUDO_NI}-l{NO_IN}")
            add("sudo without password", rc == 0 and "NOPASSWD" in out, "" if rc == 0 else out[:120])
            rc, out = _run(client, f"{PATHFIX}{SUDO_NI}iptables -L INPUT -n{NO_IN} >/dev/null")
            add("firewall control (iptables)", rc == 0, out[:120])
            rc, out = _run(client, f"{PATHFIX}{SUDO_NI}passwd -S {s.ssh_username}{NO_IN}")
            add("account control (passwd)", rc == 0, out[:120])
    finally:
        client.close()
    ready = all(c["ok"] for c in checks)
    return {"ip": ip, "ready": ready, "checks": checks,
            "hint": "" if ready else f"Run on the engine: ./start.sh enroll {ip}"}


# --------------------------------------------------------------------------- main
def enroll(ip: str, admin: str, password: str, log=print) -> dict:
    s = _settings_ok()
    assert_in_scope(ip)                       # never outside the authorized scope
    u = s.ssh_username
    if admin == u:
        raise EnrollError(f"use an existing admin account, not '{u}' itself")
    pub = public_key_line()
    log_event("admin-cli", "enroll.start", ip, {"admin_user": admin, "mgmt_user": u})
    client = _admin_connect(ip, admin, password)
    try:
        log(f"[1/5] user '{u}'");                _step_user(client, admin, password, u)
        log("[2/5] engine SSH key");            _step_key(client, admin, password, u, pub)
        paths = _find_tools(client)
        log(f"[3/5] sudo rules ({len(paths)} commands)")
        where = _step_sudoers(client, admin, password, u, paths)
        log("[4/5] lock password, clear expiry"); _step_lock(client, admin, password, u)
    finally:
        client.close()
    log("[5/5] testing key login + sudo")
    result = check_target(ip)
    result["sudoers"] = where
    result["allowed_commands"] = paths
    log_event("admin-cli", "enroll.done", ip, {"ready": result["ready"], "sudoers": where,
                                               "commands": paths})
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="enroll", description="Prepare a Linux lab host for auto-fix")
    ap.add_argument("ip")
    ap.add_argument("--admin-user", help="existing admin on the target (e.g. msfadmin)")
    ap.add_argument("--check-only", action="store_true", help="only test, change nothing")
    ap.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    a = ap.parse_args(argv)
    try:
        if a.check_only:
            r = check_target(a.ip)
        else:
            s = _settings_ok()
            assert_in_scope(a.ip)
            admin = a.admin_user or input(f"Existing admin user on {a.ip}: ").strip()
            print(f"\nThis will, on {a.ip}: create user '{s.ssh_username}', add the engine key,\n"
                  f"allow only the fix commands via sudo, and lock its password (key-only).")
            if not a.yes and input("Continue? [y/N] ").strip().lower() != "y":
                print("Cancelled.")
                return 1
            pw = getpass.getpass(f"Password for {admin}@{a.ip} (hidden, not stored): ")
            r = enroll(a.ip, admin, pw)
            pw = ""
    except EnrollError as e:
        print(f"\n✘ {e}")
        return 2
    except Exception as e:
        print(f"\n✘ {type(e).__name__}: {e}")
        return 2
    print()
    for c in r["checks"]:
        print(f"  {'✔' if c['ok'] else '✘'} {c['check']}" + (f"  ({c['detail']})" if c["detail"] and not c["ok"] else ""))
    if r.get("sudoers"):
        print(f"  sudo rules in: {r['sudoers']}")
    print("\nREADY for auto-fix ✔" if r["ready"] else f"\nNOT ready ✘  {r['hint']}")
    return 0 if r["ready"] else 3


if __name__ == "__main__":
    sys.exit(main())
