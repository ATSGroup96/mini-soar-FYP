"""
SSH-based remediation actions (defensive, lab-only).

Supported actions (the agent's "playbooks"), each with a dry-run preview, an
apply command and a rollback command:
  * block_port      — drop inbound traffic to a risky port (iptables)
  * stop_service    — stop + disable a risky service (systemd, SysV init.d or
                      inetd — works on modern Linux AND old ones like
                      Metasploitable 2 / Ubuntu 8.04)
  * disable_account — lock a local account that had a default credential

Linux targets get POSIX shell commands; Windows targets (OpenSSH Server,
built into Windows 10/11 and Server 2019+) get PowerShell commands sent as
-EncodedCommand so no quoting can break. The OS is taken from params["os"],
which the approval step fills from the asset's nmap OS guess.

SAFETY (enforced here, not just by convention):
  * assert_in_scope() on the target before ANY connection
  * dry-run ALWAYS produces the exact commands; nothing runs in dry-run
  * apply() refuses unless the remediation has been approved AND TOTP-verified
  * FORCE_DRY_RUN in .env is a global kill-switch (apply becomes a no-op preview)
  * refuses actions that would lock the engine out (blocking SSH/22, locking
    the management account or root)
  * every step is written to the tamper-evident audit log and syslog/SIEM
  * a rollback plan is computed up front and stored, so every change is undoable
  * any command that fails raises -> the worker rolls the change back
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from common.config import get_settings
from common.allowlist import assert_in_scope
from common.audit import log_event
from common import syslog_logger as slog

# old distros keep iptables/init tools in sbin, which a non-login SSH shell
# may not have on PATH
PRE = 'PATH="$PATH:/usr/sbin:/sbin"; export PATH; '
_SAFE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PROTECTED_PORTS = {22}            # the engine manages hosts over SSH
PROTECTED_ACCOUNTS = {"root", "administrator"}


def os_family(os_guess: str | None) -> str:
    """'windows' or 'linux' from an nmap OS guess (default linux)."""
    return "windows" if "windows" in (os_guess or "").lower() else "linux"


def _ps(script: str) -> str:
    """Wrap a PowerShell script so it runs safely from any Windows SSH shell."""
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc}"


def _ps_plain(script: str) -> str:
    """Readable form of the same script, used only for dry-run previews."""
    return f"[PowerShell] {script}"


@dataclass
class Plan:
    action_type: str
    target_ip: str
    params: dict
    apply_cmds: list[str] = field(default_factory=list)
    rollback_cmds: list[str] = field(default_factory=list)
    description: str = ""


class RemediationError(RuntimeError):
    pass


class CommandFailed(RemediationError):
    """A remote command ran and returned non-zero: the host MAY be half-changed."""


def _safe(value: str, what: str) -> str:
    value = str(value)
    if not _SAFE.match(value):
        raise RemediationError(f"Unsafe {what}: {value!r}")
    return value


def _stop_service_cmds(svc: str) -> tuple[str, str]:
    """Portable stop/disable + matching rollback for systemd, SysV and inetd."""
    apply = (
        PRE +
        f'if command -v systemctl >/dev/null 2>&1 && systemctl cat {svc} >/dev/null 2>&1; then '
        f'sudo systemctl stop {svc} && sudo systemctl disable {svc}; '
        f'elif [ -x /etc/init.d/{svc} ]; then '
        f'sudo /etc/init.d/{svc} stop; sudo update-rc.d -f {svc} remove >/dev/null 2>&1 || true; '
        f'elif grep -Eq "^[[:space:]]*{svc}[[:space:]]" /etc/inetd.conf 2>/dev/null; then '
        f'sudo sed -i "s/^\\([[:space:]]*\\){svc}\\([[:space:]]\\)/#SOAR# {svc}\\2/" /etc/inetd.conf && '
        f'(sudo /etc/init.d/openbsd-inetd reload || sudo /etc/init.d/inetd reload || sudo pkill -HUP inetd); '
        f'else echo "service {svc} not found (systemd/init.d/inetd)" >&2; exit 3; fi'
    )
    rollback = (
        PRE +
        f'if command -v systemctl >/dev/null 2>&1 && systemctl cat {svc} >/dev/null 2>&1; then '
        f'sudo systemctl enable {svc} && sudo systemctl start {svc}; '
        f'elif [ -x /etc/init.d/{svc} ]; then '
        f'sudo update-rc.d {svc} defaults >/dev/null 2>&1 || true; sudo /etc/init.d/{svc} start; '
        f'elif grep -q "^#SOAR# {svc}[[:space:]]" /etc/inetd.conf 2>/dev/null; then '
        f'sudo sed -i "s/^#SOAR# {svc}\\([[:space:]]\\)/{svc}\\1/" /etc/inetd.conf && '
        f'(sudo /etc/init.d/openbsd-inetd reload || sudo /etc/init.d/inetd reload || sudo pkill -HUP inetd); '
        f'else echo "nothing to roll back for {svc}" >&2; exit 3; fi'
    )
    return apply, rollback


def build_plan(action_type: str, target_ip: str, params: dict) -> Plan:
    """Construct the exact commands for an action. No connection is made."""
    assert_in_scope(target_ip)  # fail closed
    p = Plan(action_type=action_type, target_ip=target_ip, params=params)
    if (params or {}).get("os") == "windows":
        return _build_windows(p)

    if action_type == "block_port":
        port = int(params["port"])
        if not 1 <= port <= 65535:
            raise RemediationError(f"Invalid port: {port}")
        if port in PROTECTED_PORTS:
            raise RemediationError(
                f"Refused: blocking port {port} would cut the engine's SSH access. "
                "Use stop_service / hardening instead.")
        proto = _safe(params.get("proto", "tcp"), "protocol")
        if proto not in ("tcp", "udp"):
            raise RemediationError(f"Invalid protocol: {proto}")
        rule = f"INPUT -p {proto} --dport {port} -j DROP"
        # delete-then-insert is idempotent and works on old iptables without -C
        p.apply_cmds = [PRE + f"sudo iptables -D {rule} 2>/dev/null; sudo iptables -I {rule}"]
        p.rollback_cmds = [PRE + f"sudo iptables -D {rule}"]
        p.description = f"Block inbound {proto}/{port} on {target_ip}"

    elif action_type == "stop_service":
        svc = _safe(params["service"], "service name")
        if svc in ("ssh", "sshd", "openssh-server"):
            raise RemediationError("Refused: stopping SSH would cut the engine's access.")
        apply, rollback = _stop_service_cmds(svc)
        p.apply_cmds = [apply]
        p.rollback_cmds = [rollback]
        p.description = f"Stop + disable service '{svc}' on {target_ip}"

    elif action_type == "disable_account":
        user = _safe(params["username"], "username")
        mgmt = get_settings().ssh_username
        if user in PROTECTED_ACCOUNTS or (mgmt and user == mgmt):
            raise RemediationError(
                f"Refused: locking '{user}' would lock out root or the engine's own account.")
        p.apply_cmds = [PRE + f"sudo passwd -l {user}"]
        # old shadow-utils (e.g. Metasploitable / Ubuntu 8.04) also EXPIRE the
        # account on `passwd -l`; clear the expiry too so the undo is complete
        p.rollback_cmds = [PRE + f"sudo passwd -u {user} && (sudo chage -E -1 {user} || true)"]
        p.description = f"Lock account '{user}' on {target_ip}"

    else:
        raise RemediationError(f"Unknown action_type: {action_type!r}")

    return p


def _build_windows(p: Plan) -> Plan:
    """Same three playbooks for Windows, via PowerShell."""
    params, mgmt = p.params, (get_settings().ssh_username or "").lower()
    stop_on_err = "$ErrorActionPreference='Stop'; "

    if p.action_type == "block_port":
        port = int(params["port"])
        if not 1 <= port <= 65535:
            raise RemediationError(f"Invalid port: {port}")
        if port in PROTECTED_PORTS:
            raise RemediationError(
                f"Refused: blocking port {port} would cut the engine's SSH access.")
        proto = _safe(params.get("proto", "tcp"), "protocol").upper()
        if proto not in ("TCP", "UDP"):
            raise RemediationError(f"Invalid protocol: {proto}")
        name = f"MiniSOAR-Block-{proto}-{port}"
        apply = (stop_on_err +
                 f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; "
                 f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound "
                 f"-Protocol {proto} -LocalPort {port} -Action Block -Profile Any | Out-Null; "
                 f"if (-not (Get-NetFirewallProfile | Where-Object Enabled)) "
                 f"{{ Write-Error 'Windows Firewall is off on every profile' }}")
        rollback = stop_on_err + f"Remove-NetFirewallRule -DisplayName '{name}'"
        p.description = f"Block inbound {proto.lower()}/{port} on {p.target_ip} (Windows Firewall)"

    elif p.action_type == "stop_service":
        svc = _safe(params["service"], "service name")
        if svc.lower() in ("sshd", "ssh-agent"):
            raise RemediationError("Refused: stopping OpenSSH would cut the engine's access.")
        state = f"$env:ProgramData\\MiniSOAR\\svc-{svc}.txt"
        apply = (stop_on_err +
                 f"$s = Get-Service -Name '{svc}'; "
                 f"New-Item -ItemType Directory -Force \"$env:ProgramData\\MiniSOAR\" | Out-Null; "
                 f"Set-Content -Path \"{state}\" -Value $s.StartType; "
                 f"Stop-Service -Name '{svc}' -Force; Set-Service -Name '{svc}' -StartupType Disabled")
        rollback = (stop_on_err +
                    f"$t = 'Automatic'; if (Test-Path \"{state}\") {{ $t = (Get-Content \"{state}\").Trim() }}; "
                    f"if ($t -eq 'AutomaticDelayedStart') {{ $t = 'Automatic' }}; "
                    f"Set-Service -Name '{svc}' -StartupType $t; "
                    f"if ($t -ne 'Disabled') {{ Start-Service -Name '{svc}' }}")
        p.description = f"Stop + disable Windows service '{svc}' on {p.target_ip}"

    elif p.action_type == "disable_account":
        user = _safe(params["username"], "username")
        if user.lower() in PROTECTED_ACCOUNTS or (mgmt and user.lower() == mgmt):
            raise RemediationError(
                f"Refused: disabling '{user}' would lock out Administrator or the engine's account.")
        apply = stop_on_err + f"Disable-LocalUser -Name '{user}'"
        rollback = stop_on_err + f"Enable-LocalUser -Name '{user}'"
        p.description = f"Disable local account '{user}' on {p.target_ip} (Windows)"

    else:
        raise RemediationError(f"Unknown action_type: {p.action_type!r}")

    p.apply_cmds = [_ps(apply)]
    p.rollback_cmds = [_ps(rollback)]
    p.params = dict(params, _preview_apply=apply, _preview_rollback=rollback)
    return p


def dry_run(plan: Plan) -> str:
    """Return a human-readable preview of exactly what apply() would run."""
    assert_in_scope(plan.target_ip)
    lines = [f"# DRY-RUN — {plan.description}",
             f"# target: {plan.target_ip}  action: {plan.action_type}",
             "# commands that WOULD run:"]
    if plan.params.get("os") == "windows":
        lines += [f"  > {_ps_plain(plan.params['_preview_apply'])}"]
        lines += ["# rollback (stored for undo):"]
        lines += [f"  > {_ps_plain(plan.params['_preview_rollback'])}"]
    else:
        lines += [f"  $ {c}" for c in plan.apply_cmds]
        lines += ["# rollback (stored for undo):"]
        lines += [f"  $ {c}" for c in plan.rollback_cmds]
    preview = "\n".join(lines)
    log_event("engine", "remediation.dryrun", plan.target_ip,
              {"action": plan.action_type, "params": plan.params})
    return preview


# --------------------------------------------------------------------------- SSH
def _load_key(path: str):
    import paramiko
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key_file(path)
        except Exception as e:  # wrong type -> try the next one
            last = e
    raise RemediationError(f"Cannot load SSH key {path}: {last}")


def _connect(ip: str):
    """Key-based SSH. Falls back to legacy ssh-rsa (SHA-1) signatures, which
    old servers such as Metasploitable 2 (OpenSSH 4.7) need."""
    import paramiko
    s = get_settings()
    if not s.ssh_private_key_path or not s.ssh_username:
        raise RemediationError("SSH_PRIVATE_KEY_PATH / SSH_USERNAME not set in .env")
    key = _load_key(s.ssh_private_key_path)
    attempts = [None, {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]}]
    last = None
    for disabled in attempts:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, username=s.ssh_username, pkey=key, timeout=8,
                           allow_agent=False, look_for_keys=False,
                           banner_timeout=15, auth_timeout=15,
                           disabled_algorithms=disabled)
            return client
        except Exception as e:
            last = e
            client.close()
    raise RemediationError(f"SSH to {ip} failed: {last}")


def run_remote(ip: str, cmds: list[str], check: bool = True) -> list[tuple[str, int, str]]:
    """Run commands over SSH. Returns [(cmd, rc, output)]. Raises on rc != 0 if check."""
    assert_in_scope(ip)
    client = _connect(ip)
    results = []
    try:
        for c in cmds:
            stdin, stdout, stderr = client.exec_command(c, timeout=60)
            stdin.close()
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            results.append((c, rc, (out + err).strip()))
            if check and rc != 0:
                raise CommandFailed(f"command failed (rc={rc}): {(out + err).strip()[:300]}")
    finally:
        client.close()
    return results


def _ssh_exec(ip: str, cmds: list[str]) -> str:
    return "\n".join(f"$ {c}\n[rc={rc}] {o}" for c, rc, o in run_remote(ip, cmds))


# ---------------------------------------------------------------- apply / undo
def apply(plan: Plan, *, approved: bool, totp_verified: bool) -> str:
    """
    Execute the plan — ONLY if approved AND TOTP-verified AND not force-dry-run.
    Returns the command output (or the dry-run preview when gated off).
    Raises RemediationError if any command fails.
    """
    assert_in_scope(plan.target_ip)
    s = get_settings()

    if not approved:
        raise RemediationError("Refused: remediation is not admin-approved.")
    if not totp_verified:
        raise RemediationError("Refused: TOTP 2FA not verified.")
    if s.force_dry_run:
        log_event("engine", "remediation.blocked_force_dryrun", plan.target_ip,
                  {"action": plan.action_type})
        slog.send(f"remediation blocked by FORCE_DRY_RUN: {plan.description}",
                  slog.WARNING)
        return "FORCE_DRY_RUN is on — not executed.\n" + dry_run(plan)

    log_event("admin", "remediation.execute", plan.target_ip,
              {"action": plan.action_type, "params": plan.params,
               "cmds": plan.apply_cmds})
    slog.send(f"EXECUTING remediation: {plan.description}", slog.ALERT)
    out = _ssh_exec(plan.target_ip, plan.apply_cmds)
    log_event("admin", "remediation.execute.done", plan.target_ip,
              {"action": plan.action_type, "output_tail": out[-400:]})
    return out


def rollback(plan: Plan) -> str:
    """Undo a previously applied plan."""
    assert_in_scope(plan.target_ip)
    if get_settings().force_dry_run:
        return "FORCE_DRY_RUN is on — rollback not executed.\n" + "\n".join(
            f"  $ {c}" for c in plan.rollback_cmds)
    log_event("admin", "remediation.rollback", plan.target_ip,
              {"action": plan.action_type, "cmds": plan.rollback_cmds})
    slog.send(f"ROLLING BACK: {plan.description}", slog.ALERT)
    out = _ssh_exec(plan.target_ip, plan.rollback_cmds)
    log_event("admin", "remediation.rollback.done", plan.target_ip,
              {"output_tail": out[-400:]})
    return out
