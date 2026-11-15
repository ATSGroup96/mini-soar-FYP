"""
Patch / fix verification — proves a remediation actually worked.

  * block_port      -> the port no longer accepts TCP connections from the engine
  * stop_service    -> its port is closed (if known), else the process is gone
  * disable_account -> `passwd -S` reports the account as locked (L / LK);
                       on Windows, Get-LocalUser reports Enabled = False
Windows targets are recognised by params["os"] == "windows".
"""
from __future__ import annotations

import socket

from common.allowlist import assert_in_scope
from common.audit import log_event

# common service -> port, for stop_service when the request has no port
SERVICE_PORTS = {"termservice": 3389, "lanmanserver": 445, "tlntsvr": 23,
                 "telnet": 23, "ftp": 21, "vsftpd": 21, "proftpd": 2121,
                 "shell": 514, "rsh": 514, "login": 513, "rlogin": 513,
                 "exec": 512, "rexec": 512, "distcc": 3632, "distccd": 3632,
                 "mysql": 3306, "postgresql": 5432, "vnc": 5900}


def _port_open(ip: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def verify_fix(asset_ip: str, params: dict, action_type: str = "block_port") -> bool:
    """Return True when the fix is confirmed on the live host."""
    assert_in_scope(asset_ip)
    fixed = False
    detail: dict = {"action": action_type}

    windows = params.get("os") == "windows"
    if action_type == "disable_account":
        from .remediation import run_remote, PRE, _ps
        user = params.get("username", "")
        try:
            if windows:
                res = run_remote(asset_ip, [_ps(f"(Get-LocalUser -Name '{user}').Enabled")], check=False)
                out = res[0][2] if res else ""
                fixed = out.strip().lower().endswith("false")
                detail["enabled"] = out.strip()[:40]
            else:
                res = run_remote(asset_ip, [PRE + f"sudo passwd -S {user}"], check=False)
                out = res[0][2] if res else ""
                fields = out.split()
                fixed = len(fields) > 1 and fields[1] in ("L", "LK")
                detail["passwd_status"] = out[:80]
        except Exception as e:
            detail["error"] = str(e)[:200]
    else:
        port = params.get("port")
        if port in (None, "") and action_type == "stop_service":
            port = SERVICE_PORTS.get((params.get("service") or "").lower())
        if port in (None, ""):
            if action_type == "stop_service":
                from .remediation import run_remote, _ps
                svc = params.get("service", "")
                try:
                    cmd = (_ps(f"if ((Get-Service -Name '{svc}').Status -eq 'Running') "
                               f"{{ 'RUNNING' }} else {{ 'STOPPED' }}") if windows
                           else f"pgrep -x {svc} >/dev/null && echo RUNNING || echo STOPPED")
                    res = run_remote(asset_ip, [cmd], check=False)
                    fixed = bool(res) and "STOPPED" in res[0][2]
                except Exception as e:
                    detail["error"] = str(e)[:200]
            else:
                detail["reason"] = "no port to probe"
        else:
            still_open = _port_open(asset_ip, int(port))
            fixed = not still_open
            detail.update({"port": int(port), "still_open": still_open})

    detail["fixed"] = fixed
    log_event("engine", "remediation.verify", asset_ip, detail)
    return fixed
