"""
Playbook selection — maps a finding to the remediation action to suggest.

The agent never invents commands: it picks one of the three tested playbooks in
soar/remediation.py (block_port, stop_service, disable_account) and fills in the
parameters from the scan. The suggestion is stored on the ticket so the analyst
only has to confirm it; execution still needs admin approval + TOTP.

Rules (first match wins):
  1. a login service still accepts a default password     -> disable_account
     (anonymous FTP has no account to lock                 -> block_port)
  2. clear-text remote-login services (telnet, rsh, ...)  -> stop_service
  3. known backdoor / remote-exec ports                    -> block_port
  4. databases / admin services exposed to the network     -> block_port
  5. any other vulnerable service                          -> block_port
     (a compensating control until the software is patched)
"""
from __future__ import annotations

# nmap service name -> init/inetd service name used by stop_service
CLEARTEXT_SERVICES = {
    "telnet": "telnet", "shell": "shell", "login": "login", "exec": "exec",
    "rsh": "shell", "rlogin": "login", "rexec": "exec",
}
# ports where blocking is the right first response
BACKDOOR_PORTS = {1524: "bind shell (ingreslock)", 6200: "vsftpd backdoor shell",
                  6667: "UnrealIRCd backdoor", 3632: "distccd remote exec",
                  1099: "Java RMI registry", 8787: "Ruby DRb remote exec"}
EXPOSED_ADMIN_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                       27017: "MongoDB", 6379: "Redis", 5900: "VNC",
                       2049: "NFS", 111: "rpcbind", 6000: "X11",
                       # Windows remote-access / file-sharing surface
                       3389: "Remote Desktop (RDP)", 445: "SMB file sharing",
                       139: "NetBIOS session", 135: "MS-RPC endpoint mapper",
                       5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)"}
# nmap service name -> Windows service name used by stop_service
WINDOWS_SERVICES = {"telnet": "TlntSvr"}
# product/version combinations that are themselves a backdoor
BACKDOORED_PRODUCTS = {("vsftpd", "2.3.4"), ("unrealircd", "3.2.8.1")}


def _action(action_type: str, reason: str, **params) -> dict:
    return {"action_type": action_type, "params": params, "reason": reason}


def suggest(service: dict | None, cve: dict | None = None,
            default_cred_user: str | None = None, os: str = "linux") -> dict | None:
    """Return {action_type, params, reason} or None when no port/service is known.
    `os` ('linux' | 'windows') is copied into the params so the right playbook runs."""
    out = _suggest(service, cve, default_cred_user, os)
    if out:
        out["params"]["os"] = os
    return out


def _suggest(service, cve, default_cred_user, os):
    svc = service or {}
    port = svc.get("port")
    name = (svc.get("service_name") or "").lower()
    product = (svc.get("product") or "").lower()
    version = (svc.get("version") or "").strip()

    if default_cred_user:
        if default_cred_user.lower() in ("anonymous", "ftp") and port:
            return _action("block_port", f"anonymous login allowed on {name or 'service'}:{port}",
                           port=int(port), proto="tcp")
        return _action("disable_account",
                       f"account '{default_cred_user}' still uses a default password",
                       username=default_cred_user)

    if name in CLEARTEXT_SERVICES:
        target = (WINDOWS_SERVICES.get(name) if os == "windows" else CLEARTEXT_SERVICES[name])
        if target:
            return _action("stop_service", f"{name} sends credentials in clear text",
                           service=target, port=int(port) if port else None)

    if port is None:
        return None
    port = int(port)
    if port == 22:
        # the engine manages hosts over SSH, so port 22 is never blocked;
        # an SSH flaw needs a software update (manual / future patch playbook)
        return None

    for prod, ver in BACKDOORED_PRODUCTS:
        if prod in product.replace(" ", "") and version.startswith(ver):
            return _action("block_port", f"{svc.get('product')} {version} is a known backdoored build",
                           port=port, proto="tcp")
    if port in BACKDOOR_PORTS:
        return _action("block_port", f"{BACKDOOR_PORTS[port]} exposed", port=port, proto="tcp")
    if port in EXPOSED_ADMIN_PORTS:
        return _action("block_port", f"{EXPOSED_ADMIN_PORTS[port]} reachable from the network",
                       port=port, proto="tcp")
    if cve:
        return _action("block_port",
                       f"{cve.get('cve_id')} on {name or 'service'}:{port} — block until patched",
                       port=port, proto="tcp")
    return None
