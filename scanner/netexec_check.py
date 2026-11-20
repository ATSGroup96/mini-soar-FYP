"""
NetExec read-only posture checks for SMB, RDP and WinRM (Windows hosts, and
Samba on Linux).

NetExec is an attack tool (dos Santos 2026 uses it to break into an AD lab).
Mini-SOAR uses it DEFENSIVELY and READ-ONLY, to see what Nmap version matching
cannot: SMBv1, SMB signing, anonymous (null-session) shares, RDP Network Level
Authentication and WinRM over plain HTTP.

Read-only by construction (proposal: "its exploitation and credential-harvesting
modules are not used"):
  * the commands are built here from fixed templates, never from user input
  * assert_read_only() refuses any argument not on a short allow-list, so
    modules (-M), command execution (-x / -X), dumps (--sam / --lsa / --ntds),
    file transfer (--put-file / --get-file), spidering and every other action
    can never be passed, even by a future code change
  * the only login tried is the anonymous null session ('' / ''), which is the
    check itself; no password list, no guest, no real account
  * assert_in_scope() on the host first; one command at a time, with a timeout

Needs the NetExec binary (nxc). Missing = skipped, the scan still finishes.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from common.allowlist import assert_in_scope
from common.audit import log_event
from common import syslog_logger as slog

SMB_PORTS = (445, 139)
RDP_PORTS = (3389,)
WINRM_HTTP, WINRM_HTTPS = 5985, 5986

# every argument that may ever reach NetExec (besides the IP and port numbers)
_ALLOWED_ARGS = {"smb", "rdp", "winrm", "--port", "-u", "-p", "", "--shares", "--timeout", "5"}
_ALLOWED_PROTOCOLS = {"smb", "rdp", "winrm"}
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_WIN_PATHS = (r"tools\netexec\nxc.exe", r"tools\nxc\nxc.exe",
              os.path.expandvars(r"%USERPROFILE%\.local\bin\nxc.exe"),
              os.path.expandvars(r"%USERPROFILE%\pipx\venvs\netexec\Scripts\nxc.exe"))


class NotReadOnly(RuntimeError):
    """A NetExec command with a not-allowed argument was refused."""


def binary() -> str | None:
    env = (os.environ.get("NETEXEC_PATH", "") or "").strip().strip('"')
    if env and Path(env).exists():
        return env
    for name in ("nxc", "netexec", "/opt/netexec/bin/nxc"):
        found = shutil.which(name)
        if found:
            return found
    for p in _WIN_PATHS:
        if Path(p).exists():
            return str(Path(p).resolve())
    return None


def available() -> bool:
    return binary() is not None


def assert_read_only(argv: list[str], ip: str) -> None:
    """argv[0] = binary, argv[1] = protocol, argv[2] = ip, then allowed args only."""
    if len(argv) < 3 or argv[1] not in _ALLOWED_PROTOCOLS or argv[2] != ip:
        raise NotReadOnly(f"refused NetExec command {argv[1:3]!r}")
    rest = argv[3:]
    for i, a in enumerate(rest):
        if a in _ALLOWED_ARGS:
            continue
        if a.isdigit() and i > 0 and rest[i - 1] == "--port":
            continue
        raise NotReadOnly(f"refused NetExec argument {a!r} (read-only checks only)")
    # a login other than the anonymous null session is never tried
    for flag in ("-u", "-p"):
        if flag in rest:
            j = rest.index(flag)
            if j + 1 >= len(rest) or rest[j + 1] != "":
                raise NotReadOnly("only the anonymous null session may be tried")


def build_commands(nxc: str, ip: str, open_ports: set[int]) -> list[tuple[str, list[str]]]:
    cmds: list[tuple[str, list[str]]] = []
    smb = next((p for p in SMB_PORTS if p in open_ports), None)
    if smb:
        cmds.append(("smb-info", [nxc, "smb", ip, "--port", str(smb), "--timeout", "5"]))
        cmds.append(("smb-null", [nxc, "smb", ip, "--port", str(smb), "-u", "", "-p", "",
                                  "--shares", "--timeout", "5"]))
    if 3389 in open_ports:
        cmds.append(("rdp-info", [nxc, "rdp", ip, "--port", "3389", "--timeout", "5"]))
    if WINRM_HTTP in open_ports:
        cmds.append(("winrm-http", [nxc, "winrm", ip, "--port", str(WINRM_HTTP), "--timeout", "5"]))
    return cmds


def _clean(text: str) -> str:
    return _ANSI.sub("", text or "")


def _flag(text: str, name: str) -> bool | None:
    m = re.search(rf"\({re.escape(name)}:\s*(True|False)\)", text, re.IGNORECASE)
    return None if not m else m.group(1).lower() == "true"


def _finding(key: str, port: int, evidence: str) -> dict:
    from ml.finding_map import NETEXEC_CHECKS, severity_from_cvss
    title, cvss, why = NETEXEC_CHECKS[key]
    return {"source": "netexec", "finding_key": key, "title": title, "port": port,
            "cvss_score": cvss, "severity": severity_from_cvss(cvss), "cve_id": None,
            "description": why, "evidence": evidence.strip()[:500]}


def _banner(text: str) -> str:
    """The '[*] ...' line with OS / name / signing info (for the evidence)."""
    for line in text.splitlines():
        if "[*]" in line:
            return line.split("[*]", 1)[1].strip()
    return ""


def parse_smb_info(text: str, port: int) -> list[dict]:
    text = _clean(text)
    banner = _banner(text)
    out = []
    if _flag(text, "SMBv1") is True:
        out.append(_finding("netexec:smbv1-enabled", port, banner))
    if _flag(text, "signing") is False:
        out.append(_finding("netexec:smb-signing-not-required", port, banner))
    return out


def parse_smb_null(text: str, port: int) -> list[dict]:
    """Null-session login result + the share table that follows it."""
    text = _clean(text)
    out = []
    logged_in = any("[+]" in line and re.search(r"\\:?\s*$|\\:", line) for line in text.splitlines())
    if _flag(text, "Null Auth") is True:
        logged_in = True
    if logged_in:
        out.append(_finding("netexec:smb-null-session", port, "anonymous login accepted"))
    readable, writable = [], []
    in_table = False
    for line in text.splitlines():
        if re.search(r"\bShare\b\s+\bPermissions\b", line):
            in_table = True
            continue
        if not in_table or "-----" in line:
            continue
        m = re.search(r"\s(\S+)\s+((?:READ|WRITE)(?:,(?:READ|WRITE))?)\b", line)
        if m:
            share, perm = m.group(1), m.group(2)
            if share.upper() == "IPC$":
                continue                 # IPC$ is not a file share
            (writable if "WRITE" in perm else readable).append(share)
    if writable:
        out.append(_finding("netexec:smb-anonymous-share-write", port,
                            "writable without a password: " + ", ".join(writable[:10])))
    if readable:
        out.append(_finding("netexec:smb-anonymous-share-read", port,
                            "readable without a password: " + ", ".join(readable[:10])))
    return out


def parse_rdp(text: str, port: int = 3389) -> list[dict]:
    text = _clean(text)
    if _flag(text, "nla") is False:
        return [_finding("netexec:rdp-nla-disabled", port, _banner(text))]
    return []


def parse_winrm(text: str, port: int = WINRM_HTTP) -> list[dict]:
    text = _clean(text)
    if "[*]" in text or "WINRM" in text.upper():
        return [_finding("netexec:winrm-http", port, _banner(text) or "WinRM answered on HTTP")]
    return []


_PARSERS = {"smb-info": parse_smb_info, "smb-null": parse_smb_null,
            "rdp-info": parse_rdp, "winrm-http": parse_winrm}


def _port_of(argv: list[str]) -> int:
    return int(argv[argv.index("--port") + 1])


def check_host(ip: str, services) -> list[dict]:
    """Run the read-only NetExec checks for one in-scope host. Never raises."""
    assert_in_scope(ip)
    nxc = binary()
    if not nxc:
        return []
    ports = {getattr(s, "port", None) if not isinstance(s, dict) else s.get("port")
             for s in services}
    cmds = build_commands(nxc, ip, {p for p in ports if p is not None})
    if not cmds:
        return []
    findings: list[dict] = []
    env = dict(os.environ, NO_COLOR="1", TERM="dumb")
    for name, argv in cmds:
        try:
            assert_read_only(argv, ip)
        except NotReadOnly as e:
            log_event("engine", "netexec.refused", ip, {"error": str(e)})
            continue
        log_event("engine", "netexec.check", ip, {"check": name, "args": argv[1:]})
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env,
                                  encoding="utf-8", errors="replace")
        except Exception as e:
            log_event("engine", "netexec.error", ip, {"check": name, "error": str(e)[:200]})
            continue
        findings += _PARSERS[name](proc.stdout + "\n" + proc.stderr, _port_of(argv))
    log_event("engine", "netexec.finish", ip, {"findings": [f["finding_key"] for f in findings]})
    for f in findings:
        if f["severity"] in ("high", "critical"):
            slog.send(f"NETEXEC {f['severity'].upper()} on {ip}:{f['port']} {f['title']}", slog.ALERT)
    return findings
