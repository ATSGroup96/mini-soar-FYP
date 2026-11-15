"""
Default-credential check (defensive hygiene, lab-only).

Purpose: flag devices in YOUR OWN authorized lab that still have well-known
factory/default passwords — a standard CAASM finding. It is NOT a brute-forcer:
it tries only a tiny, curated list of vendor-documented defaults, one quick
attempt each, exclusively against in-scope hosts, and records every attempt in
the tamper-evident audit log.

Scope rules enforced here:
  * assert_in_scope() on every host before any connection
  * global authorization gate via filter path in the engine
  * hard caps: <= len(DEFAULT_CREDS) attempts per service, 1 connection each
  * generous timeouts, no retries, no password lists, no lockout risk tuning
"""
from __future__ import annotations

from dataclasses import dataclass

from common.allowlist import assert_in_scope
from common.audit import log_event
from common import syslog_logger as slog

# Small set of PUBLICLY DOCUMENTED defaults commonly shipped by test images and
# appliances. Deliberately short — this detects "left on factory default", it
# does not guess user passwords.
DEFAULT_CREDS: list[tuple[str, str]] = [
    ("msfadmin", "msfadmin"),   # Metasploitable 2
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("guest", "guest"),
]

CONNECT_TIMEOUT = 4


@dataclass
class CredFinding:
    ip: str
    port: int
    service: str
    username: str
    password: str
    note: str = "Default/weak credential accepted"


def _check_ssh(ip: str, port: int) -> CredFinding | None:
    try:
        import paramiko
    except Exception:
        return None
    for user, pwd in DEFAULT_CREDS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, port=port, username=user, password=pwd,
                           timeout=CONNECT_TIMEOUT, allow_agent=False,
                           look_for_keys=False, banner_timeout=CONNECT_TIMEOUT)
            # success = device accepts a known default. Close immediately.
            client.close()
            return CredFinding(ip, port, "ssh", user, pwd)
        except paramiko.AuthenticationException:
            continue
        except Exception:
            break  # service unreachable / not really SSH -> stop
        finally:
            try:
                client.close()
            except Exception:
                pass
    return None


def _check_ftp(ip: str, port: int) -> CredFinding | None:
    from ftplib import FTP, error_perm
    # anonymous first — a very common misconfig
    candidates = [("anonymous", "anonymous@")] + DEFAULT_CREDS
    for user, pwd in candidates:
        try:
            ftp = FTP()
            ftp.connect(ip, port, timeout=CONNECT_TIMEOUT)
            ftp.login(user, pwd)
            ftp.quit()
            return CredFinding(ip, port, "ftp", user, pwd)
        except error_perm:
            continue
        except Exception:
            break
    return None


def _check_http_basic(ip: str, port: int) -> CredFinding | None:
    """
    HTTP Basic-auth check, in two steps:
      1. ask for the page with NO password. Only a page that answers
         "401 + WWW-Authenticate: Basic" is password-protected; anything else
         (public page, login form, redirect) is skipped, so a normal website is
         never reported as "accepts admin/admin".
      2. try each default pair; the first one that is no longer refused
         (not 401/403) is the finding.
    """
    import requests
    from requests.auth import HTTPBasicAuth
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    opts = {"timeout": CONNECT_TIMEOUT, "verify": False, "allow_redirects": False}
    try:
        first = requests.get(url, **opts)
    except Exception:
        return None  # not reachable / not HTTP
    challenge = first.headers.get("WWW-Authenticate", "")
    if first.status_code != 401 or "basic" not in challenge.lower():
        return None
    for user, pwd in DEFAULT_CREDS:
        try:
            r = requests.get(url, auth=HTTPBasicAuth(user, pwd), **opts)
        except Exception:
            break
        if r.status_code not in (401, 403) and r.status_code < 500:
            return CredFinding(ip, port, "http", user, pwd)
    return None


_CHECKERS = {
    "ssh": _check_ssh, "ftp": _check_ftp,
    "http": _check_http_basic, "https": _check_http_basic,
}


def check_host(ip: str, services) -> list[CredFinding]:
    """
    Run default-cred checks for the services on one in-scope host.
    `services` is a list of ServiceInfo (from port_scan).
    """
    assert_in_scope(ip)
    findings: list[CredFinding] = []
    for svc in services:
        name = (svc.service_name or "").lower()
        checker = _CHECKERS.get(name)
        if not checker:
            continue
        log_event("engine", "defaultcred.check", f"{ip}:{svc.port}",
                  {"service": name})
        finding = checker(ip, svc.port)
        if finding:
            findings.append(finding)
            log_event("engine", "defaultcred.found", f"{ip}:{svc.port}",
                      {"service": name, "username": finding.username})
            slog.send(
                f"DEFAULT CREDENTIAL on {ip}:{svc.port} ({name}) "
                f"user={finding.username}", slog.ALERT)
    return findings
