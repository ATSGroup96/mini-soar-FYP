"""
Minimal RFC 3164 / RFC 5424-ish syslog forwarder to a SIEM (Wazuh / ELK).
Best-effort: never raises into the caller.
"""
from __future__ import annotations

import socket

from .config import get_settings

# syslog severities
EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG = range(8)
_FACILITY_LOCAL0 = 16


def send(message: str, severity: int = INFO, app: str = "mini-soar") -> None:
    s = get_settings()
    pri = _FACILITY_LOCAL0 * 8 + severity
    host = socket.gethostname()
    packet = f"<{pri}>{app}[{host}]: {message}".encode("utf-8", "replace")
    try:
        if s.syslog_proto.lower() == "tcp":
            with socket.create_connection((s.syslog_host, s.syslog_port), timeout=2) as sk:
                sk.sendall(packet + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
                sk.sendto(packet, (s.syslog_host, s.syslog_port))
    except OSError:
        pass  # SIEM may be down; do not break the scan/remediation flow
