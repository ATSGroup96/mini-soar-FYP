"""
Shared honeypot event recorder.

Every decoy hit is: enriched with IP reputation, written to the tamper-evident
audit log, forwarded to the SIEM over syslog, and (when configured) stored in
Supabase + raised as a notification. Honeypots are PURELY defensive — they only
record attempts and never grant access.
"""
from __future__ import annotations

from common.db import get_service_client
from common.audit import log_event
from common import syslog_logger as slog
from .ip_reputation import lookup


def record(service: str, src_ip: str, src_port: int | None = None,
           username: str | None = None, password: str | None = None,
           path_or_cmd: str | None = None) -> dict:
    rep = lookup(src_ip)
    event = {
        "service": service, "src_ip": src_ip, "src_port": src_port,
        "username_tried": username, "password_tried": password,
        "path_or_cmd": path_or_cmd,
        "abuse_score": rep["abuse_score"], "otx_pulses": rep["otx_pulses"],
        "reputation": rep["reputation"],
    }

    log_event("honeypot", f"honeypot.{service}", src_ip,
              {"user": username, "reputation": rep["reputation"]})
    sev = slog.ALERT if rep["reputation"] == "malicious" else slog.WARNING
    slog.send(f"HONEYPOT {service} hit from {src_ip} "
              f"user={username} rep={rep['reputation']}", sev)

    client = get_service_client()
    if client:
        try:
            client.table("honeypot_events").insert(event).execute()
            if rep["reputation"] in ("malicious", "suspicious"):
                client.table("notifications").insert({
                    "level": "high" if rep["reputation"] == "malicious" else "medium",
                    "title": f"Honeypot hit ({service})",
                    "body": f"{src_ip} tried {service} — reputation {rep['reputation']}",
                    "link": "/honeypot",
                }).execute()
        except Exception:
            pass
    return event
