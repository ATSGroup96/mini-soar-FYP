"""
Shared honeypot event recorder.

Every decoy hit is: enriched with IP reputation, written to the tamper-evident
audit log, forwarded to the SIEM over syslog, and (when configured) stored in
Supabase. Honeypots are PURELY defensive — they only record attempts and never
grant access.

Alerts (dashboard notification + push):
  * a hit from a malicious / suspicious public address, and
  * ANY hit from inside the lab - no machine there has a reason to touch the
    decoy, so that is the strongest sign of an intruder or infected device.
Every hit is stored, but one source only raises one alert per service every
ALERT_EVERY_SECONDS, so a password-guessing run does not flood the dashboard.
"""
from __future__ import annotations

import threading
import time

from common.db import get_service_client
from common.audit import log_event
from common.notify import notify
from common import syslog_logger as slog
from .ip_reputation import lookup

ALERT_EVERY_SECONDS = 300
MAX_CRED = 256           # stored length of a tried username / password
MAX_PATH = 512           # stored length of a request line

_ALERT_LEVEL = {"malicious": "high", "suspicious": "medium", "internal": "medium"}
_last_alert: dict[tuple[str, str], float] = {}
_lock = threading.Lock()


def _trim(value, limit: int):
    return value if value is None else str(value)[:limit]


def _should_alert(src_ip: str, service: str) -> bool:
    now = time.monotonic()
    with _lock:
        last = _last_alert.get((src_ip, service))
        if last is not None and now - last < ALERT_EVERY_SECONDS:
            return False
        _last_alert[(src_ip, service)] = now
        if len(_last_alert) > 5000:       # forget the oldest half
            for key in sorted(_last_alert, key=_last_alert.get)[:2500]:
                del _last_alert[key]
        return True


def record(service: str, src_ip: str, src_port: int | None = None,
           username: str | None = None, password: str | None = None,
           path_or_cmd: str | None = None) -> dict:
    rep = lookup(src_ip)
    event = {
        "service": service, "src_ip": src_ip, "src_port": src_port,
        "username_tried": _trim(username, MAX_CRED),
        "password_tried": _trim(password, MAX_CRED),
        "path_or_cmd": _trim(path_or_cmd, MAX_PATH),
        "abuse_score": rep["abuse_score"], "otx_pulses": rep["otx_pulses"],
        "reputation": rep["reputation"],
    }

    log_event("honeypot", f"honeypot.{service}", src_ip,
              {"user": event["username_tried"], "reputation": rep["reputation"]})
    sev = slog.ALERT if rep["reputation"] == "malicious" else slog.WARNING
    slog.send(f"HONEYPOT {service} hit from {src_ip} "
              f"user={event['username_tried']} rep={rep['reputation']}", sev)

    client = get_service_client()
    if client:
        try:
            client.table("honeypot_events").insert(event).execute()
        except Exception:
            pass
        level = _ALERT_LEVEL.get(rep["reputation"])
        if level and _should_alert(src_ip, service):
            where = "a lab device" if rep["reputation"] == "internal" \
                else f"reputation {rep['reputation']}"
            notify(client, level, f"Honeypot hit ({service})",
                   f"{src_ip} touched the fake {service} service ({where}).", "/honeypot")
    return event


def reset_alert_throttle() -> None:
    """Forget which sources were alerted recently (used by the tests)."""
    with _lock:
        _last_alert.clear()
