"""
One place that raises a dashboard notification.

A notification is a row in public.notifications (shown by the bell in the
dashboard, live through Supabase Realtime) and, when Web Push is set up, also a
push message to every subscribed browser (common/webpush.py).

Best-effort on purpose: a notification problem never breaks a scan, a
or a remediation.
"""
from __future__ import annotations

LEVELS = ("info", "low", "medium", "high", "critical")
# only these levels are worth interrupting someone with a push message
PUSH_LEVELS = ("medium", "high", "critical")


def notify(client, level: str, title: str, body: str = "", link: str = "/dashboard") -> dict:
    """Insert the notification and push it. Returns {"stored": bool, "push": {...}}."""
    out = {"stored": False, "push": {"sent": 0, "failed": 0, "removed": 0}}
    if client is None:
        return out
    if level not in LEVELS:
        level = "info"
    try:
        client.table("notifications").insert(
            {"level": level, "title": title, "body": body, "link": link}).execute()
        out["stored"] = True
    except Exception:
        pass
    if level in PUSH_LEVELS:
        try:
            from . import webpush
            out["push"] = webpush.send_to_all(client, title, body, link)
        except Exception:
            pass
    return out
