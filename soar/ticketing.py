"""
Ticket creation + SLA timers + escalation + auto-suggested fixes.

After a scan:
  * open a ticket for each high-priority CVE (KEV, critical, ML risk >= 70,
    or on the team's CVE watchlist). Unconfirmed version matches get a ticket
    only when the CVE is on the watchlist (title tagged [unconfirmed])
  * open a ticket for each default credential and each clear-text login service
  * attach an auto-suggested remediation playbook (soar/playbooks.py) to every
    ticket, so the analyst only confirms it
  * resolve tickets whose finding disappeared on the re-scan (verified fixed)
  * escalate tickets that are past their SLA
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from common.db import get_service_client
from common.audit import log_event
from common.notify import notify
from ml.features import WATCHLIST_REASON
from . import playbooks
from .remediation import os_family

# SLA windows (hours) by severity
SLA_HOURS = {"critical": 24, "high": 72, "medium": 168, "low": 336, "info": 720}
# a CVE with an ML risk score at or above this gets a ticket
PRIORITY_RISK = 70


def _sla_due(severity: str) -> str:
    hrs = SLA_HOURS.get(severity, 168)
    return (datetime.now(timezone.utc) + timedelta(hours=hrs)).isoformat()


def _insert_ticket(client, row: dict) -> bool:
    try:
        client.table("tickets").insert(row).execute()
        return True
    except Exception:
        # DB without the v2 suggested_action column
        row.pop("suggested_action", None)
        try:
            client.table("tickets").insert(row).execute()
            return True
        except Exception:
            return False


def _open_ticket_titles(client) -> set[str]:
    rows = (client.table("tickets").select("title,status")
            .neq("status", "resolved").neq("status", "rejected").execute().data)
    return {r["title"] for r in rows}


def open_tickets_for_scan(host_results: list[dict] | None = None) -> int:
    """Create tickets for new high-priority findings. Returns count created."""
    client = get_service_client()
    if not client:
        return 0

    services = {s["id"]: s for s in client.table("services").select("*").execute().data}
    asset_rows = client.table("assets").select("id,ip,os_guess").execute().data
    asset_os = {a["id"]: os_family(a.get("os_guess")) for a in asset_rows}
    asset_ip = {a["id"]: a.get("ip") for a in asset_rows}
    vulns = client.table("vulnerabilities").select("*").eq("status", "open").execute().data
    created = 0

    # ---- CVE tickets ---------------------------------------------------------
    for v in vulns:
        watched = WATCHLIST_REASON in (v.get("ml_reasons") or [])
        unconfirmed = v.get("confidence") == "version-unconfirmed"
        priority = (v.get("in_kev") or (v.get("severity") == "critical")
                    or (v.get("ml_risk_score") or 0) >= PRIORITY_RISK or watched)
        # an unconfirmed match ("this version MAY be affected") only gets a
        # ticket when the team asked for this CVE on the watchlist
        if not priority or (unconfirmed and not watched):
            continue
        existing = client.table("tickets").select("id").eq("vuln_id", v["id"]).execute().data
        if existing:
            continue
        svc = services.get(v.get("service_id")) or {}
        sev = v.get("severity") or "medium"
        where = f":{svc['port']}" if svc.get("port") else ""
        ip = asset_ip.get(v.get("asset_id"))
        title = f"{v['cve_id']} on {svc.get('service_name') or 'service'}{where}" + \
                (" [KEV]" if v.get("in_kev") else "") + \
                (" [unconfirmed]" if unconfirmed else "") + (f" ({ip})" if ip else "")
        description = (v.get("description") or "")[:500]
        if unconfirmed:
            description = ("On the CVE watchlist. The installed version could not be confirmed as "
                           "affected: check the version on the host before fixing. " + description)[:500]
        if _insert_ticket(client, {
            "vuln_id": v["id"], "asset_id": v["asset_id"], "title": title,
            "description": description,
            "severity": sev, "status": "open", "sla_due_at": _sla_due(sev),
            "suggested_action": playbooks.suggest(svc, cve=v, os=asset_os.get(v["asset_id"], "linux")),
        }):
            created += 1

    # ---- default-credential + clear-text service tickets ----------------------
    if host_results:
        titles = _open_ticket_titles(client)
        assets = {a["ip"]: a["id"] for a in
                  client.table("assets").select("id,ip").execute().data}
        for h in host_results:
            asset_id = assets.get(h["ip"])
            if not asset_id or not h.get("scan_ok", True):
                continue
            by_port = {s["port"]: s for s in h.get("services", [])}
            hos = os_family(h.get("os_guess"))
            for c in h.get("default_creds", []):
                title = f"Default credential '{c['username']}' on {c['service']}:{c['port']} ({h['ip']})"
                if title in titles:
                    continue
                if _insert_ticket(client, {
                    "asset_id": asset_id, "title": title, "severity": "critical",
                    "description": "A well-known default password is still accepted.",
                    "status": "open", "sla_due_at": _sla_due("critical"),
                    "suggested_action": playbooks.suggest(
                        by_port.get(c["port"]), default_cred_user=c["username"], os=hos),
                }):
                    created += 1
                    titles.add(title)
            for s in h.get("services", []):
                if (s.get("service_name") or "").lower() not in playbooks.CLEARTEXT_SERVICES:
                    continue
                title = f"Clear-text service {s['service_name']}:{s['port']} ({h['ip']})"
                if title in titles:
                    continue
                if _insert_ticket(client, {
                    "asset_id": asset_id, "title": title, "severity": "high",
                    "description": "Remote-login service sends credentials unencrypted.",
                    "status": "open", "sla_due_at": _sla_due("high"),
                    "suggested_action": playbooks.suggest(s, os=hos),
                }):
                    created += 1
                    titles.add(title)
            # risky services reachable from the network (RDP, SMB, DBs, backdoors)
            for s in h.get("services", []):
                port = s.get("port")
                what = playbooks.BACKDOOR_PORTS.get(port) or playbooks.EXPOSED_ADMIN_PORTS.get(port)
                if not what:
                    continue
                title = f"Exposed {what} :{port} ({h['ip']})"
                if title in titles:
                    continue
                sev = "critical" if port in playbooks.BACKDOOR_PORTS else "high"
                if _insert_ticket(client, {
                    "asset_id": asset_id, "title": title, "severity": sev,
                    "description": f"{what} is reachable from the network on port {port}.",
                    "status": "open", "sla_due_at": _sla_due(sev),
                    "suggested_action": playbooks.suggest(s, os=hos),
                }):
                    created += 1
                    titles.add(title)

    if created:
        log_event("engine", "tickets.created", "", {"count": created})
    return created


_PORT_IP = re.compile(r":(\d+) \(([^)]+)\)$")


def resolve_by_rescan(host_results: list[dict] | None) -> int:
    """
    Close host-level tickets (exposed port / clear-text service / default
    credential) when the latest scan of that host no longer shows the problem.
    Only hosts whose port scan really finished in this scan are judged, so a
    partial, failed or timed-out scan never closes tickets.
    """
    client = get_service_client()
    if not client or not host_results:
        return 0
    judged = [h for h in host_results if h.get("scan_ok", True)]
    open_ports = {h["ip"]: {s["port"] for s in h.get("services", [])} for h in judged}
    cred_ports = {h["ip"]: {c["port"] for c in h.get("default_creds", [])} for h in judged}
    n = 0
    for t in (client.table("tickets").select("id,title,status,vuln_id")
              .neq("status", "resolved").neq("status", "rejected").execute().data):
        if t.get("vuln_id"):
            continue  # CVE tickets are handled by resolve_fixed()
        m = _PORT_IP.search(t.get("title") or "")
        if not m:
            continue
        port, ip = int(m.group(1)), m.group(2)
        if ip not in open_ports:
            continue
        gone = port not in open_ports[ip]
        if (t["title"].startswith("Default credential") and port not in cred_ports[ip]):
            gone = True
        if gone:
            client.table("tickets").update({"status": "resolved"}).eq("id", t["id"]).execute()
            n += 1
    if n:
        log_event("engine", "tickets.resolved_by_rescan", "", {"count": n, "kind": "host-level"})
    return n


def resolve_fixed() -> int:
    """Close CVE tickets whose vulnerability no longer appears (re-scan verified)."""
    client = get_service_client()
    if not client:
        return 0
    fixed = {v["id"] for v in client.table("vulnerabilities").select("id")
             .eq("status", "remediated").execute().data}
    if not fixed:
        return 0
    n = 0
    for t in (client.table("tickets").select("id,vuln_id,status")
              .neq("status", "resolved").neq("status", "rejected").execute().data):
        if t.get("vuln_id") in fixed:
            client.table("tickets").update({"status": "resolved"}).eq("id", t["id"]).execute()
            n += 1
    if n:
        log_event("engine", "tickets.resolved_by_rescan", "", {"count": n})
    return n


def escalate_overdue() -> int:
    """Mark tickets past SLA as escalated + notify. Returns count escalated."""
    client = get_service_client()
    if not client:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    overdue = (client.table("tickets").select("*")
               .lt("sla_due_at", now).eq("escalated", False)
               .neq("status", "resolved").neq("status", "rejected").execute().data)
    for t in overdue:
        client.table("tickets").update(
            {"escalated": True, "status": "escalated"}).eq("id", t["id"]).execute()
        notify(client, "high", "SLA breached",
               f"Ticket '{t['title']}' is past its SLA.", "/tickets")
    if overdue:
        log_event("engine", "tickets.escalated", "", {"count": len(overdue)})
    return len(overdue)
