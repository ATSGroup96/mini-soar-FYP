"""
Encrypted + signed uplink of scan results to the cloud (Supabase), with an
offline fallback to a local JSON store.

Every result bundle is HMAC-signed (common.crypto.sign_payload) so a receiver
can prove it came from the trusted scanner. The raw bundle is also stored
AES-256-GCM encrypted on disk for the tamper-evident record. Structured rows
are then upserted into the Supabase tables the dashboard reads.

Rogue / shadow-IT detection happens here: a freshly discovered asset that is
not already marked is_authorized is flagged is_rogue=true and raises an alert.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from common.db import get_service_client
from common.crypto import encrypt_json, sign_payload
from common.audit import log_event
from common import syslog_logger as slog

_OFFLINE_DIR = Path("./data/offline_results")


def _store_offline(bundle: dict) -> str:
    _OFFLINE_DIR.mkdir(parents=True, exist_ok=True)
    enc = encrypt_json(bundle)                 # AES-256-GCM at rest
    sig = sign_payload(json.dumps(bundle, separators=(",", ":")).encode())
    fname = _OFFLINE_DIR / f"scan_{int(time.time())}.enc.json"
    fname.write_text(json.dumps({"sig": sig, "ciphertext": enc}), encoding="utf-8")
    return str(fname)


def push_scan(scan_meta: dict, host_results: list[dict]) -> dict:
    """
    scan_meta  : {scope, started_at, finished_at, host_count, status}
    host_results: list of per-host dicts produced by the engine.
    Returns a small summary dict.
    """
    bundle = {"scan": scan_meta, "hosts": host_results}

    # 1) always keep an encrypted+signed local copy
    offline_path = _store_offline(bundle)

    client = get_service_client()
    if client is None:
        log_event("engine", "uplink.offline", scan_meta.get("scope", ""),
                  {"stored": offline_path, "hosts": len(host_results)})
        slog.send("scan stored offline (Supabase not configured)", slog.NOTICE)
        return {"mode": "offline", "path": offline_path,
                "rogue": sum(1 for h in host_results if h.get("is_rogue"))}

    # 2) create the scan row
    scan_row = client.table("scans").insert({
        "scope": scan_meta.get("scope", ""),
        "started_at": scan_meta.get("started_at"),
        "finished_at": scan_meta.get("finished_at"),
        "host_count": scan_meta.get("host_count", len(host_results)),
        "status": "completed",
        "summary": scan_meta.get("summary", {}),
    }).execute()
    scan_id = scan_row.data[0]["id"]

    rogue_count = 0
    for h in host_results:
        asset_id = _upsert_asset(client, h)
        if h.get("is_rogue"):
            rogue_count += 1
        if h.get("is_rogue") and h.get("_new_asset"):
            # alert once, when an unauthorized device first appears
            _notify(client, "high", "Rogue / unknown device",
                    f"{h['ip']} ({h.get('mac') or 'no-mac'}) appeared and is "
                    f"not on the authorized list.", "/assets")
        svc_id_by_port: dict[int, str] = {}
        for svc in h.get("services", []):
            sid = _insert_service(client, asset_id, scan_id, svc)
            if sid:
                svc_id_by_port[svc.get("port")] = sid
        _close_missing_services(client, asset_id, set(svc_id_by_port))
        if h.get("tls") is not None:
            # keep only the latest certificate per port (no duplicates per scan)
            try:
                client.table("tls_certs").delete().eq("asset_id", asset_id).execute()
            except Exception:
                pass
        for cert in h.get("tls", []):
            _insert_tls(client, asset_id, cert)
        seen_vulns: set[tuple[str, str | None]] = set()
        for v in h.get("vulnerabilities", []):
            sid = svc_id_by_port.get(v.get("port"))
            _insert_vuln(client, asset_id, sid, v)
            seen_vulns.add((v["cve_id"], sid))
        _resolve_missing_vulns(client, asset_id, seen_vulns)

        # roll up asset risk from the scan's ML scoring
        if h.get("risk_score") is not None:
            client.table("assets").update({
                "risk_score": h.get("risk_score"),
                "risk_grade": h.get("risk_grade"),
            }).eq("id", asset_id).execute()

    sig = sign_payload(json.dumps(bundle, separators=(",", ":")).encode())
    log_event("engine", "uplink.cloud", scan_meta.get("scope", ""),
              {"scan_id": scan_id, "hosts": len(host_results),
               "rogue": rogue_count, "sig": sig["X-Soar-Signature"][:16]})
    slog.send(f"scan uploaded: {len(host_results)} hosts, {rogue_count} rogue",
              slog.NOTICE)
    return {"mode": "cloud", "scan_id": scan_id, "rogue": rogue_count}


def _upsert_asset(client, h: dict) -> str:
    ip, mac = h["ip"], h.get("mac")
    # look up existing by ip (+mac)
    q = client.table("assets").select("id,is_authorized").eq("ip", ip)
    existing = q.execute().data
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    is_rogue = not (existing and existing[0].get("is_authorized"))
    h["is_rogue"] = is_rogue

    payload = {
        "ip": ip, "mac": mac, "hostname": h.get("hostname"),
        "os_guess": h.get("os_guess"), "os_accuracy": h.get("os_accuracy"),
        "last_seen": now, "is_rogue": is_rogue,
    }
    h["_new_asset"] = not existing
    if existing:
        client.table("assets").update(payload).eq("id", existing[0]["id"]).execute()
        return existing[0]["id"]
    payload["first_seen"] = now
    row = client.table("assets").insert(payload).execute()
    return row.data[0]["id"]


def _insert_service(client, asset_id: str, scan_id: str, svc: dict) -> str | None:
    """Upsert one row per (asset, port, protocol) so re-scans never duplicate."""
    payload = {
        "asset_id": asset_id, "scan_id": scan_id,
        "port": svc["port"], "protocol": svc.get("protocol", "tcp"),
        "state": svc.get("state", "open"),
        "service_name": svc.get("service_name"), "product": svc.get("product"),
        "version": svc.get("version"), "cpe": svc.get("cpe"),
        "banner": svc.get("banner"),
        "has_default_cred": svc.get("has_default_cred", False),
    }
    try:
        res = client.table("services").upsert(
            payload, on_conflict="asset_id,port,protocol").execute()
    except Exception:
        # older DB without the unique index: fall back to update-or-insert
        found = (client.table("services").select("id").eq("asset_id", asset_id)
                 .eq("port", svc["port"]).eq("protocol", payload["protocol"])
                 .execute().data)
        if found:
            client.table("services").update(payload).eq("id", found[0]["id"]).execute()
            return found[0]["id"]
        res = client.table("services").insert(payload).execute()
    return res.data[0]["id"] if res.data else None


def _close_missing_services(client, asset_id: str, open_ports: set) -> None:
    """Ports seen earlier but not in this scan are now closed (change detection)."""
    try:
        rows = (client.table("services").select("id,port,state")
                .eq("asset_id", asset_id).execute().data)
        for r in rows:
            if r["port"] not in open_ports and r.get("state") != "closed":
                client.table("services").update({"state": "closed"}).eq("id", r["id"]).execute()
                log_event("engine", "change.port_closed", asset_id, {"port": r["port"]})
    except Exception:
        pass


def _resolve_missing_vulns(client, asset_id: str, seen: set) -> None:
    """An open vuln that no longer shows up has been fixed -> mark remediated."""
    try:
        rows = (client.table("vulnerabilities").select("id,cve_id,service_id,status")
                .eq("asset_id", asset_id).execute().data)
        for r in rows:
            key = (r["cve_id"], r.get("service_id"))
            if r.get("status") == "open" and key not in seen:
                client.table("vulnerabilities").update(
                    {"status": "remediated"}).eq("id", r["id"]).execute()
            elif r.get("status") == "remediated" and key in seen:
                # it came back (fix rolled back / regression) -> reopen
                client.table("vulnerabilities").update(
                    {"status": "open"}).eq("id", r["id"]).execute()
    except Exception:
        pass


def _insert_vuln(client, asset_id: str, service_id, v: dict) -> None:
    row = {
        "asset_id": asset_id, "service_id": service_id,
        "cve_id": v["cve_id"], "cvss_score": v.get("cvss_score"),
        "cvss_vector": v.get("cvss_vector"), "severity": v.get("severity"),
        "epss_score": v.get("epss_score"),
        "epss_percentile": v.get("epss_percentile"),
        "in_kev": v.get("in_kev", False), "kev_due_date": v.get("kev_due_date"),
        "ml_risk_score": v.get("ml_risk_score"),
        "ml_reasons": v.get("ml_reasons", []),
        "confidence": v.get("confidence", "version-confirmed"),
        "description": (v.get("description") or "")[:2000],
        # status is left alone on re-scan so analyst decisions
        # (accepted / false_positive) survive; new rows default to 'open'
    }
    try:
        client.table("vulnerabilities").upsert(
            row, on_conflict="asset_id,cve_id,service_id").execute()
    except Exception:
        # DB without the v2 'confidence' column: retry without it
        row.pop("confidence", None)
        try:
            client.table("vulnerabilities").upsert(
                row, on_conflict="asset_id,cve_id,service_id").execute()
        except Exception:
            pass  # a transient error should not abort the whole scan


def _insert_tls(client, asset_id: str, cert: dict) -> None:
    client.table("tls_certs").insert({
        "asset_id": asset_id, "port": cert["port"],
        "subject": cert.get("subject"), "issuer": cert.get("issuer"),
        "not_before": cert.get("not_before"), "not_after": cert.get("not_after"),
        "days_to_expiry": cert.get("days_to_expiry"),
        "is_self_signed": cert.get("is_self_signed"),
        "is_expired": cert.get("is_expired"),
        "weak_sig_alg": cert.get("weak_sig_alg"),
        "tls_version": cert.get("tls_version"),
    }).execute()


def _notify(client, level: str, title: str, body: str, link: str) -> None:
    try:
        client.table("notifications").insert({
            "level": level, "title": title, "body": body, "link": link,
        }).execute()
    except Exception:
        pass
