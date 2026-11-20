"""
Encrypted + signed uplink of scan results to the cloud (Supabase), with an
offline fallback to a local store.

What happens to every scan bundle:
  1. it is stored on disk AES-256-GCM encrypted, together with an HMAC
     signature (data/offline_results/scan_<time>.enc.json). load_bundle()
     checks that signature again whenever a stored bundle is read back, so an
     edited or swapped file is rejected (verify_stored_bundles()).
  2. the structured rows are written to the Supabase tables the dashboard reads.

Also done here, because this is where "what we saw now" meets "what we knew":
  * rogue / shadow-IT detection - a device that is not marked is_authorized is
    flagged is_rogue and raises an alert the first time it appears
  * change detection - ports that opened or closed and software versions that
    changed since the last scan (table asset_changes + notifications)
  * re-scan verification - a finding that is gone is marked remediated
  * risk-trend tracking - one risk_history row per host and one for the whole
    network after every scan
  * CVE watchlist alerts

SAFETY: a host whose port scan failed or timed out (scan_ok = False) proves
nothing. For such a host nothing is closed, resolved or re-graded.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from common.db import get_service_client
from common.crypto import decrypt_json, encrypt_json, sign_payload, verify_signature
from common.audit import log_event
from common.notify import notify
from ml.features import WATCHLIST_REASON
from common import syslog_logger as slog

_OFFLINE_DIR = Path("./data/offline_results")


class BundleTampered(RuntimeError):
    """A stored scan bundle failed its signature / decryption check."""


def _canonical(bundle: dict) -> bytes:
    return json.dumps(bundle, separators=(",", ":")).encode()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------- stored bundles
def _store_offline(bundle: dict) -> str:
    _OFFLINE_DIR.mkdir(parents=True, exist_ok=True)
    enc = encrypt_json(bundle)                 # AES-256-GCM at rest
    sig = sign_payload(_canonical(bundle))
    fname = _OFFLINE_DIR / f"scan_{int(time.time())}.enc.json"
    n = 1
    while fname.exists():                      # two scans in the same second
        fname = _OFFLINE_DIR / f"scan_{int(time.time())}_{n}.enc.json"
        n += 1
    fname.write_text(json.dumps({"sig": sig, "ciphertext": enc}), encoding="utf-8")
    return str(fname)


def load_bundle(path) -> dict:
    """Decrypt a stored bundle and verify its HMAC signature.
    Raises BundleTampered if the file was changed or made with another key."""
    try:
        wrapper = json.loads(Path(path).read_text(encoding="utf-8"))
        sig, ciphertext = wrapper["sig"], wrapper["ciphertext"]
        bundle = decrypt_json(ciphertext)
    except Exception as e:
        raise BundleTampered(f"{Path(path).name}: cannot be decrypted ({type(e).__name__})")
    ok = verify_signature(_canonical(bundle), str(sig.get("X-Soar-Timestamp", "")),
                          str(sig.get("X-Soar-Signature", "")), max_skew_seconds=None)
    if not ok:
        raise BundleTampered(f"{Path(path).name}: signature does not match")
    return bundle


def verify_stored_bundles() -> dict:
    """Check every stored bundle. {"checked": n, "ok": n, "bad": [messages]}"""
    files = sorted(_OFFLINE_DIR.glob("scan_*.enc.json")) if _OFFLINE_DIR.exists() else []
    bad: list[str] = []
    for f in files:
        try:
            load_bundle(f)
        except BundleTampered as e:
            bad.append(str(e))
    result = {"checked": len(files), "ok": len(files) - len(bad), "bad": bad}
    if bad:
        log_event("engine", "bundle.verify_failed", "", {"bad": bad[:20]})
    return result


# ------------------------------------------------------------------ main upload
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
    changes = {"new_assets": 0, "ports_opened": 0, "ports_closed": 0,
               "versions_changed": 0, "inconclusive_hosts": 0, "watchlist_hits": 0}
    for h in host_results:
        asset_id = _upsert_asset(client, h)
        if h.get("is_rogue"):
            rogue_count += 1
        if h.get("_new_asset"):
            changes["new_assets"] += 1
            _record_change(client, asset_id, scan_id, "new_asset", None, {"ip": h["ip"]})
        if h.get("is_rogue") and h.get("_new_asset"):
            # alert once, when an unauthorized device first appears
            notify(client, "high", "Rogue / unknown device",
                   f"{h['ip']} ({h.get('mac') or 'no-mac'}) appeared and is "
                   f"not on the authorized list.", "/assets")

        if not h.get("scan_ok", True):
            # the port scan of this host failed or timed out: keep everything
            # we knew about it, close nothing, and say so
            changes["inconclusive_hosts"] += 1
            log_event("engine", "scan.host_inconclusive", h["ip"], {"scan_id": scan_id})
            notify(client, "medium", "Scan of a host did not finish",
                   f"{h['ip']}: the port scan failed or timed out. Nothing was "
                   f"closed for this host; scan it again.", "/assets")
            continue

        _sync_host(client, asset_id, scan_id, h, changes)

    _record_network_risk(client, scan_id)

    sig = sign_payload(_canonical(bundle))
    log_event("engine", "uplink.cloud", scan_meta.get("scope", ""),
              {"scan_id": scan_id, "hosts": len(host_results),
               "rogue": rogue_count, "changes": changes,
               "sig": sig["X-Soar-Signature"][:16]})
    slog.send(f"scan uploaded: {len(host_results)} hosts, {rogue_count} rogue",
              slog.NOTICE)
    return {"mode": "cloud", "scan_id": scan_id, "rogue": rogue_count,
            "changes": changes, "path": offline_path}


def _sync_host(client, asset_id: str, scan_id: str, h: dict, changes: dict) -> None:
    """Write one successfully scanned host: services, TLS, CVEs, risk, history."""
    first_scan = bool(h.get("_new_asset"))
    known = _known_services(client, asset_id)

    svc_id_by_port: dict[int, str] = {}
    for svc in h.get("services", []):
        sid = _insert_service(client, asset_id, scan_id, svc)
        if sid:
            svc_id_by_port[svc.get("port")] = sid
        if not first_scan:
            _detect_service_change(client, asset_id, scan_id, h["ip"], svc, known, changes)
    changes["ports_closed"] += _close_missing_services(
        client, asset_id, scan_id, set(svc_id_by_port.values()))

    if h.get("tls") is not None:
        # keep only the latest certificate per port (no duplicates per scan)
        try:
            client.table("tls_certs").delete().eq("asset_id", asset_id).execute()
        except Exception:
            pass
    for cert in h.get("tls", []):
        _insert_tls(client, asset_id, cert)

    existing = _known_vulns(client, asset_id)
    seen_vulns: set[tuple[str, str | None]] = set()
    for v in h.get("vulnerabilities", []):
        sid = svc_id_by_port.get(v.get("port"))
        key = (finding_id(v), sid)
        was = existing.get(key)
        _insert_vuln(client, asset_id, sid, v, was)
        seen_vulns.add(key)
        if _newly_watched(v, was):
            changes["watchlist_hits"] += 1
            log_event("engine", "watchlist.hit", h["ip"], {"cve": v.get("cve_id")})
            notify(client, "high", "Watchlisted CVE found",
                   f"{v['cve_id']} was found on {h['ip']}"
                   + (f" port {v['port']}" if v.get("port") else "") + ".",
                   "/vulnerabilities")
    _resolve_missing_vulns(client, existing, seen_vulns)

    # roll up asset risk from the scan's ML scoring + keep the trend
    if h.get("risk_score") is not None:
        client.table("assets").update({
            "risk_score": h.get("risk_score"),
            "risk_grade": h.get("risk_grade"),
        }).eq("id", asset_id).execute()
        _record_risk(client, scan_id, asset_id, h.get("risk_score"), h.get("risk_grade"),
                     open_vulns=len(h.get("vulnerabilities", [])),
                     kev_count=sum(1 for v in h.get("vulnerabilities", []) if v.get("in_kev")))


# ----------------------------------------------------------------------- assets
def _upsert_asset(client, h: dict) -> str:
    ip, mac = h["ip"], h.get("mac")
    existing = client.table("assets").select("id,is_authorized").eq("ip", ip).execute().data
    now = _now()

    is_rogue = not (existing and existing[0].get("is_authorized"))
    h["is_rogue"] = is_rogue
    h["_new_asset"] = not existing
    payload = {"ip": ip, "last_seen": now, "is_rogue": is_rogue}
    if h.get("scan_ok", True):
        payload.update({"mac": mac, "hostname": h.get("hostname"),
                        "os_guess": h.get("os_guess"), "os_accuracy": h.get("os_accuracy")})
    elif mac:
        payload["mac"] = mac                    # discovery still saw the device
    if existing:
        client.table("assets").update(payload).eq("id", existing[0]["id"]).execute()
        return existing[0]["id"]
    payload["first_seen"] = now
    row = client.table("assets").insert(payload).execute()
    return row.data[0]["id"]


# --------------------------------------------------------------------- services
def _known_services(client, asset_id: str) -> dict:
    """{(port, protocol): row} as stored before this scan."""
    try:
        rows = client.table("services").select("*").eq("asset_id", asset_id).execute().data
    except Exception:
        return {}
    return {(r["port"], r.get("protocol") or "tcp"): r for r in rows}


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


def _detect_service_change(client, asset_id, scan_id, ip, svc, known, changes) -> None:
    """Compare one open service with what the last scan stored."""
    port, proto = svc["port"], svc.get("protocol", "tcp")
    name = svc.get("service_name") or "service"
    before = known.get((port, proto))
    if before is None or before.get("state") == "closed":
        changes["ports_opened"] += 1
        detail = {"service": name, "product": svc.get("product"),
                  "version": svc.get("version"), "reopened": before is not None}
        _record_change(client, asset_id, scan_id, "port_opened", port, detail)
        log_event("engine", "change.port_opened", ip, {"port": port, **detail})
        notify(client, "medium", "New open port",
               f"{ip}: port {port}/{proto} ({name}) is open and was not before.", "/assets")
        return
    old = (before.get("product") or "", before.get("version") or "")
    new = (svc.get("product") or "", svc.get("version") or "")
    # only when both scans identified the software: an empty answer from nmap's
    # version probe is not a change
    if old != new and all(old) and all(new):
        changes["versions_changed"] += 1
        detail = {"service": name, "from": " ".join(old), "to": " ".join(new)}
        _record_change(client, asset_id, scan_id, "version_changed", port, detail)
        log_event("engine", "change.service_version", ip, {"port": port, **detail})
        notify(client, "low", "Software version changed",
               f"{ip}: port {port} changed from {detail['from']} to {detail['to']}.", "/assets")


def _close_missing_services(client, asset_id: str, scan_id: str, open_ids: set) -> int:
    """Ports seen earlier but not in this scan are now closed (change detection)."""
    closed = 0
    try:
        rows = (client.table("services").select("id,port,state")
                .eq("asset_id", asset_id).execute().data)
        for r in rows:
            if r["id"] not in open_ids and r.get("state") != "closed":
                client.table("services").update({"state": "closed"}).eq("id", r["id"]).execute()
                _record_change(client, asset_id, scan_id, "port_closed", r["port"], {})
                log_event("engine", "change.port_closed", asset_id, {"port": r["port"]})
                closed += 1
    except Exception:
        pass
    return closed


def _record_change(client, asset_id, scan_id, kind: str, port, detail: dict) -> None:
    """One row in asset_changes (migration 004). Skipped quietly on an older DB."""
    try:
        client.table("asset_changes").insert({
            "asset_id": asset_id, "scan_id": scan_id, "kind": kind,
            "port": port, "detail": detail or {},
        }).execute()
    except Exception:
        pass


# -------------------------------------------------------------- vulnerabilities
def finding_id(v: dict) -> str:
    """Identity of a finding: its check id (Nuclei template / NetExec check) or
    its CVE id. A CVE match from the version matcher uses the CVE id."""
    return str(v.get("finding_key") or v.get("cve_id") or "")


def _known_vulns(client, asset_id: str) -> dict:
    """{(finding id, service_id): row} as stored before this scan."""
    try:
        rows = (client.table("vulnerabilities")
                .select("id,cve_id,finding_key,service_id,status,ml_reasons")
                .eq("asset_id", asset_id).execute().data)
    except Exception:
        try:      # database before migration 006 (no finding_key column)
            rows = (client.table("vulnerabilities")
                    .select("id,cve_id,service_id,status,ml_reasons")
                    .eq("asset_id", asset_id).execute().data)
        except Exception:
            return {}
    return {(finding_id(r), r.get("service_id")): r for r in rows}


def _newly_watched(v: dict, was: dict | None) -> bool:
    """Alert for a watchlisted CVE once: when the finding is new, came back, or
    was already there but the CVE has only now been put on the watchlist."""
    if not v.get("on_watchlist"):
        return False
    if was is None or was.get("status") != "open":
        return True
    return WATCHLIST_REASON not in (was.get("ml_reasons") or [])


def _insert_vuln(client, asset_id: str, service_id, v: dict, existing: dict | None) -> None:
    """Update the stored finding, or insert it when it is new.
    (Looked up by hand rather than by the unique index: Postgres never treats
    two NULL service ids as a conflict, which would duplicate such rows.)"""
    reasons = list(v.get("ml_reasons") or [])
    if v.get("on_watchlist") and WATCHLIST_REASON not in reasons:
        reasons.insert(0, WATCHLIST_REASON)   # the stored row remembers it was alerted
    row = {
        "asset_id": asset_id, "service_id": service_id,
        "cve_id": v.get("cve_id"), "cvss_score": v.get("cvss_score"),
        "cvss_vector": v.get("cvss_vector"), "severity": v.get("severity"),
        "epss_score": v.get("epss_score"),
        "epss_percentile": v.get("epss_percentile"),
        "in_kev": v.get("in_kev", False), "kev_due_date": v.get("kev_due_date"),
        "ml_risk_score": v.get("ml_risk_score"),
        "ml_reasons": reasons,
        "confidence": v.get("confidence", "version-confirmed"),
        "description": (v.get("description") or "")[:2000],
        # one finding format (migration 006): CVE matches, Nuclei, NetExec
        "source": v.get("source") or "cve", "finding_key": finding_id(v),
        "title": v.get("title") or v.get("cve_id"),
        "evidence": (v.get("evidence") or "")[:1000] or None,
        # status is left alone on re-scan so analyst decisions
        # (accepted / false_positive) survive; new rows default to 'open'
    }

    def write(payload: dict) -> None:
        if existing:
            client.table("vulnerabilities").update(payload).eq("id", existing["id"]).execute()
        else:
            client.table("vulnerabilities").insert(payload).execute()

    try:
        write(row)
    except Exception:
        # database before migration 006 (no source / finding_key / title / evidence)
        # or before v2 (no confidence): only CVE findings can be stored there
        for k in ("source", "finding_key", "title", "evidence", "confidence"):
            row.pop(k, None)
        if not row.get("cve_id"):
            return
        try:
            write(row)
        except Exception:
            pass  # a transient error should not abort the whole scan


def _resolve_missing_vulns(client, existing: dict, seen: set) -> None:
    """An open vuln that no longer shows up has been fixed -> mark remediated."""
    try:
        for key, r in existing.items():
            if r.get("status") == "open" and key not in seen:
                client.table("vulnerabilities").update(
                    {"status": "remediated"}).eq("id", r["id"]).execute()
            elif r.get("status") == "remediated" and key in seen:
                # it came back (fix rolled back / regression) -> reopen
                client.table("vulnerabilities").update(
                    {"status": "open"}).eq("id", r["id"]).execute()
    except Exception:
        pass


# -------------------------------------------------------------------------- TLS
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


# ------------------------------------------------------------------- risk trend
def _grade(score: float) -> str:
    try:
        from ml.risk_score import grade_from_score
        return grade_from_score(score)
    except Exception:
        return "F" if score >= 80 else "D" if score >= 60 else "C" if score >= 40 \
            else "B" if score >= 20 else "A"


def _record_risk(client, scan_id, asset_id, score, grade, open_vulns=0, kev_count=0) -> None:
    """One point of the risk trend (migration 004). asset_id None = whole network."""
    try:
        client.table("risk_history").insert({
            "scan_id": scan_id, "asset_id": asset_id,
            "risk_score": score, "risk_grade": grade,
            "open_vulns": open_vulns, "kev_count": kev_count,
        }).execute()
    except Exception:
        pass


def _record_network_risk(client, scan_id: str) -> None:
    """Network posture after this scan = average risk of every known asset."""
    try:
        from common.db import fetch_all
        assets = fetch_all(client, "assets", columns="id,risk_score")
        vulns = fetch_all(client, "vulnerabilities", columns="id,in_kev,status",
                          eq={"status": "open"})
    except Exception:
        return
    if not assets:
        return
    avg = round(sum(float(a.get("risk_score") or 0) for a in assets) / len(assets), 1)
    _record_risk(client, scan_id, None, avg, _grade(avg), open_vulns=len(vulns),
                 kev_count=sum(1 for v in vulns if v.get("in_kev")))
